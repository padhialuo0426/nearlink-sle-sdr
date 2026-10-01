/* Offline waveform, UI and main-cleanup checks. Hardware-facing calls in
 * the included application are redirected to test stubs. Keep function/data
 * sections and --gc-sections to discard unused hardware implementations. */
#define sle_rt_radio_setup test_radio_setup
#define sle_rt_radio_start test_radio_start
#define sle_rt_radio_stop test_radio_stop
#define sle_rt_radio_restore test_radio_restore
#define sle_rt_radio_submit test_radio_submit
#define sle_rt_radio_retune test_radio_retune
#define sle_rt_hwstat_open test_hwstat_open
#define main sle_t_main_under_test
#include "sle_tnode.c"
#undef main
#undef sle_rt_radio_setup
#undef sle_rt_radio_start
#undef sle_rt_radio_stop
#undef sle_rt_radio_restore
#undef sle_rt_radio_submit
#undef sle_rt_radio_retune
#undef sle_rt_hwstat_open
#include <assert.h>
/* Include the real, key-free SSAP/CMTC codecs in the existing offline
 * target; the Makefile deliberately does not link the pairing runtime. */
#include "sle_ssap_server.c"
#include "sle_cmtc.c"
static int64_t test_now_ns=123456789;
int64_t sle_iio_now_ns(void) { return test_now_ns; }
/* Authentication is a boundary stub: on_sdu receives already authenticated
 * SDUs in production. These tests exercise UI/SSAP, not pairing or CCM. */
static int stub_encrypted=1;
static int main_test_active;
static char main_lifecycle[16];
static size_t main_lifecycle_len;
static sle_rt_radio *main_radio;
static sle_t_runtime *main_runtime;
static void main_step(char step)
{
    assert(main_test_active && main_lifecycle_len+1<sizeof main_lifecycle);
    main_lifecycle[main_lifecycle_len++]=step;
    main_lifecycle[main_lifecycle_len]=0;
}
int sle_t_runtime_encrypted(const sle_t_runtime *r) { (void)r; return stub_encrypted; }
int sle_t_runtime_poll(sle_t_runtime *r,uint64_t now)
{
    (void)now;
    assert(main_test_active && r==main_runtime && r->initialized);
    return 0; /* Startup only: no pairing worker or keys. */
}
/* Main lifecycle seam: init/setup/start succeed, the first calibration
 * command raises SIGINT, and the actual main must stop/destroy/restore.
 * Unexpected protocol or hardware work fails rather than touching devices. */
int sle_iio_realtime(int cpu,int prio)
{
    assert(main_test_active && cpu==0 && prio==60); return 0;
}
int sle_t_runtime_init_variant(sle_t_runtime *r,const uint8_t t[6],int cpu,unsigned variant)
{
    (void)t;
    assert(!main_runtime && cpu==0 && variant==SLE_PAIR_V_COUNT_PLAIN);
    main_runtime=r; r->initialized=1; r->rng_fd=-1; r->pair.state=SLE_T_PAIR_READY;
    main_step('I'); return 0;
}
int test_radio_setup(double tx_gain,double rx_gain)
{
    (void)tx_gain; (void)rx_gain;
    assert(main_runtime && main_runtime->initialized);
    main_step('P'); return 0;
}
int test_radio_start(sle_rt_radio *r,int cpu,int prio)
{
    assert(!main_radio && cpu==1 && prio==80);
    main_radio=r; r->started=1; atomic_store(&r->depth,SLE_RT_CAL_DEPTH);
    main_step('B'); return 0;
}
int test_radio_submit(sle_rt_radio *r,const sle_rt_command *c)
{
    assert(r==main_radio && r->started && c->seq==1 && c->wave.n>0);
    assert(!strcmp(main_lifecycle,"IPB"));
    struct sigaction sa;
    assert(!sigaction(SIGINT,NULL,&sa) && sa.sa_handler==stop_signal);
    main_step('S');
    assert(!raise(SIGINT) && interrupted==SIGINT);
    return 0;
}
int test_radio_stop(sle_rt_radio *r)
{
    assert(r==main_radio && r->started && interrupted==SIGINT);
    assert(main_runtime->initialized && !strcmp(main_lifecycle,"IPBS"));
    r->started=0; main_step('T'); return 0;
}
int sle_t_runtime_destroy(sle_t_runtime *r)
{
    assert(r==main_runtime && r->initialized && main_radio && !main_radio->started);
    assert(!strcmp(main_lifecycle,"IPBST"));
    r->initialized=0; main_step('D'); return 0;
}
int test_radio_restore(void)
{
    assert(main_radio && !main_radio->started && !main_runtime->initialized);
    assert(!strcmp(main_lifecycle,"IPBSTD"));
    main_step('R'); return 0;
}
int test_radio_retune(int tx,int mhz)
{
    (void)tx; (void)mhz; assert(!"unexpected retune in startup SIGINT test"); return -1;
}
int test_hwstat_open(sle_rt_hwstat *h)
{
    (void)h; assert(!"offline tests must not open hardware status"); return -1;
}
int sle_t_runtime_bind(sle_t_runtime *r,const uint8_t g[6],uint32_t sync)
{
    (void)r; (void)g; (void)sync; assert(!"unexpected pairing bind"); return -1;
}
int sle_t_runtime_queue(sle_t_runtime *r,sle_rt_tx_store *s,sle_link_t *l)
{
    (void)r; (void)s; (void)l; assert(!"unexpected pairing queue"); return -1;
}
int sle_t_runtime_tx(sle_t_runtime *r,sle_link_tx_t *tx)
{
    (void)r; (void)tx; assert(!"unexpected protected TX"); return -1;
}
int sle_t_runtime_submitted(sle_t_runtime *r,const sle_link_tx_t *tx)
{
    (void)r; (void)tx; assert(!"unexpected protected submission"); return -1;
}
int sle_t_runtime_rx(sle_t_runtime *r,sle_link_t *l,const sle_link_rx_t *wire,
                     sle_link_rx_out_t *out,sle_rt_rx *scratch,uint64_t now)
{
    (void)r; (void)l; (void)wire; (void)out; (void)scratch; (void)now;
    assert(!"unexpected protected RX"); return -1;
}
/* This invokes production main with its real signal installation and cleanup,
 * not merely stop_signal/alive. It reaches radio_started, then interrupts the
 * first calibration submission; it does not emulate a connected ready session. */
static void interactive_main_sigint(void)
{
    __typeof__(opt) saved_opt=opt;
    const int signals[]={SIGINT,SIGTERM,SIGHUP,SIGPIPE};
    struct sigaction saved_actions[4]; sigset_t saved_mask,one;
    assert(!hw && !interrupted);
    for(size_t i=0;i<4;i++) assert(!sigaction(signals[i],NULL,&saved_actions[i]));
    assert(!sigemptyset(&one) && !sigaddset(&one,SIGINT));
    assert(!sigprocmask(SIG_UNBLOCK,&one,&saved_mask));
    char path[]="/tmp/sle-t-main-sigint-XXXXXX";
    int fd=mkstemp(path); assert(fd>=0 && !close(fd));
    main_lifecycle_len=0; main_lifecycle[0]=0;
    main_radio=NULL; main_runtime=NULL; main_test_active=1; stub_encrypted=0;
    char *args[]={"sle_tnode","--interactive","1","--hw-status","0",
        "--attempts","2","--resource-layout","standard","--pair-variant","0x200",
        "--log",path,NULL};
    int rc=sle_t_main_under_test((int)(sizeof args/sizeof args[0])-1,args);
    assert(rc==1 && interrupted==SIGINT && !strcmp(main_lifecycle,"IPBSTDR"));
    /* main has freed its state; retain only the lifecycle record from now on. */
    main_radio=NULL; main_runtime=NULL; main_test_active=0;
    FILE *log=fopen(path,"r"); assert(log);
    char text[16384]; size_t n=fread(text,1,sizeof text-1,log);
    assert(!ferror(log) && feof(log)); text[n]=0;
    assert(!fclose(log) && !unlink(path));
    const char *started=strstr(text,"\"kind\":\"radio_started\"");
    const char *ended=strstr(text,"\"kind\":\"attempt_end\"");
    const char *cleanup=strstr(text,"{\"kind\":\"cleanup\",\"restore_result\":0}");
    assert(started && ended && cleanup && started<ended && ended<cleanup);
    assert(strstr(ended,"\"reason\":\"signal\"") && strstr(ended,"\"stage_achieved\":false"));
    assert(!strstr(text,"\"stage_achieved\":true") && !strstr(text,"protected_server_business"));
    assert(!strstr(text,"\"attempt\":2") && !strstr(text,"\"kind\":\"readvertise\""));
    assert(!strstr(text,"\"kind\":\"ssap_ready\"")); /* startup coverage boundary */
    for(size_t i=0;i<4;i++) assert(!sigaction(signals[i],&saved_actions[i],NULL));
    assert(!sigprocmask(SIG_SETMASK,&saved_mask,NULL));
    opt=saved_opt; interrupted=0; stub_encrypted=1;
}

/* TX store stubs for the SDU pump test: records land in a flat log;
 * stub_free is the number of free slots reported, stub_full makes the next
 * sle_rt_queue report "all slots referenced". */
static uint8_t stub_rec[64][SLE_RT_TX_MAX]; static size_t stub_len[64]; static unsigned stub_n, stub_free=8, stub_full;
int sle_rt_queue(sle_rt_tx_store *s, sle_link_t *l, uint8_t type, const uint8_t *p, size_t n)
{
    (void)s; (void)l; assert(type==SLE_PTYPE_DATA && n<=SLE_RT_TX_MAX-4);
    if (stub_full) { stub_full=0; return -2; }
    assert(stub_n<64); memcpy(stub_rec[stub_n],p,n); stub_len[stub_n++]=n; return 0;
}
unsigned sle_rt_free_slots(const sle_rt_tx_store *s, const sle_link_t *l) { (void)s; (void)l; return stub_free; }
void sle_rt_wipe(void *p, size_t n) { memset(p,0,n); }
static void calibration_diagnostic(t_app *a)
{
    a->journal=calloc(1,JOURNAL); assert(a->journal);
    assert(observe_cal(a,1000,1100)==SLE_RT_OK);
    assert(observe_cal(a,2000,2100)==SLE_RT_OK);
    assert(!a->used); /* successful witness updates add no diagnostic rows */
    assert(observe_cal(a,3000,3109)==SLE_RT_OFFSET_JUMP);
    assert(!a->cal.count && !a->cal.valid && !a->cal.offset);
    assert(strstr(a->journal,"\"kind\":\"calibration_failure\"")!=NULL);
    assert(strstr(a->journal,"\"candidate_offset\":109,\"offset_before\":100,\"count_before\":2")!=NULL);
    assert(strstr(a->journal,"\"offset\":0,\"count\":0,\"valid_after\":false,\"cleared\":true")!=NULL);
    assert(strstr(a->journal,"\"mono_ns\":123456789")!=NULL);
    free(a->journal); a->journal=NULL; a->used=0;
}
/* Restart policy: a jump before the mapping is valid restarts collection;
 * three fresh stable markers then validate; a range error fails closed. */
static void calibration_restart(t_app *a)
{
    a->journal=calloc(1,JOURNAL); assert(a->journal);
    sle_rt_cal_clear(&a->cal); a->cal_restarts=0; a->reason=NULL;
    assert(!cal_decide(a,0,1000,1100) && a->cal.count==1);
    assert(!cal_decide(a,1,2000,2100) && a->cal.count==2);
    assert(!cal_decide(a,2,3000,3620) && !a->cal.count && !a->cal.valid);  /* +520 jump */
    assert(a->cal_restarts==1 && a->reason==NULL);
    assert(strstr(a->journal,"\"kind\":\"calibration_restart\"")!=NULL);
    assert(strstr(a->journal,"\"trial\":2,\"remaining_trials\":9,\"reason\":\"initial_offset_jump\",\"restarts\":1")!=NULL);
    assert(!cal_decide(a,3,4000,4620) && a->cal.count==1 && a->cal.offset==620);
    assert(!cal_decide(a,4,5000,5621) && !cal_decide(a,5,6000,6619));
    assert(a->cal.valid && a->cal.count==3 && a->cal.offset==620);
    sle_rt_cal_clear(&a->cal);
    assert(cal_decide(a,6,1000,1000+SLE_RT_FS) == -1);                       /* out of range */
    assert(a->reason && !strcmp(a->reason,"calibration_invalid"));
    free(a->journal); a->journal=NULL; a->used=0; a->reason=NULL;
}
/* Advertisement witness: two consecutive misses skip their request windows,
 * a witness resets the run, the third consecutive miss aborts. */
static void advertisement_witness(t_app *a)
{
    a->journal=calloc(1,JOURNAL); assert(a->journal);
    a->adv_miss_run=a->adv_misses=0; a->reason=NULL;
    assert(adv_witness_decide(a,100,1,1,0)==1);
    assert(adv_witness_decide(a,200,0,1,1)==0 && a->adv_miss_run==1 && !a->reason);
    assert(strstr(a->journal,"\"sync\":200,\"run\":1,\"limit\":3,\"total\":1,\"near_frames\":1,\"near_rejected\":1,\"action\":\"skip_request_window\"")!=NULL);
    assert(adv_witness_decide(a,300,0,0,0)==0 && a->adv_miss_run==2);
    assert(adv_witness_decide(a,400,1,1,0)==1 && a->adv_miss_run==0 && a->adv_misses==2);
    assert(adv_witness_decide(a,500,0,0,0)==0 && adv_witness_decide(a,600,0,0,0)==0);
    assert(adv_witness_decide(a,700,0,2,2)==-1 && a->adv_miss_run==3 && a->adv_misses==5);
    assert(a->reason && !strcmp(a->reason,"advertisement_witness_missing"));
    assert(strstr(a->journal,"\"sync\":700,\"run\":3,\"limit\":3,\"total\":5,\"near_frames\":2,\"near_rejected\":2,\"action\":\"abort\"")!=NULL);
    free(a->journal); a->journal=NULL; a->used=0; a->reason=NULL; a->adv_miss_run=a->adv_misses=0;
}
/* Establishment: six events without a peer frame end the attempt; any
 * peer frame, or fewer events, keeps the connection. */
static void connection_establish(t_app *a)
{
    a->journal=calloc(1,JOURNAL); assert(a->journal);
    a->reason=NULL; a->peer_frames=0; a->request_sample=4242;
    for(a->events=1;a->events<SLE_T_CONN_ESTABLISH_EVENTS;a->events++) assert(!establish_failed(a) && !a->reason);
    assert(establish_failed(a) && !strcmp(a->reason,"connection_establish_failed"));
    assert(strstr(a->journal,"\"kind\":\"connection_establish_failed\"")!=NULL);
    assert(strstr(a->journal,"\"events\":6,\"limit\":6,\"request_sample\":4242")!=NULL);
    a->reason=NULL; a->peer_frames=1; a->events=400;
    assert(!establish_failed(a) && !a->reason);
    free(a->journal); a->journal=NULL; a->used=0; a->peer_frames=a->events=0;
}
/* Schedule log: every input plus events 0..7 exactly as sle_conn_event()
 * computes them, and only the first eight listened events are logged. */
static void schedule_log(t_app *a)
{
    a->journal=calloc(1,JOURNAL); assert(a->journal);
    memset(&a->txi,0,sizeof a->txi);
    a->txi.start_offset_us=10850; a->txi.base_slot=108000; a->txi.group_period_slots=100; a->txi.sched_slot=4;
    a->txi.first_lid=2182256; a->txi.first_crc_init=3137378289u; a->txi.intra_event_gap_us=125;
    a->txi.timeout_10ms=500; a->txi.hop_map_len=10; memset(a->txi.hop_map,0xff,10); a->txi.hop_map[9]=0x1f;
    a->request_sample=62731939;
    sle_conn_sched_t s; assert(!sle_conn_sched_init(&s,sle_samples_to_ns(a->request_sample,SLE_RT_FS),&a->txi));
    log_schedule(a,&s);
    char want[256]; sle_conn_event_t e;
    for(uint32_t k=0;k<SLE_T_SCHED_LOG_EVENTS;k++){
        sle_conn_event(&s,k,&e);
        snprintf(want,sizeof want,"{\"k\":%u,\"sync\":%" PRId64 ",\"slot\":%u,\"phys\":%u,\"mhz\":%d,\"seed\":%u}",
            k,sle_ns_to_samples(e.t_ns,SLE_RT_FS),e.slot,e.phys,e.mhz,e.white_seed);
        assert(strstr(a->journal,want)!=NULL);
    }
    assert(strstr(a->journal,"\"anchor_sample\":62731939,\"start_offset_us\":10850,\"t0_sample\":62775339,\"base_slot_raw\":108000,\"base_slot\":108000,\"period_slots\":100")!=NULL);
    assert(strstr(a->journal,"\"hop_map\":\"ffffffffffffffffff1f\"")!=NULL);
    size_t used=a->used;
    sle_link_tx_t plan={.k=3}; sle_conn_event(&s,3,&plan.ev);
    a->events=7; log_event_plan(a,&plan); assert(a->used>used && strstr(a->journal,"\"kind\":\"conn_event_plan\",")!=NULL);
    used=a->used; a->events=8; log_event_plan(a,&plan); assert(a->used==used);
    free(a->journal); a->journal=NULL; a->used=0; a->events=0; a->request_sample=0;
}


/* Re-advertising: only after an establishment failure, at most
 * SLE_T_READVERTISE_LIMIT times per attempt, never after a signal. */
static void readvertise_policy(t_app *a)
{
    a->readvertises=0; a->reason="connection_establish_failed";
    assert(readvertise_allowed(a));
    a->readvertises=SLE_T_READVERTISE_LIMIT-1; assert(readvertise_allowed(a));
    a->readvertises=SLE_T_READVERTISE_LIMIT; assert(!readvertise_allowed(a));
    a->readvertises=0;
    a->reason="link_down"; assert(!readvertise_allowed(a));
    a->reason="budget_exhausted"; assert(!readvertise_allowed(a));
    a->reason=NULL; assert(!readvertise_allowed(a));
    a->reason="connection_establish_failed"; interrupted=SIGTERM; assert(!readvertise_allowed(a));
    interrupted=0; a->reason=NULL;
}
/* Connection witness: 3 misses abort when any of them lacked the peer
 * frame; with the peer seen in every event the run may reach 8; a witness
 * resets the run. */
static void conn_witness_policy(t_app *a)
{
    a->journal=calloc(1,JOURNAL); assert(a->journal);
    a->reason=NULL; a->conn_miss_run=0; a->conn_miss_peer=1;
    assert(!conn_witness_decide(a,0,0,1) && !conn_witness_decide(a,1,0,1));
    assert(!conn_witness_decide(a,2,1,1) && !a->conn_miss_run);  /* witness resets */
    assert(!conn_witness_decide(a,4,0,1) && !conn_witness_decide(a,5,0,0) && !a->reason);
    assert(conn_witness_decide(a,6,0,1)==-1 && !strcmp(a->reason,"predict_witness_missing")); /* run 3, one peer miss */
    assert(strstr(a->journal,"\"k\":6,\"run\":3,\"peer_seen_all\":0,\"limit\":3,\"action\":\"abort\"")!=NULL);
    a->reason=NULL; a->conn_miss_run=0; a->conn_miss_peer=1;
    for(int i=0;i<SLE_T_CONN_WITNESS_MISS_LIMIT_PEER-1;i++) assert(!conn_witness_decide(a,10+i,0,1) && !a->reason);
    assert(conn_witness_decide(a,20,0,1)==-1 && !strcmp(a->reason,"predict_witness_missing"));
    assert(strstr(a->journal,"\"k\":20,\"run\":8,\"peer_seen_all\":1,\"limit\":8,\"action\":\"abort\"")!=NULL);
    free(a->journal); a->journal=NULL; a->used=0; a->reason=NULL; a->conn_miss_run=0;
}
static unsigned got_sdus; static size_t got_len; static uint8_t got[SLE_SDU_MAX]; static unsigned got_frags;
static void got_sdu(void *ctx,const uint8_t *p,size_t n,unsigned f) { (void)ctx; memcpy(got,p,n); got_len=n; got_frags=f; got_sdus++; }
/* SDU pump: 24-byte records reassemble to the queued SDU; it pauses while
 * only the reserve is free or the store is full, and resumes later. Also
 * the deterministic long notification value. */
static void sdu_pump(t_app *a)
{
    a->journal=calloc(1,JOURNAL); assert(a->journal);
    sle_link_t *l=calloc(1,sizeof *l); assert(l); a->link=l; a->reason=NULL; txq_clear(a);
    opt.tx_frag=24; stub_n=0; stub_free=8;
    uint8_t sdu[200]; for(int i=0;i<200;i++) sdu[i]=(uint8_t)(i*3+1);
    stub_free=SLE_T_TX_RESERVE; assert(!queue_sdu(a,sdu,200) && stub_n==0 && a->txq_len==1); /* waits */
    stub_free=8; stub_full=1; assert(!tx_pump(a) && stub_n==0);                          /* store full */
    assert(!tx_pump(a) && !a->txq_len && stub_n==9);                                        /* 8x24 + 8 */
    sle_sdu_rx r; sle_sdu_rx_init(&r,SLE_SDU_MAX); got_sdus=0;
    for(unsigned i=0;i<stub_n;i++){ assert(stub_len[i]<=26); assert(!sle_sdu_rx_feed(&r,stub_rec[i],stub_len[i],got_sdu,NULL)); }
    assert(got_sdus==1 && got_len==200 && got_frags==9 && !memcmp(got,sdu,200));
    assert(strstr(a->journal,"\"kind\":\"sdu_tx\",")!=NULL && strstr(a->journal,"\"len\":200,\"fragments\":9,\"tx_frag\":24")!=NULL);
    stub_n=0; assert(!queue_sdu(a,sdu,20) && stub_n==1 && (stub_rec[0][0]>>1&3)==0);         /* short: complete */
    for(int i=0;i<SLE_T_TX_SDUS;i++){ stub_free=0; assert(!queue_sdu(a,sdu,30)); }
    assert(queue_sdu(a,sdu,30)==-1); stub_free=8; txq_clear(a);                               /* FIFO bound */
    char v[SLE_SSAP_SERVER_VALUE_MAX+1];
    opt.notify_len=0; a->attempt=1; a->notified=2; assert(notify_value(a,v,sizeof v)==(int)strlen("SLE-SERVER-1-02\r\n") && !strcmp(v,"SLE-SERVER-1-02\r\n"));
    opt.notify_len=40; assert(notify_value(a,v,sizeof v)==40 && !strcmp(v,"SLE-SERVER-1-02-0123456789ABCDEFGHIJKL\r\n"));
    opt.notify_len=512; assert(notify_value(a,v,sizeof v)==512 && v[510]=='\r' && v[511]=='\n' && v[16]=='0' && v[16+36]=='0');
    opt.notify_len=0; a->notified=0; a->attempt=0;
    free(l); a->link=NULL; free(a->journal); a->journal=NULL; a->used=0;
}
/* Interactive line splitting: CRLF/LF lines, long input pieces, partial
 * lines wait for more input. */
static void chat_lines(void)
{
    char b[64],v[64]; size_t n;
    strcpy(b,"hi\r\nsecond\npart"); size_t len=strlen(b);
    assert(chat_next(b,&len,32,v)==4 && !memcmp(v,"hi\r\n",4));
    assert(chat_next(b,&len,32,v)==8 && !memcmp(v,"second\r\n",8));
    assert(chat_next(b,&len,32,v)==0 && len==4 && !memcmp(b,"part",4));
    memcpy(b,"ABCDEFGHIJ",10); len=10;                     /* maxv 6: 4-byte pieces */
    assert((n=chat_next(b,&len,6,v))==6 && !memcmp(v,"ABCD\r\n",6) && len==6);
    assert(chat_next(b,&len,6,v)==6 && !memcmp(v,"EFGH\r\n",6) && len==2);
    assert(chat_next(b,&len,6,v)==0);
    memcpy(b,"\n",1); len=1; assert(chat_next(b,&len,32,v)==2 && !memcmp(v,"\r\n",2) && !len); /* empty line */
    memcpy(b,"toolongline\n",12); len=12;                  /* line longer than a piece */
    assert(chat_next(b,&len,6,v)==6 && !memcmp(v,"tool\r\n",6) && len==8);
}
/* Pipe-backed stdin and captured stdout exercise the real chat pump, SSAP
 * encoder/decoder and application delivery path. The radio TX store and
 * authentication boundary are stubbed; no hardware or key material is used. */
typedef struct {
    t_app *a;
    int saved_in, saved_out, input;
    FILE *console;
} chat_fixture;
static chat_fixture chat_open(uint16_t mtu)
{
    chat_fixture f={0}; int input[2];
    assert(!fflush(stdout));
    f.saved_in=dup(STDIN_FILENO); f.saved_out=dup(STDOUT_FILENO);
    assert(f.saved_in>=0 && f.saved_out>=0 && !pipe(input));
    f.console=tmpfile(); assert(f.console);
    assert(dup2(input[0],STDIN_FILENO)==STDIN_FILENO);
    assert(dup2(fileno(f.console),STDOUT_FILENO)==STDOUT_FILENO);
    assert(!close(input[0])); f.input=input[1];
    f.a=calloc(1,sizeof *f.a); assert(f.a);
    f.a->journal=calloc(1,JOURNAL); assert(f.a->journal);
    f.a->output=tmpfile(); assert(f.a->output);
    f.a->link=calloc(1,sizeof *f.a->link); assert(f.a->link);
    assert(!sle_ssap_server_init(&f.a->ssap,mtu));
    /* Inject a discovered session; pairing/MTU negotiation has separate tests. */
    f.a->ssap.mtu=mtu; f.a->ssap.negotiated=f.a->ssap.discovered=1;
    f.a->deadline=INT64_MAX;
    opt.interactive=1; interrupted=0; stub_encrypted=1;
    stub_n=stub_full=0; stub_free=SLE_T_TX_RESERVE;
    return f;
}
static void chat_input(chat_fixture *f,const char *p,size_t n)
{
    /* Each test writes less than PIPE_BUF, so no background writer is needed. */
    assert(write(f->input,p,n)==(ssize_t)n);
}
static size_t chat_output(chat_fixture *f,char *p,size_t cap)
{
    assert(!fflush(stdout));
    off_t n=lseek(fileno(f->console),0,SEEK_END);
    assert(n>=0 && (size_t)n<cap);
    assert(pread(fileno(f->console),p,(size_t)n,0)==n);
    p[n]=0; return (size_t)n;
}
static void chat_close(chat_fixture *f)
{
    assert(!fflush(stdout));
    assert(dup2(f->saved_in,STDIN_FILENO)==STDIN_FILENO);
    assert(dup2(f->saved_out,STDOUT_FILENO)==STDOUT_FILENO);
    assert(!close(f->saved_in) && !close(f->saved_out));
    if(f->input>=0) assert(!close(f->input));
    assert(!fclose(f->console) && !fclose(f->a->output));
    free(f->a->link); free(f->a->journal); free(f->a);
    opt.interactive=0; interrupted=0; stub_encrypted=1;
    stub_n=stub_full=0; stub_free=8; test_now_ns=123456789;
}
static void chat_queued(t_app *a,unsigned i,const void *value,size_t n)
{
    assert(i<a->txq_len && n<=SLE_SSAP_SERVER_VALUE_MAX && n+6<=a->ssap.mtu);
    unsigned slot=(a->txq_head+i)%SLE_T_TX_SDUS;
    const uint8_t *p=a->txq[slot].data;
    assert(a->txq[slot].len==n+10 && !a->txq[slot].off);
    const uint8_t head[]={10,0,(uint8_t)(n+6),(uint8_t)((n+6)>>8),
                          15,3,2,0,(uint8_t)n,(uint8_t)(n>>8)};
    assert(!memcmp(p,head,sizeof head) && !memcmp(p+10,value,n));
}
static void interactive_input(void)
{
    chat_fixture f=chat_open(520); t_app *a=f.a;
    const char input[]="alpha\r\n\nbeta\npart";
    chat_input(&f,input,sizeof input-1);
    assert(!business(a) && !a->chat_len && !a->ssap.notifications);
    a->discovered_ms=100; test_now_ns=1101000000;
    assert(!business(a) && a->ready_emitted && a->ssap.notifications==3);
    chat_queued(a,0,"alpha\r\n",7); chat_queued(a,1,"\r\n",2);
    chat_queued(a,2,"beta\r\n",6);
    assert(a->chat_len==4 && !memcmp(a->chat,"part",4));
    char text[2048]; chat_output(&f,text,sizeof text);
    assert(strstr(text,"MTU 520") && strstr(text,"Ctrl+C"));
    assert(strstr(text,"通知已排队 7 B") && !strstr(text,"通知已发出"));
    assert(strstr(a->journal,"\"interactive\":true"));
    assert(strstr(a->journal,"\"value_hex\":\"616c7068610d0a\",\"len\":7"));
    /* A temporarily empty pipe leaves the partial line untouched. */
    assert(!business(a) && !a->chat_eof && a->chat_len==4);
    chat_input(&f,"ial\n",4);
    assert(!business(a) && a->ssap.notifications==4 && !a->chat_len);
    chat_queued(a,3,"partial\r\n",9);
    /* EOF stops input polling, not the session. No automatic notifications. */
    assert(!close(f.input)); f.input=-1;
    assert(!business(a) && a->chat_eof && !a->reason);
    test_now_ns=20000000000;
    assert(!business(a) && !a->notified && a->ssap.notifications==4 && alive(a));
    chat_close(&f);
}
static void interactive_backpressure(void)
{
    chat_fixture f=chat_open(520); t_app *a=f.a; a->ready_emitted=1;
    chat_input(&f,"0\n1\n2\n3\n4\n5\n",12);
    assert(!business(a) && a->txq_len==SLE_T_TX_SDUS && a->chat_len==4);
    assert(!memcmp(a->chat,"4\n5\n",4) && !stub_n);
    assert(!business(a) && a->chat_len==4 && a->ssap.notifications==4);
    for(unsigned i=0;i<4;i++){
        char value[]={(char)('0'+i),'\r','\n'}; chat_queued(a,i,value,sizeof value);
    }
    stub_free=8; assert(!tx_pump(a) && !a->txq_len && stub_n==4);
    stub_free=SLE_T_TX_RESERVE;
    assert(!business(a) && !a->chat_len && a->ssap.notifications==6);
    chat_queued(a,0,"4\r\n",3); chat_queued(a,1,"5\r\n",3);
    chat_close(&f);
}
static void interactive_mtu(void)
{
    const uint16_t mtus[]={23,520,1024};
    for(size_t i=0;i<sizeof mtus/sizeof mtus[0];i++){
        chat_fixture f=chat_open(mtus[i]); t_app *a=f.a; a->ready_emitted=1;
        size_t maxv=mtus[i]-6;
        if(maxv>SLE_SSAP_SERVER_VALUE_MAX) maxv=SLE_SSAP_SERVER_VALUE_MAX;
        char input[SLE_SSAP_SERVER_VALUE_MAX+1],value[SLE_SSAP_SERVER_VALUE_MAX];
        memset(input,'x',maxv-1); input[maxv-1]='\n';
        chat_input(&f,input,maxv);
        assert(!business(a) && a->ssap.notifications==2 && !a->chat_len);
        memset(value,'x',maxv-2); value[maxv-2]='\r'; value[maxv-1]='\n';
        chat_queued(a,0,value,maxv); chat_queued(a,1,"x\r\n",3);
        /* Exercise the existing link fragmentation/reassembly after the UI. */
        stub_free=8; assert(!tx_pump(a) && !a->txq_len);
        sle_sdu_rx r; sle_sdu_rx_init(&r,SLE_SDU_MAX); got_sdus=0;
        for(unsigned j=0;j<stub_n;j++){
            unsigned before=got_sdus;
            assert(!sle_sdu_rx_feed(&r,stub_rec[j],stub_len[j],got_sdu,NULL));
            if(got_sdus>before){
                if(got_sdus==1) assert(got_len==maxv+10 && !memcmp(got+10,value,maxv));
                else assert(got_sdus==2 && got_len==13 && !memcmp(got+10,"x\r\n",3));
            }
        }
        assert(got_sdus==2);
        chat_close(&f);
    }
}
static void interactive_eof_and_signals(void)
{
    chat_fixture f=chat_open(23); t_app *a=f.a; a->ready_emitted=1;
    chat_input(&f,"123456789012345tail",19);
    assert(!close(f.input)); f.input=-1;
    assert(!business(a) && a->ssap.notifications==1);
    chat_queued(a,0,"123456789012345\r\n",17);
    assert(!business(a) && a->chat_eof && a->chat_len==4);
    /* Existing T semantics: short unterminated tail stays buffered at EOF. */
    assert(!memcmp(a->chat,"tail",4) && !business(a) && a->chat_len==4 && alive(a));
    const int signals[]={SIGINT,SIGTERM,SIGHUP,SIGPIPE};
    for(size_t i=0;i<sizeof signals/sizeof signals[0];i++){
        interrupted=0; a->reason=NULL;
        stop_signal(signals[i]);
        assert(interrupted==signals[i] && !alive(a) && !strcmp(a->reason,"signal"));
        a->reason="connection_establish_failed";
        assert(!readvertise_allowed(a));
    }
    chat_close(&f);
}
static void interactive_received_write(void)
{
    chat_fixture f=chat_open(520); t_app *a=f.a; a->ready_emitted=1;
    /* Binary output must keep NUL and CR/LF; no newline or prefix is added. */
    const uint8_t value[]={'W',0,'S','\r','\n'};
    sle_ssap_write_t w={.fragment=SLE_SSAP_FRAG_NONE,.oper=SLE_SSAP_WRITE_INSTANT,
        .item={.handle=2,.value=value,.value_len=sizeof value}};
    uint8_t msg[64],sdu[68]; char text[128];
    size_t n=sle_ssap_write_build(SLE_SSAP_WRITE_REQ,&w,msg,sizeof msg); assert(n);
    sdu[0]=10; sdu[1]=0; sdu[2]=(uint8_t)n; sdu[3]=(uint8_t)(n>>8); memcpy(sdu+4,msg,n);
    on_sdu(a,sdu,n+4,1);
    assert(!a->reason && a->ssap.writes==1 && a->txq_len==1);
    assert(chat_output(&f,text,sizeof text)==sizeof value && !memcmp(text,value,sizeof value));
    assert(strstr(a->journal,"\"kind\":\"ssap_write\"") && strstr(a->journal,"\"value_hex\":\"5700530d0a\""));
    assert(a->txq[0].len==sizeof value+9 && a->txq[0].data[4]==SLE_SSAP_WRITE_RSP);
    assert(!memcmp(a->txq[0].data+9,value,sizeof value));
    /* WRITE_CMD displays the bytes too, but produces no response. */
    txq_clear(a); sdu[4]=SLE_SSAP_WRITE_CMD;
    on_sdu(a,sdu,n+4,1);
    assert(!a->reason && a->ssap.writes==2 && !a->txq_len);
    assert(chat_output(&f,text,sizeof text)==2*sizeof value);
    assert(!memcmp(text+sizeof value,value,sizeof value));
    opt.interactive=0; on_sdu(a,sdu,n+4,1);
    assert(a->ssap.writes==3 && chat_output(&f,text,sizeof text)==2*sizeof value);
    opt.interactive=1; stub_encrypted=0; on_sdu(a,sdu,n+4,1);
    assert(a->reason && !strcmp(a->reason,"ssap_failed") && a->ssap.writes==3);
    assert(chat_output(&f,text,sizeof text)==2*sizeof value);
    chat_close(&f);
}

static sle_frame_t captured;
static unsigned found;
static void capture(const sle_found_frame_t *f,void *unused)
{
    (void)unused;
    assert(f->frame.crc12_ok && f->frame.crc24_ok);
    captured=f->frame; found++;
}
static void decode(const sle_rt_wave *w,int mhz,int seed)
{
    sle_demod_channel_t *d=calloc(1,sizeof *d);assert(d);
    assert(!sle_demod_channel_init(d,SLE_RT_FS,0,mhz,capture,NULL));
    sle_demod_set_fir_bypass(d,1);sle_demod_set_dedup(d,1);
    assert(!sle_demod_add_broadcast_target(d,seed,0));
    size_t count=((w->n+512+255)/256)*256;
    int16_t *iq=calloc(count*2,sizeof *iq);assert(iq);
    memcpy(iq+200,w->iq,w->n*4);found=0;
    for(size_t k=0;k<count;k+=256)
        assert(sle_demod_channel_process(d,iq+2*k,256,k)==SLE_STREAM_OK);
    assert(found==1);free(iq);free(d);
}
static void cli_defaults(void)
{
    char *defaults[]={"sle_tnode",NULL};
    assert(parse(1,defaults)==1);
    assert(opt.resource_layout==SLE_RESOURCE_STANDARD);
    assert(opt.pair_variant==SLE_PAIR_V_COUNT_PLAIN && opt.predictive==1);
    assert(opt.local_mtu==520 && opt.tx_frag==24 && opt.cal_depth==6);
    char *compat[]={"sle_tnode","--resource-layout","legacy-ws63","--pair-variant","0x300","--reply-mode","delayed",NULL};
    assert(parse(7,compat)==1 && opt.resource_layout==SLE_RESOURCE_LEGACY_WS63);
    assert(opt.pair_variant==SLE_PAIR_PROFILE_WS63 && opt.predictive==0);
    char *sdk[]={"sle_tnode","--resource-layout","standard","--pair-variant","0x200","--reply-mode","predictive","--interactive","1",NULL};
    assert(parse(9,sdk)==1 && opt.resource_layout==SLE_RESOURCE_STANDARD);
    assert(opt.pair_variant==SLE_PAIR_V_COUNT_PLAIN && opt.predictive==1 && opt.interactive==1);
    opt.interactive=0;
    const char *removed[]={"--cal-capture","--establish-probe-ms","--pair-debug-keys","--capture"};
    for(size_t i=0;i<sizeof removed/sizeof removed[0];i++) {
        char *args[]={"sle_tnode",(char *)removed[i],"1",NULL};
        assert(parse(3,args)==2);
    }
}
int main(void)
{
    cli_defaults();
    assert(opt.resource_layout==SLE_RESOURCE_STANDARD);
    assert(opt.pair_variant==SLE_PAIR_V_COUNT_PLAIN);
    opt.resource_layout=SLE_RESOURCE_LEGACY_WS63; /* legacy codec vectors below */
    sle_t_wave_init();
    t_app *a=calloc(1,sizeof *a);assert(a);
    calibration_diagnostic(a);
    calibration_restart(a);
    advertisement_witness(a);
    connection_establish(a);
    schedule_log(a);
    readvertise_policy(a);
    conn_witness_policy(a);
    sdu_pump(a);
    chat_lines();
    interactive_input();
    interactive_backpressure();
    interactive_mtu();
    interactive_eof_and_signals();
    interactive_received_write();
    interactive_main_sigint();
    const uint8_t local[6]={0xc2,0x53,0x4c,0x45,0,0x20};
    memcpy(a->local,local,6);sle_rt_wave primary,aux;
    assert(!build_adv(a,&primary,&aux));
    decode(&primary,2424,77);
    assert(captured.packet_type==0 && captured.broadcast_type==1);
    sle_bcast_pdu_t p;assert(!sle_bcast_pdu_parse(captured.payload,captured.payload_len,&p));
    assert(p.present==(SLE_PRESENT_LOCAL_ID|SLE_PRESENT_RESOURCE));
    assert(!memcmp(p.local_id,local,6));sle_resource_word_t rw;
    sle_resource_word_decode(p.resource_word,&rw);
    assert(rw.channel==22 && sle_phys_to_mhz(rw.channel)==2426);
    assert(sle_resource_word_offset_us(&rw)==20000);
    assert(p.resource_word==0x00014016u); /* legacy fixed vector: 16 40 01 00 */
    opt.resource_layout=SLE_RESOURCE_STANDARD;
    assert(!build_adv(a,&primary,&aux));decode(&primary,2424,77);
    assert(!sle_bcast_pdu_parse(captured.payload,captured.payload_len,&p));
    assert(p.resource_word==0x0000a016u); /* standard: 16 a0 00 00 */
    assert(sle_resource_word_decode_layout(p.resource_word,SLE_RESOURCE_STANDARD,&rw)==SLE_ACC_OK);
    assert(rw.channel==22 && rw.unit==0 && rw.offset==160 && sle_resource_word_offset_us(&rw)==20000);
    opt.resource_layout=SLE_RESOURCE_LEGACY_WS63;
    assert(!build_adv(a,&primary,&aux)); /* remaining historical vectors stay legacy */
    decode(&aux,2426,22);
    assert(captured.packet_type==1 && captured.broadcast_type==1);
    assert(!sle_bcast_pdu_parse(captured.payload,captured.payload_len,&p));
    assert(!memcmp(p.local_id,local,6));size_t n;
    const uint8_t *v=sle_bcast_pdu_find_tlv(&p,SLE_TLV_DISC_ACCESS_CFG,&n);
    assert(v && n==7);
    /* Independent byte-level vector: offsets LE, count/GT, request type. */
    const uint8_t resource[]={0xc4,0x09,0xff,0xd4,0x30,0x04,0x01};
    assert(!memcmp(v,resource,sizeof resource));
    v=sle_bcast_pdu_find_tlv(&p,SLE_TLV_HIGH_LAYER,&n);
    assert(v && n==20 && v[0]==1 && v[1]==2 && v[2]==1);
    assert(v[3]==16 && v[4]==11 && !memcmp(v+5,"sle_uart_server",15));
    sle_access_rsp_info_t rsp={.count=1};
    const uint8_t peer[6]={0xee,0xef,0x33,0x9b,0x8d,0x5c};
    memcpy(rsp.unit[0].peer_id,peer,6);rsp.unit[0].repeat=1;rsp.unit[0].has_capability=1;
    const uint8_t cap[6]={0xff,0xcc,0x81,0x6a,0x43,0x18};
    memcpy(rsp.unit[0].capability,cap,6);uint8_t bytes[64];
    n=sle_access_response_build(local,&rsp,bytes,sizeof bytes);assert(n==24);
    const uint8_t expected[]={0x11,0,0xc2,0x53,0x4c,0x45,0,0x20,4,14,1,
        0xee,0xef,0x33,0x9b,0x8d,0x5c,0x40,0xff,0xcc,0x81,0x6a,0x43,0x18};
    assert(!memcmp(bytes,expected,sizeof expected));
    assert(!bcast_wave(&aux,bytes,n,22,1,5));decode(&aux,2426,22);
    assert(captured.packet_type==5 && captured.payload_len==24);
    assert(!memcmp(captured.payload,expected,sizeof expected));
    free(a);puts("T offline advertising, response and interactive checks passed");return 0;
}
