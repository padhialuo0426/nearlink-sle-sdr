/* Offline regression; build and coverage notes: ../docs/e310-source.md. */
#define _GNU_SOURCE
#include "sle_radio.h"
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; \
    fprintf(stderr,"Radio check failed %s:%d: %s\n",__FILE__,__LINE__,#x); } } while (0)
#include <signal.h>
#include "radio_fixtures.h"

/* Exercise actual static application state transitions using reviewer-style
 * wrapped I/O. These scripted frames are regression inputs only. */
#include "sle_g_runtime.h"
static int prepare_fault, prepare_signal, setup_calls, start_calls, event_fault;
static int post_start_signal, destroy_calls, cleanup_step;
static int event_write_fault(void *opaque,const char *row,size_t n);
static unsigned observed_pair_variant;
static int tested_pair_init(sle_g_runtime *r,const uint8_t g[6],const uint8_t t[6],uint32_t sync,int cpu,
                            unsigned variant)
{
    observed_pair_variant=variant;
    if (!prepare_fault) return sle_g_runtime_init_variant(r,g,t,sync,cpu,variant);
    memset(r,0,sizeof *r); r->rng_fd=-1; r->initialized=1;
    if (prepare_fault==2) { raise(prepare_signal ? prepare_signal:SIGTERM); return 0; }
    if (prepare_fault==3) return 0; /* inert runtime for post-start cleanup */
    return r->error=SLE_PAIR_ERR_RNG;
}
static int counted_runtime_destroy(sle_g_runtime *r)
{
    if (post_start_signal) { CHECK(cleanup_step==1); cleanup_step=2; destroy_calls++; }
    return sle_g_runtime_destroy(r);
}
/* Keep the actual main path offline, including its read-only RF-port probe. */
static int offline_iio_read(const char *path,char *buf,size_t n)
{
    (void)path;
    if (n) buf[0]=0;
    return -1;
}
static unsigned rotation_calls, modulation_calls;
static int compute_delay_samples;
static void advance_samples(int64_t delta);
static void counted_rotate(sle_rt_wave *out,const sle_rt_wave *in,double cfo)
{
    rotation_calls++; sle_rt_rotate(out,in,cfo);
    if (compute_delay_samples) advance_samples(compute_delay_samples);
}
static int counted_modulate(sle_rt_wave *out,const uint8_t *bits,size_t n,double cfo)
{
    modulation_calls++; return sle_rt_modulate(out,bits,n,cfo);
}
#define sle_rt_rotate counted_rotate
#define sle_rt_modulate counted_modulate
#define sle_g_runtime_init_variant tested_pair_init
#define SLE_RT_WAIT_HOOK() advance_samples(SLE_RT_BLOCK)
#define SLE_RT_EVENT_WRITE_FAULT(a,row,n) event_write_fault(a,row,n)
#define sle_g_runtime_destroy counted_runtime_destroy
#define sle_iio_read offline_iio_read
#define main sle_rt_program_main
#include "sle_gnode.c"
#undef main
#undef sle_g_runtime_destroy
#undef sle_iio_read
#undef SLE_RT_EVENT_WRITE_FAULT
#undef sle_rt_rotate
#undef sle_rt_modulate
#undef sle_g_runtime_init_variant

/* The hook is confined to the optional event write, with production default 0.
 * Fault 1 models a failed first write; fault 2 models capacity after start. */
static int event_write_fault(void *opaque,const char *row,size_t n)
{
    app *a=opaque;
    char terminated[8192];
    CHECK(n<sizeof terminated);
    if (n>=sizeof terminated) return 1;
    memcpy(terminated,row,n); terminated[n]=0;
    if (!strstr(terminated,"\"kind\":\"cleanup\""))
        CHECK(a->used>=n && !memcmp(a->log+a->used-n,row,n));
    if (strstr(terminated,"\"kind\":\"attempt_start\"")) {
        if (event_fault==1) { errno=EIO; return 1; }
        if (event_fault==2) { a->used=LOG_CAP-LOG_TAIL; a->log_full=1; }
    }
    return 0;
}
static app *subject;
static int scenario, armed, retunes, stop_calls, restore_calls, signal_to_raise, submit_error;
static int64_t fake_mono, fake_sample, tx_retune_samples, rx_retune_samples, ack_delay_samples;
static int64_t access_rsp_sample, leakage_shift;
static int settling, settle_delay, settle_stall, access_leak, response_fault, rx_retune_error, cleanup_error;
static sle_rt_received scripted[3];
static unsigned consumed, issued, scripted_count;
static int submit_depth_min=99, submit_depth_max;
static uint8_t last_cal_marker[16];
enum { ACCESS_TEST, ONE_REPLY, REPEATED_REPLY, BODYFAIL_REPLY, SIGNAL_TEST, ACK_TIMEOUT, ACK_SIGNAL,
       FIRST_NO_LEAK, FIRST_OFFSET_JUMP, CAL_OFFSET_JUMP, SCAN_CACHE, LONG_PAIR_WITNESS,
       CAL_RECOVER_ONCE, CAL_JUMP_TO_LIMIT, CAL_SUCCEED_AT_LIMIT };
static void advance_samples(int64_t delta)
{
    fake_sample+=delta; fake_mono=fake_sample*250;
    atomic_store(&subject->radio->rx_head,fake_sample);
    atomic_store(&subject->radio->tx_head,fake_sample+SLE_RT_ACCESS_DEPTH*SLE_RT_BLOCK);
}
int64_t __wrap_sle_iio_now_ns(void)
{
    if (scenario==ACK_TIMEOUT) fake_mono+=1000000;
    if (settling) {
        int64_t head=atomic_load(&subject->radio->rx_head);
        advance_samples(settle_delay);
        if (settle_stall) atomic_store(&subject->radio->rx_head,head);
    }
    return fake_mono;
}
int64_t __wrap_sle_rt_radio_now(const sle_rt_radio *r) { (void)r; return fake_sample; }
int __wrap_sle_iio_realtime(int cpu,int prio) { (void)cpu; (void)prio; return 0; }
int __wrap_sle_rt_radio_retune(int tx,int mhz)
{
    (void)mhz; retunes++;
    if (scenario==ACCESS_TEST) {
        CHECK(tx ? !armed && retunes==1 : armed==1 && retunes==2);
        advance_samples(tx ? tx_retune_samples:rx_retune_samples);
        if (!tx) { settling=1; return rx_retune_error; }
    }
    return 0;
}
int __wrap_sle_rt_radio_submit(sle_rt_radio *r,const sle_rt_command *c)
{
    if (submit_error) return submit_error;
    armed+=c->wave.n>0; issued++; consumed=0; scripted_count=2;
    { int d=atomic_load(&r->depth); if (d<submit_depth_min) submit_depth_min=d; if (d>submit_depth_max) submit_depth_max=d; }
    if (scenario==ACK_TIMEOUT) { fake_mono+=21000000; return 0; }
    if (scenario==ACK_SIGNAL) { raise(SIGTERM); return 0; }
    atomic_store(&r->ack_result,SLE_RT_OK); atomic_store(&r->ack_seq,c->seq);
    if (scenario==SCAN_CACHE) {
        CHECK(!c->wave.n && c->estimate_cfo); scripted_count=3;
        const int64_t sample[]={10000,20000,250000};
        for (int i=0;i<3;i++) {
            scripted[i]=(sle_rt_received){.seq=c->seq,.f=primary(),.cfo_hz=-69000+i*250};
            scripted[i].f.sample_index=(uint64_t)sample[i];
        }
        return 0;
    }
    if (scenario==ACCESS_TEST) {
        CHECK(retunes==1); /* TX tuned; RX must still be on the primary */
        const sle_rt_wave *w=&subject->cache->request[c->seed];
        CHECK(c->wave.n==w->n && !memcmp(c->wave.iq,w->iq,w->n*4));
        advance_samples(ack_delay_samples);
        scripted_count=0;
        if (access_leak) {
            sle_rt_received *v=&scripted[scripted_count++]; memset(v,0,sizeof *v);
            v->seq=c->seq; v->f.channel_mhz=c->mhz;
            v->f.sample_index=(uint64_t)(c->tx_start+sle_rt_sync_in_wave()+subject->cal.offset+leakage_shift);
            sle_frame_t *f=&v->f.frame;
            f->seed=(uint8_t)c->seed; f->packet_type=4; f->broadcast_type=1;
            f->crc12_ok=f->has_crc24=f->crc24_ok=1; f->length=f->payload_len=84;
            memcpy(f->payload,subject->request,84);
        }
        if (response_fault!=7) {
            sle_rt_received *v=&scripted[scripted_count++]; memset(v,0,sizeof *v);
            v->seq=c->seq; v->f=response(); v->f.sample_index=(uint64_t)access_rsp_sample;
            v->f.channel_mhz=c->mhz; v->f.frame.seed=(uint8_t)c->seed;
            memcpy(v->f.frame.payload+11,subject->peer.local,6);
            if (response_fault==1) v->f.frame.payload[2]^=1; /* source */
            if (response_fault==2) v->f.frame.payload[11]^=1; /* destination */
            if (response_fault==3) v->f.frame.crc24_ok=0;
            if (response_fault==4) v->f.sample_index+=SLE_RT_REPLY_TOL+1;
            if (response_fault==5) v->f.frame.payload[17]=0x41; /* explicit rejection */
            if (response_fault==6) v->f.frame.crc12_ok=0;
        }
        if (response_fault==8 && scripted_count==2) {
            sle_rt_received v=scripted[0]; scripted[0]=scripted[1]; scripted[1]=v;
        }
        return 0;
    }
    if (scenario==CAL_RECOVER_ONCE || scenario==CAL_JUMP_TO_LIMIT ||
        scenario==CAL_SUCCEED_AT_LIMIT) {
        /* Every trial must use a fresh marker; a stale RF leakage frame cannot
         * be credited toward any of the three post-jump observations. */
        CHECK(scripted_count==2 && c->wave.n>0);
        if (issued>1) CHECK(memcmp(last_cal_marker,subject->marker,sizeof last_cal_marker)!=0);
        memcpy(last_cal_marker,subject->marker,sizeof last_cal_marker);
        sle_rt_received *v=&scripted[0]; memset(v,0,sizeof *v); scripted_count=1;
        /* Zero-based trial 8 jumps, leaving indices 9/10/11 for fresh markers. */
        static const int late_offsets[12]={0,9,0,8,9,0,9,0,9,0,8,0};
        CHECK(issued<=12);
        int64_t offset=scenario==CAL_JUMP_TO_LIMIT ? ((issued-1)&1 ? SLE_RT_OFFSET_TOL+1:0) :
            scenario==CAL_SUCCEED_AT_LIMIT ? late_offsets[issued<=12 ? issued-1:11] :
            issued==2 ? SLE_RT_OFFSET_TOL+1 : issued==4 ? SLE_RT_OFFSET_TOL : 0;
        v->seq=c->seq;
        v->f.sample_index=(uint64_t)(c->tx_start+sle_rt_sync_in_wave()+offset);
        v->f.frame.crc24_ok=1; v->f.frame.payload_len=sizeof subject->marker;
        memcpy(v->f.frame.payload,subject->marker,sizeof subject->marker);
        settling=1; settle_delay=SLE_RT_BLOCK;
        return 0;
    }
    if (scenario==CAL_OFFSET_JUMP) {
        sle_rt_received *v=&scripted[0]; memset(v,0,sizeof *v); scripted_count=1;
        v->seq=c->seq; v->f.sample_index=(uint64_t)(c->tx_start+sle_rt_sync_in_wave()+SLE_RT_OFFSET_TOL+1);
        v->f.frame.crc24_ok=1; v->f.frame.payload_len=sizeof subject->marker;
        memcpy(v->f.frame.payload,subject->marker,sizeof subject->marker);
        return 0;
    }
    int64_t sync=c->tx_start+sle_rt_sync_in_wave();
    if (scenario==LONG_PAIR_WITNESS) {
        size_t n=subject->g_runtime->tx_secure ? 77:73;
        sle_conn_sched_t s; CHECK(!sle_conn_sched_init(&s,0,&subject->peer.txi));
        int64_t second=sync+sle_ns_to_samples(sle_second_sender_offset_ns(&s,(uint32_t)n,0)-3000,SLE_RT_FS);
        CHECK(c->rx_end==second+SAMPLES_US(3000));
        for (int i=0;i<2;i++) {
            sle_rt_received *v=&scripted[i]; memset(v,0,sizeof *v);
            v->seq=c->seq; v->f.channel_mhz=c->mhz;
            v->f.sample_index=(uint64_t)(i ? second:sync);
            sle_frame_t *f=&v->f.frame;
            f->kind=SLE_FRAME_CONNECT; f->seed=(uint8_t)c->seed;
            f->crc12_ok=f->has_crc24=f->crc24_ok=1;
            if (i) { f->conn_empty=1; f->conn_nesn=1; }
            else {
                f->conn_pkt_type=SLE_PTYPE_CTRL; f->length=f->payload_len=(uint16_t)n;
                memcpy(f->payload,subject->g_runtime->wire,n);
            }
        }
        /* At 501 us the 73/77B own packet is still being received. */
        settling=1; return 0;
    }
    for (int i=0;i<2;i++) {
        sle_rt_received *v=&scripted[i]; memset(v,0,sizeof *v);
        v->seq=c->seq; v->f.channel_mhz=c->mhz; v->f.sample_index=(uint64_t)(sync+i*988);
        v->f.frame.kind=SLE_FRAME_CONNECT; v->f.frame.seed=(uint8_t)c->seed;
        v->f.frame.crc12_ok=1; v->f.frame.conn_empty=1;
        if (i && scenario==BODYFAIL_REPLY) { v->f.frame.has_crc24=1; v->f.frame.conn_empty=0; }
    }
    if (scenario==FIRST_NO_LEAK) { scripted[0]=scripted[1]; scripted_count=1; }
    if (scenario==FIRST_OFFSET_JUMP) scripted[0].f.sample_index+=SLE_RT_OFFSET_TOL+1;
    return 0;
}
int __wrap_sle_rt_ring_pop(sle_rt_frame_ring *q,sle_rt_received *f)
{
    if (scenario==LONG_PAIR_WITNESS && settling) {
        settling=0;
        advance_samples((int64_t)scripted[0].f.sample_index+SAMPLES_US(501)-fake_sample);
        return -1;
    }
    (void)q; settling=0;
    if (consumed<scripted_count) {
        *f=scripted[consumed++];
        int64_t end=(int64_t)f->f.sample_index+300+f->f.frame.payload_len*32;
        if (scenario==SCAN_CACHE) end=(int64_t)f->f.sample_index+3000;
        if (end>fake_sample) advance_samples(end-fake_sample);
        if (scenario==CAL_RECOVER_ONCE || scenario==CAL_JUMP_TO_LIMIT ||
            scenario==CAL_SUCCEED_AT_LIMIT) settling=1;
        return 0;
    }
    if (scenario==ONE_REPLY || scenario==LONG_PAIR_WITNESS) {
        fake_sample=(int64_t)scripted[1].f.sample_index+1;
        atomic_store(&subject->radio->rx_head,fake_sample);
        fake_mono=subject->deadline+1;
    }
    if (scenario==ACCESS_TEST || scenario==FIRST_NO_LEAK) advance_samples(SLE_RT_BLOCK);
    if (scenario==SCAN_CACHE) fake_mono=subject->deadline+1;
    return -1;
}
int __wrap_sle_rt_radio_setup(double tx,double rx)
{
    (void)tx; (void)rx;
    setup_calls++;
    CHECK(scenario==SIGNAL_TEST);
    if (post_start_signal) return 0;
    raise(signal_to_raise); return -1;
}
int __wrap_sle_rt_radio_start(sle_rt_radio *r,int cpu,int prio)
{
    (void)cpu; (void)prio; start_calls++;
    if (post_start_signal) {
        CHECK(!cleanup_step); r->started=1;
        raise(post_start_signal); return 0;
    }
    CHECK(0); return -1; /* other signal scenarios must stop before start */
}
int __wrap_sle_rt_radio_stop(sle_rt_radio *r)
{
    if (post_start_signal) {
        CHECK(r->started && atomic_load(&r->stop) && !cleanup_step);
        cleanup_step=1;
    }
    stop_calls++; r->started=0; atomic_store(&r->stop,1); atomic_store(&r->pending,0);
    sle_rt_render_clear(&r->renderer); settling=0; return cleanup_error;
}
int __wrap_sle_rt_radio_restore(void)
{
    if (post_start_signal) { CHECK(cleanup_step==2); cleanup_step=3; }
    restore_calls++; return 0;
}
static void reset_app(app *a)
{
    memset(a,0,sizeof *a); a->reason="initialization_failed"; a->deadline=1000000000;
    sle_sdu_rx_init(&a->sdu_rx,SLE_SDU_MAX);
    a->radio=calloc(1,sizeof *a->radio); a->log=calloc(1,LOG_CAP); a->requests=calloc(76,sizeof *a->requests);
    a->cache=calloc(1,sizeof *a->cache);
    if (!a->radio || !a->log || !a->requests || !a->cache) abort();
    CHECK(!sle_rt_peer_init(&a->peer,opt.local,opt.server,opt.lid,opt.crc,opt.slot));
    a->cal=(sle_rt_cal){.valid=1,.count=3,.offset=0};
    atomic_init(&a->radio->depth,SLE_RT_ACCESS_DEPTH);
    subject=a; armed=retunes=stop_calls=0; issued=consumed=0; fake_sample=fake_mono=0;
    interrupted=submit_error=settling=access_leak=response_fault=rx_retune_error=cleanup_error=0;
    settle_delay=64; settle_stall=0;
    tx_retune_samples=6700; rx_retune_samples=6700; ack_delay_samples=0; leakage_shift=0;
    access_rsp_sample=33600; scripted_count=0; memset(last_cal_marker,0,sizeof last_cal_marker);
    opt.auto_cfo=0; opt.cfo=0; rotation_calls=modulation_calls=0; compute_delay_samples=0;
}
static void free_app(app *a) { free(a->radio); free(a->log); free(a->requests); free(a->cache); }
static int iq_error(const int16_t *a,const int16_t *b,size_t n)
{
    int max=0;
    for (size_t i=0;i<2*n;i++) { int e=abs(a[i]-b[i]); if (e>max) max=e; }
    return max;
}
static void cache_regression(void)
{
    app a; reset_app(&a); scenario=ACCESS_TEST; opt.cfo=-69278.397;
    CHECK(!prepare_waves(&a) && a.cache->valid && a.cache->source_sample==-1 && a.cache->cfo==opt.cfo);
    const double offsets[]={0,-69278.397,12500.25,-200000,200000};
    sle_rt_wave ref; uint8_t bits[1024]; int max=0;
    for (size_t k=0;k<sizeof offsets/sizeof offsets[0];k++) {
        CHECK(!cache_build(&a,offsets[k],-1));
        for (int seed=0;seed<76;seed++) {
            size_t nb=sle_access_encode_frame(bits,sizeof bits,a.request,sizeof a.request,(uint8_t)seed,1,4);
            CHECK(nb && !sle_rt_modulate(&ref,bits,nb,offsets[k]));
            const sle_rt_wave *w=&a.cache->request[seed];
            int e=iq_error(ref.iq,w->iq,ref.n); if (e>max) max=e;
            CHECK(w->n==ref.n && e<=2);
        }
        sle_link_t *l=calloc(1,sizeof *l); if (!l) abort();
        l->s.lid=a.peer.txi.first_lid; l->crc_init=a.peer.txi.first_crc_init;
        for (int seed=64;seed<128;seed++) for (int nesn=0;nesn<2;nesn++) {
            sle_link_tx_t tx={.empty=1,.ptype=SLE_PTYPE_DATA,.nesn=(uint8_t)nesn};
            tx.ev.white_seed=(uint8_t)seed;
            size_t nb=sle_link_encode(l,&tx,bits,sizeof bits);
            CHECK(nb && !sle_rt_modulate(&ref,bits,nb,offsets[k]));
            const empty_wave *w=&a.cache->empty[seed-64][nesn];
            int e=ref.n<=EMPTY_SAMPLES ? iq_error(ref.iq,w->iq,ref.n):INT_MAX;
            if (e>max) max=e;
            CHECK(w->n==ref.n && e<=2);
        }
        free(l);
    }
    printf("Radio cached IQ vs direct CFO modulation: 76 request seeds, 64 x 2 empty variants, 5 CFOs; max IQ error %d LSB\n",max);
    CHECK(cache_build(&a,NAN,-1)==-1 && !a.cache->valid);
    CHECK(cache_build(&a,200001,-1)==-1 && !a.cache->valid);
    free_app(&a);

    /* A bulk build costs 51 ms in this script: neither its source primary nor
     * the queued primary during the build may be used for access. */
    reset_app(&a); scenario=SCAN_CACHE; opt.auto_cfo=1; CHECK(!prepare_waves(&a));
    CHECK(!a.cache->valid); compute_delay_samples=1000;
    sle_access_plan_t p;
    CHECK(!scan(&a,&p) && a.primary_sample==250000 && a.cache->source_sample==10000);
    CHECK(a.cache->ready_sample==217000 && a.cache->build_ns==51000000);
    CHECK(a.cfo==-69000 && a.cfo_delta==500 && a.primary_pending);
    CHECK(!strstr(a.log,"\"kind\":\"access_plan\"") && !strstr(a.log,"\"kind\":\"access_slack\""));
    unsigned rotations=rotation_calls, mods=modulation_calls;
    size_t sample_count=a.cache->request[p.aux_channel].n;
    scenario=ACCESS_TEST; access_rsp_sample=sle_ns_to_samples(p.rsp_sync_ns,SLE_RT_FS);
    CHECK(!access_peer(&a,&p) && a.request_submitted);
    CHECK(rotation_calls==rotations && modulation_calls==mods && rotations==204);
    CHECK(sample_count>0 && a.copy_ns==0 && strstr(a.log,"\"rotation_in_access\":false"));
    CHECK(strstr(a.log,"\"cfo_source_sample\":10000") && strstr(a.log,"\"cfo_delta_hz\":500.000"));
    CHECK(!a.primary_pending && !a.n_slack);

    /* Reuse does not refresh source age; drift or expiry rebuilds and skips
     * that primary. Invalid estimates never authorize cached transmission. */
    compute_delay_samples=0;
    sle_rt_received f={.f=primary(),.cfo_hz=-69000}; f.f.sample_index=400000;
    advance_samples(401000-fake_sample);
    CHECK(cache_primary(&a,&f,401000)==1 && a.cache->source_sample==10000);
    f.cfo_hz=-67000; CHECK(cache_primary(&a,&f,401000)==1); /* boundary */
    f.cfo_hz=-66999; CHECK(cache_primary(&a,&f,401000)==0 && a.cache->cfo==-66999);
    CHECK(a.cache->source_sample==400000);
    f.f.sample_index=402000; f.cfo_hz=NAN;
    CHECK(cache_primary(&a,&f,403000)==0);
    f.cfo_hz=-66999; f.f.sample_index=400000+CFO_TTL+1;
    advance_samples((int64_t)f.f.sample_index+1000-fake_sample);
    CHECK(cache_primary(&a,&f,(int64_t)f.f.sample_index+1000)==0 && a.cache->source_sample==(int64_t)f.f.sample_index);
    CHECK(strstr(a.log,"\"reason\":\"change\"") && strstr(a.log,"\"reason\":\"age\""));
    free_app(&a); opt.auto_cfo=0; opt.cfo=0;

    /* A missing or aged bank is never replaced with on-demand rotation in
     * access, including expiry between the selected primary and submission. */
    for (int expired=0;expired<2;expired++) {
        reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
        f.f=primary(); f.f.sample_index=0;
        CHECK(!sle_rt_primary(&a.peer,&f.f,0,0,0,&p));
        opt.auto_cfo=1; a.cache->valid=expired; a.cache->source_sample=-CFO_TTL+10000;
        rotations=rotation_calls; mods=modulation_calls;
        CHECK(access_peer(&a,&p)==-1 && !armed && !retunes);
        CHECK(!strcmp(a.reason,expired ? "cfo_cache_expired":"wave_cache_missing"));
        CHECK(rotation_calls==rotations && modulation_calls==mods); free_app(&a);
    }
    opt.auto_cfo=0;
}
/* Count exact journal rows, rather than allowing a substring in one row to
 * stand in for all retries. The main path owns radio restore; these direct
 * calibrate() fixtures can only assert its mocked cleanup call explicitly. */
static unsigned journal_rows(const app *a,const char *kind)
{
    char needle[96]; unsigned count=0;
    int n=snprintf(needle,sizeof needle,"\"kind\":\"%s\"",kind);
    CHECK(n>0 && (size_t)n<sizeof needle);
    if (n<=0 || (size_t)n>=sizeof needle) return 0;
    for (const char *p=a->log;(p=strstr(p,needle))!=NULL;p+=n) count++;
    return count;
}
static void calibration_recovery_regression(void)
{
    app a;
    reset_app(&a); scenario=CAL_RECOVER_ONCE; a.cal.valid=0; a.cal.count=0;
    CHECK(!prepare_waves(&a));
    submit_depth_min=99; submit_depth_max=0;
    CHECK(calibrate(&a)==0 && a.cal.valid && a.cal.count==SLE_RT_CAL_COUNT && a.cal.offset==0);
    /* Every calibration burst is submitted with the deeper reserve; the
     * access depth is restored only after the extra blocks have drained. */
    CHECK(submit_depth_min==opt.cal_depth && submit_depth_max==opt.cal_depth &&
          atomic_load(&a.radio->depth)==SLE_RT_ACCESS_DEPTH && journal_rows(&a,"cal_depth")==2);
    CHECK(strstr(a.log,"\"phase\":\"raise\",\"depth\":6,\"restore_depth\":3")!=NULL &&
          strstr(a.log,"\"settle_error\":0")!=NULL);
    CHECK(issued==5 && journal_rows(&a,"calibration")==5 &&
          journal_rows(&a,"calibration_restart")==1);
    CHECK(strstr(a.log,"\"result\":\"offset_jump\"")!=NULL &&
          strstr(a.log,"\"reason\":\"initial_offset_jump\"")!=NULL &&
          strstr(a.log,"\"remaining_trials\":10")!=NULL);
    CHECK(atomic_load(&a.radio->guard)==1 && !stop_calls);
    CHECK(strstr(a.log,"\"candidate_offset\":9,\"offset_before\":0,\"count_before\":1,")!=NULL);
    CHECK(strstr(a.log,"\"valid_after\":false,\"cleared\":true")!=NULL);
    CHECK(journal_rows(&a,"calibration_failure")==1);
    free_app(&a);

    /* Zero-based trial 8 is the last possible jump allowing three new bursts.
     * The third new marker at index 11 (twelfth attempt) must still count. */
    reset_app(&a); scenario=CAL_SUCCEED_AT_LIMIT; a.cal.valid=0; a.cal.count=0;
    CHECK(!prepare_waves(&a));
    CHECK(calibrate(&a)==0 && a.cal.valid && a.cal.count==SLE_RT_CAL_COUNT && a.cal.offset==0);
    CHECK(issued==12 && journal_rows(&a,"calibration")==12 &&
          journal_rows(&a,"calibration_restart")==4);
    CHECK(strstr(a.log,"\"remaining_trials\":3")!=NULL &&
          atomic_load(&a.radio->guard)==1 && !stop_calls);
    free_app(&a);

    /* Alternating 0/+9 samples forces a new jump after each fresh first
     * marker. The last jump is trial 11: it cannot silently add trial 12. */
    reset_app(&a); scenario=CAL_JUMP_TO_LIMIT; a.cal.valid=0; a.cal.count=0;
    restore_calls=0;
    CHECK(!prepare_waves(&a));
    CHECK(calibrate(&a)==-1 && !a.cal.valid && a.cal.count==0);
    CHECK(issued==12 && journal_rows(&a,"calibration")==12 &&
          journal_rows(&a,"calibration_restart")==6);
    CHECK(strstr(a.log,"\"remaining_trials\":0")!=NULL &&
          !strcmp(a.reason,"calibration_failed") && !atomic_load(&a.radio->guard));
    CHECK(atomic_load(&a.radio->depth)==SLE_RT_ACCESS_DEPTH && journal_rows(&a,"cal_depth")==2);
    CHECK(!sle_rt_radio_stop(a.radio) && !sle_rt_radio_restore());
    CHECK(stop_calls==1 && restore_calls==1 && atomic_load(&a.radio->stop));
    free_app(&a);

    /* A valid previous calibration is a separate fail-closed path. */
    reset_app(&a); scenario=CAL_OFFSET_JUMP;
    CHECK(!prepare_waves(&a));
    CHECK(calibrate(&a)==-1 && !a.cal.valid && !strcmp(a.reason,"calibration_offset_jump"));
    CHECK(issued==1 && journal_rows(&a,"calibration")==1 &&
          journal_rows(&a,"calibration_restart")==0);
    free_app(&a);
}
static void access_regression(void)
{
    app a; reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
    sle_found_frame_t f=primary(); f.sample_index=0;
    sle_access_plan_t p;
    CHECK(!sle_rt_primary(&a.peer,&f,0,0,0,&p));
    fake_sample=6200; fake_mono=fake_sample*250;
    CHECK(access_peer(&a,&p)==-1 && !armed && !retunes && !a.request_submitted);
    CHECK(!strcmp(a.reason,"access_tx_budget")); free_app(&a);
    /* Measured primary ages and worst recorded retunes: request is submitted
     * after TX tune, response accepted without manufacturing a TX witness. */
    for (int age=300;age<=700;age+=200) {
        reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
        advance_samples(age*4); tx_retune_samples=8408; rx_retune_samples=7720;
        sle_rt_cal before=a.cal;
        CHECK(!access_peer(&a,&p) && armed==1 && retunes==2 && !stop_calls && a.request_submitted);
        CHECK(!a.access_timing_verified && a.cal.last_sample==before.last_sample && a.cal.offset==before.offset);
        CHECK(strstr(a.log,"\"timing_verified\":false,\"calibration_refreshed\":false")!=NULL);
        CHECK(strstr(a.log,"\"primary_age_us\"") && strstr(a.log,"\"request_slack_us\"") &&
              strstr(a.log,"\"response_slack_us\""));
        free_app(&a);
    }
    reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
    advance_samples(800); access_leak=1; response_fault=8; leakage_shift=SLE_RT_OFFSET_TOL+1;
    CHECK(access_peer(&a,&p)==-1 && !a.cal.valid && !a.access_timing_verified);
    CHECK(!strcmp(a.reason,"access_offset_jump") && !strstr(a.log,"access_accepted")); free_app(&a);
    reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
    advance_samples(800); access_leak=1; response_fault=7;
    CHECK(access_peer(&a,&p)==-1 && a.access_timing_verified && a.cal.last_sample==18600);
    CHECK(!strcmp(a.reason,"access_response_timeout") && !strstr(a.log,"access_accepted")); free_app(&a);
    /* A real request witness refreshes calibration; a jump aborts instead. */
    for (int jump=0;jump<2;jump++) {
        reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
        advance_samples(800); access_leak=1; leakage_shift=jump ? SLE_RT_OFFSET_TOL+1:0;
        CHECK(access_peer(&a,&p)==(jump ? -1:0));
        CHECK(jump ? !a.cal.valid && stop_calls==1 && !strcmp(a.reason,"access_offset_jump") :
              a.access_timing_verified && a.cal.last_sample==18600);
        free_app(&a);
    }
    /* Actual TX overrun: no request (including its prefix) is submitted. */
    reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
    advance_samples(800); tx_retune_samples=15200;
    CHECK(access_peer(&a,&p)==-1 && retunes==1 && !armed && !a.request_submitted);
    CHECK(!strcmp(a.reason,"late"));
    free_app(&a);
    /* RX feasibility is checked both before tuning and before submission. */
    for (int phase=0;phase<2;phase++) {
        reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
        sle_access_plan_t early=p; early.rsp_sync_ns=phase ? 6000000:5000000;
        advance_samples(800); tx_retune_samples=12000;
        CHECK(access_peer(&a,&early)==-1 && !armed && !a.request_submitted && retunes==phase);
        CHECK(!strcmp(a.reason,"access_rx_budget")); free_app(&a);
    }
    /* RX overruns/errors happen AFTER submission: stop and retain evidence. */
    for (int fault=0;fault<3;fault++) {
        reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
        advance_samples(800); rx_retune_samples=fault==1 ? 6700:27000;
        rx_retune_error=fault==1 ? -1:0; cleanup_error=fault==2 ? -1:0;
        CHECK(access_peer(&a,&p)==-1 && armed==1 && retunes==2 && a.request_submitted && stop_calls==1);
        CHECK(!strcmp(a.reason,fault==1 ? "retune_failed":"rx_retune_late_for_response"));
        CHECK(strstr(a.log,"access_failed_after_submit") && strstr(a.log,"\"tx_may_have_run\":true"));
        CHECK(!strstr(a.log,"access_not_sent") && a.cleanup_failed==(fault==2)); free_app(&a);
    }
    for (int stalled=0;stalled<2;stalled++) {
        reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
        /* RX retune now starts after the request burst (see access_run); every
         * clock read while settling adds settle_delay, so use a shorter retune
         * and step to keep the unstalled case on the settle-late path. */
        advance_samples(800); settle_delay=stalled ? 1024:2500; settle_stall=stalled;
        rx_retune_samples=1000;
        CHECK(access_peer(&a,&p)==-1 && a.request_submitted && stop_calls==1);
        CHECK(!strcmp(a.reason,"rx_ready_late_for_response")); free_app(&a);
    }
    /* A late ACK cannot silently consume the RX retune budget. */
    reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
    advance_samples(800); ack_delay_samples=SLE_RT_ACCESS_ACK_US*4+1;
    CHECK(access_peer(&a,&p)==-1 && armed==1 && retunes==1 && a.request_submitted && stop_calls==1);
    CHECK(!strcmp(a.reason,"command_ack_timeout")); free_app(&a);
    /* TTL must remain valid at the planned request, not just at admission. */
    reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a));
    a.cal.last_sample=-CAL_TTL+5000;
    CHECK(access_peer(&a,&p)==-1 && !armed && !retunes && !strcmp(a.reason,"calibration_expired")); free_app(&a);
    /* Wrong source/destination, either CRC, wrong time, rejection or silence
     * cannot be made successful by allowing access without request leakage. */
    for (int fault=1;fault<=7;fault++) {
        reset_app(&a); scenario=ACCESS_TEST; CHECK(!prepare_waves(&a)); response_fault=fault;
        advance_samples(800);
        CHECK(access_peer(&a,&p)==-1 && a.request_submitted && stop_calls==1 && !a.access_timing_verified);
        CHECK(!strcmp(a.reason,fault==5 ? "server_rejected_access":"access_response_timeout"));
        CHECK(!a.cal.last_sample && !strstr(a.log,"access_accepted")); free_app(&a);
    }
    for (int mode=ACK_TIMEOUT;mode<=ACK_SIGNAL;mode++) {
        reset_app(&a); scenario=mode;
        sle_rt_command c={.mhz=2424,.seed=77,.rx_end=INT64_MAX,.tx_start=10000}; c.wave.n=1;
        CHECK(issue(&a,&c)==-1 && armed==1 && stop_calls==1 && atomic_load(&a.radio->stop));
        CHECK(!strcmp(a.reason,mode==ACK_TIMEOUT ? "command_ack_timeout":"signal"));
        CHECK(strstr(a.log,"\"tx_may_have_run\":true")!=NULL);
        free_app(&a);
    }
    reset_app(&a); scenario=ACCESS_TEST; submit_error=SLE_RT_LATE;
    sle_rt_command c={.mhz=2424,.seed=77,.rx_end=INT64_MAX}; c.wave.n=1;
    CHECK(issue(&a,&c)==-1 && !armed && stop_calls==1 && !a.command_submitted); free_app(&a);
}
static void connection_regression(void)
{
    app a; sle_access_plan_t p={.req_sync_ns=0};
    for (int mode=FIRST_NO_LEAK;mode<=FIRST_OFFSET_JUMP;mode++) {
        reset_app(&a); scenario=mode;
        CHECK(!prepare_waves(&a));
        /* A missing local witness makes the event lost (peer reply ignored);
         * the connection stops only after SLE_RT_WITNESS_MISS_LIMIT in a row. */
        int want=mode==FIRST_NO_LEAK ? SLE_RT_WITNESS_MISS_LIMIT:1;
        CHECK(connection(&a,&p)==-1 && a.events==(unsigned)want && !a.valid_received && !a.received);
        CHECK(!strcmp(a.reason,mode==FIRST_NO_LEAK ? "event_leakage_missing":"connection_offset_jump"));
        if (mode==FIRST_NO_LEAK)
            CHECK(strstr(a.log,"\"kind\":\"event_witness_missing\",\"k\":0,\"run\":1") &&
                  strstr(a.log,"\"run\":3,\"limit\":3") && strstr(a.log,"peer_without_tx_witness"));
        CHECK(!a.cal.last_sample && !strstr(a.log,"connection_maintained")); free_app(&a);
    }
    reset_app(&a); scenario=ONE_REPLY;
    CHECK(!prepare_waves(&a));
    opt.connect_seconds=15; opt.hold_seconds=10;
    CHECK(connection(&a,&p)==-1 && a.events==1 && a.received==1 && a.valid_received==1);
    CHECK(a.last_peer_ns==a.connected_ns && !strcmp(a.reason,"connection_budget_exhausted"));
    CHECK(!strstr(a.log,"connection_maintained")); free_app(&a);
    reset_app(&a); scenario=REPEATED_REPLY; opt.connect_seconds=1;
    CHECK(!prepare_waves(&a));
    CHECK(connection(&a,&p)==-1 && a.valid_received>1);
    CHECK(a.last_peer_ns-a.connected_ns<1000000000LL && !strstr(a.log,"connection_maintained"));
    free_app(&a);
    reset_app(&a); scenario=BODYFAIL_REPLY; opt.connect_seconds=1;
    CHECK(!prepare_waves(&a));
    CHECK(connection(&a,&p)==-1 && a.received>1 && !a.valid_received); free_app(&a);
    reset_app(&a); scenario=REPEATED_REPLY; opt.connect_seconds=15;
    CHECK(!prepare_waves(&a)); unsigned rotations=rotation_calls, mods=modulation_calls;
    a.deadline=1; /* virtually no scan budget remains; connection gets its own */
    CHECK(!connection(&a,&p) && a.valid_received>=801);
    CHECK(a.last_peer_ns-a.connected_ns>=10000000000LL && !strcmp(a.reason,"connection_maintained"));
    CHECK(a.deadline==15000000000LL);
    CHECK(rotation_calls==rotations && modulation_calls==mods); free_app(&a);
}
static void signal_regression(void)
{
    const int signals[]={SIGINT,SIGTERM,SIGHUP,SIGPIPE};
    for (size_t i=0;i<sizeof signals/sizeof signals[0];i++) {
        interrupted=0; scenario=SIGNAL_TEST; signal_to_raise=signals[i]; restore_calls=0;
        char *args[]={"sle_gnode","--attempts","1","--log","/dev/null",NULL};
        CHECK(sle_rt_program_main(5,args)==128+signals[i]);
        CHECK(restore_calls==1 && interrupted==signals[i]);
    }
}
static void sle_rt_application_regression(void)
{
    options saved=opt;
    for (int secure=0;secure<2;secure++) {
        app long_frame; reset_app(&long_frame); scenario=LONG_PAIR_WITNESS;
        CHECK(!prepare_waves(&long_frame));
        long_frame.g_runtime=calloc(1,sizeof *long_frame.g_runtime); CHECK(long_frame.g_runtime!=NULL);
        if (!long_frame.g_runtime) abort();
        sle_g_runtime *r=long_frame.g_runtime;
        atomic_init(&r->worker.job,0); atomic_init(&r->worker.stop,0);
        r->rng_fd=-1; r->pair.state=secure ? SLE_PAIR_ENCRYPTED:SLE_PAIR_WAIT_PUBLIC_KEY;
        r->pair.secure=secure; r->pair.pending=1;
        r->pair.outgoing.len=73; r->pair.outgoing.encrypted=secure;
        r->pair.outgoing.data[0]=0x36; r->pair.outgoing.data[1]=1; r->pair.outgoing.data[2]=70;
        sle_access_plan_t plan={.req_sync_ns=0};
        CHECK(connection(&long_frame,&plan)==-1);
        CHECK(long_frame.events==1 && long_frame.received==1 && long_frame.valid_received==1);
        CHECK(!strcmp(long_frame.reason,"connection_budget_exhausted"));
        CHECK(!strstr(long_frame.log,"event_witness_missing"));
        CHECK(r->pair.cipher.tx_next==(uint64_t)secure);
        CHECK(!sle_g_runtime_destroy(r)); free(r); long_frame.g_runtime=NULL; free_app(&long_frame);
    }
    app a; reset_app(&a);
    uint8_t bits[1200],control[73]={0x36,1,70}; sle_rt_wave wave;
    sle_connect_config_t cfg={a.peer.txi.first_lid,64,SLE_CRC_TYPE_24,a.peer.txi.first_crc_init,0};
    size_t nb=sle_encode_connect_config(bits,sizeof bits,control,sizeof control,&cfg,
        SLE_PTYPE_CTRL,0,0,0,0,0,0);
    CHECK(nb && !sle_rt_modulate(&wave,bits,nb,0));
    int64_t sync=10000, end=sync-sle_rt_sync_in_wave()+(int64_t)wave.n;
    CHECK(end>sync+SAMPLES_US(500)); /* old cutoff preceded public-key frame end */
    CHECK(witness_deadline(sync,wave.n)==end+SLE_RT_WITNESS_MARGIN);
    CHECK(witness_deadline(sync,wave.n)>sync+SAMPLES_US(682));

    sle_link_t *l=calloc(1,sizeof *l); CHECK(l!=NULL); if (!l) abort();
    a.probe_queued=1; opt.ssap_mtu=520; opt.ssap_write="E310-P5-hello";
    static const uint8_t mtu[]={0x50,0,0x0a,0,6,0,3,3,8,2,1,0};
    ssap_on_deliver(&a,l,mtu,sizeof mtu);
    CHECK(a.ssap_validated && a.ssap_state==1 && l->q_len==1);
    CHECK(!connection_accepted(&a)); /* held link without WRITE_RSP is not success */
    uint8_t response[64]={0};
    size_t dl=strlen(opt.ssap_write)+5, len=dl+4;
    response[0]=(uint8_t)(len<<3); response[1]=(uint8_t)(len>>5);
    response[2]=0x0a; response[4]=(uint8_t)dl;
    response[6]=SLE_SSAP_WRITE_RSP; response[7]=SLE_SSAP_FRAG_NONE;
    response[8]=2; memcpy(response+11,opt.ssap_write,strlen(opt.ssap_write));
    a.prop_handle=2; a.ssap_state=2;
    ssap_on_deliver(&a,l,response,dl+6);
    CHECK(a.ssap_write_verified && a.ssap_state==3 && connection_accepted(&a));
    for (int fault=0;fault<3;fault++) {
        a.ssap_state=2; a.ssap_failed=a.ssap_write_verified=0;
        size_t offset=fault==0 ? 8:fault==1 ? 11:7;
        response[offset]^=1;
        ssap_on_deliver(&a,l,response,dl+6);
        CHECK(!a.ssap_write_verified && a.ssap_failed && !connection_accepted(&a));
        response[offset]^=1;
    }
    /* 1.10.108 status form 0e 0b 01 | handle | 07: recorded, not verified,
     * not fatal; a wrong handle or status 0 in that form stays a failure. */
    {
        static const uint8_t st7[]={0x50,0,0x0a,0,6,0,0x0e,0x0b,0x01,2,0,7};
        uint8_t v[sizeof st7];
        a.ssap_state=2; a.ssap_failed=a.ssap_write_verified=0;
        ssap_on_deliver(&a,l,st7,sizeof st7);
        CHECK(!a.ssap_write_verified && !a.ssap_failed && a.ssap_state==3 &&
              !connection_accepted(&a) && strstr(a.log,"\"status\":7"));
        for (int fault=0;fault<2;fault++) {
            memcpy(v,st7,sizeof v);
            if (fault) v[11]=0; else v[9]=3;
            a.ssap_state=2; a.ssap_failed=a.ssap_write_verified=0;
            ssap_on_deliver(&a,l,v,sizeof v);
            CHECK(!a.ssap_write_verified && a.ssap_failed);
        }
    }
    a.ssap_failed=0; a.ssap_state=2; a.ssap_write_verified=0;
    response[4]=0; /* invalid DTAP length cannot inspect an absent opcode */
    ssap_on_deliver(&a,l,response,6);
    CHECK(!a.ssap_write_verified && a.ssap_failed);
    a.ssap_failed=0;
    a.g_runtime=calloc(1,sizeof *a.g_runtime); CHECK(a.g_runtime!=NULL); if (!a.g_runtime) abort();
    a.g_runtime->pair.state=SLE_PAIR_WAIT_SECURITY_ACK; a.g_runtime->pair.secure=1;
    a.ssap_write_verified=1; a.g_runtime->protected_rx=a.g_runtime->protected_tx_acked=1;
    CHECK(!connection_accepted(&a)); /* locally sent 0007 is insufficient */
    a.g_runtime->pair.state=SLE_PAIR_ENCRYPTED;
    CHECK(connection_accepted(&a));
    a.g_runtime->protected_rx=0; CHECK(!connection_accepted(&a));
    opt.ssap_write=NULL; opt.ssap_mtu=0;
    CHECK(connection_accepted(&a)); /* explicit encrypted + hold scope */
    free(a.g_runtime); a.g_runtime=NULL; free(l); free_app(&a);
    opt=saved;
    char *args[]={"sle_gnode","--pair","--ssap-write","test",NULL};
    CHECK(!parse(4,args) && opt.pair && opt.ssap_mtu==520);
    opt=saved;
    char *standard_args[]={"sle_gnode","--resource-layout","standard",NULL};
    char *legacy_args[]={"sle_gnode","--resource-layout","legacy-ws63",NULL};
    char *bad_args[]={"sle_gnode","--resource-layout","auto",NULL};
    CHECK(!parse(3,standard_args) && opt.resource_layout==SLE_RESOURCE_STANDARD);
    CHECK(!parse(3,legacy_args) && opt.resource_layout==SLE_RESOURCE_LEGACY_WS63);
    CHECK(parse(3,bad_args)==-1);
    opt=saved;
    for (int explicit_zero=0;explicit_zero<2;explicit_zero++)
    for (prepare_fault=1;prepare_fault<=2;prepare_fault++) {
        interrupted=setup_calls=restore_calls=0; scenario=SIGNAL_TEST;
        char *cli[]={"sle_gnode","--pair","--attempts","1","--log","/dev/null","--pair-variant","0",NULL};
        CHECK(sle_rt_program_main(explicit_zero ? 8:6,cli)==(prepare_fault==1 ? 1:128+SIGTERM));
        CHECK(observed_pair_variant==(explicit_zero ? 0:SLE_PAIR_V_COUNT_PLAIN));
        CHECK(!setup_calls && restore_calls==1); /* every failure reaches RF restore */
        opt=saved;
    }
    prepare_fault=interrupted=0;
}
/* Feed chunks directly: these tests exercise framing without touching stdin. */
static void interactive_chat_regression(void)
{
    options saved=opt;
    app a; reset_app(&a);
    uint8_t out[48]; size_t n=0;
    const char *lines[]={"hello\n","hello\r\n"};
    for (size_t k=0;k<sizeof lines/sizeof lines[0];k++) {
        size_t len=strlen(lines[k]);
        for (size_t split=0;split<len;split++) {
            a.chat_len=split; memcpy(a.chat,lines[k],split);
            CHECK(chat_next(&a,out,&n)==0 && a.chat_len==split);
            memcpy(a.chat+a.chat_len,lines[k]+split,len-split); a.chat_len=len;
            CHECK(chat_next(&a,out,&n)==1 && n==7 && !memcmp(out,"hello\r\n",7));
            CHECK(!a.chat_len && !a.chat_dropping);
        }
    }
    /* Empty lines are valid; remove only the CR immediately before LF. */
    memcpy(a.chat,"\n\r\nkeep\r\r\nlast",14); a.chat_len=14;
    CHECK(chat_next(&a,out,&n)==1 && n==2 && !memcmp(out,"\r\n",2));
    CHECK(chat_next(&a,out,&n)==1 && n==2 && !memcmp(out,"\r\n",2));
    CHECK(chat_next(&a,out,&n)==1 && n==7 && !memcmp(out,"keep\r\r\n",7));
    CHECK(a.chat_len==4 && !memcmp(a.chat,"last",4));
    CHECK(chat_next(&a,out,&n)==0 && a.chat_len==4);
    a.chat[a.chat_len++]='\n';
    CHECK(chat_next(&a,out,&n)==1 && n==6 && !memcmp(out,"last\r\n",6));

    /* The limit is 46 content bytes, independent of the input terminator. */
    for (int crlf=0;crlf<2;crlf++) {
        memset(a.chat,'x',46); a.chat_len=46;
        if (crlf) a.chat[a.chat_len++]='\r';
        a.chat[a.chat_len++]='\n';
        CHECK(chat_next(&a,out,&n)==1 && n==48);
        for (size_t i=0;i<46;i++) CHECK(out[i]=='x');
        CHECK(out[46]=='\r' && out[47]=='\n' && !a.chat_len);
        memset(a.chat,'x',47); a.chat_len=47;
        if (crlf) a.chat[a.chat_len++]='\r';
        memcpy(a.chat+a.chat_len,"\nok\n",4); a.chat_len+=4;
        CHECK(chat_next(&a,out,&n)==-1);
        CHECK(a.chat_len==3 && !memcmp(a.chat,"ok\n",3));
        CHECK(chat_next(&a,out,&n)==1 && n==4 && !memcmp(out,"ok\r\n",4));
    }
    static const char nul_line[]={'b','a','d',0,'x','\n','o','k','\n'};
    memcpy(a.chat,nul_line,sizeof nul_line); a.chat_len=sizeof nul_line;
    CHECK(chat_next(&a,out,&n)==-1 && a.chat_len==3);
    CHECK(chat_next(&a,out,&n)==1 && n==4 && !memcmp(out,"ok\r\n",4));

    /* A line larger than the input buffer is discarded through its LF,
     * including when the discarded tail and next line arrive together. */
    memset(a.chat,'x',sizeof a.chat); a.chat_len=sizeof a.chat;
    CHECK(chat_next(&a,out,&n)==0 && a.chat_dropping && !a.chat_len);
    memcpy(a.chat,"tail",4); a.chat_len=4;
    CHECK(chat_next(&a,out,&n)==0 && a.chat_dropping);
    memcpy(a.chat+a.chat_len,"end\r\nok\n",8); a.chat_len+=8;
    CHECK(chat_next(&a,out,&n)==-1 && !a.chat_dropping);
    CHECK(a.chat_len==3 && !memcmp(a.chat,"ok\n",3));
    CHECK(chat_next(&a,out,&n)==1 && n==4 && !memcmp(out,"ok\r\n",4));
    CHECK(!a.chat_len && chat_next(&a,out,&n)==0);
    free_app(&a); opt=saved;
}
static void interactive_write_regression(void)
{
    options saved=opt;
    opt.interactive=opt.pair=1; opt.ssap_write=NULL; opt.ssap_mtu=520;
    app a; reset_app(&a); scenario=ACCESS_TEST;
    sle_link_t *l=calloc(1,sizeof *l); CHECK(l!=NULL); if (!l) abort();
    static const uint8_t mtu[]={0x0a,0,6,0,3,3,8,2,1,0};
    static const uint8_t property[]={0x0a,0,4,0,5,3,2,0};
    a.probe_queued=1;
    ssap_on_sdu(&a,l,mtu,sizeof mtu);
    CHECK(a.ssap_validated && a.ssap_state==1 && l->q_len==1);
    a.connecting=1;
    a.deadline=2300000000LL; fake_mono=a.deadline;
    CHECK(live(&a) && !a.chat_ready);
    fake_mono++;
    CHECK(!live(&a) && !strcmp(a.reason,"connection_budget_exhausted"));
    CHECK(!a.chat_ready && a.ssap_state==1); /* establishment has a finite budget */
    fake_mono=1700000000LL; a.reason="initialization_failed";
    int64_t ready_time=fake_mono;
    ssap_on_sdu(&a,l,property,sizeof property);
    CHECK(a.deadline==ready_time+86400LL*1000000000);
    fake_mono=2300000001LL;
    CHECK(live(&a)); /* now beyond the old establishment deadline */
    CHECK(a.prop_handle==2 && a.ssap_state==3 && a.chat_ready && !a.ssap_failed);
    CHECK(a.peer_mtu==520);
    CHECK(l->q_len==1 && !a.ssap_write_verified); /* wait for input, no automatic WRITE */
    free(l); free_app(&a);

    /* Each scenario starts with one successful request, then a different
     * current value. Late echoes must not validate the second request. */
    static const uint8_t first_rsp[]={0x0a,0,10,0,0x0e,3,2,0,0,'o','n','e','\r','\n'};
    static const uint8_t second[]="second\r\n";
    static const uint8_t second_rsp[]={0x0a,0,13,0,0x0e,3,2,0,0,'s','e','c','o','n','d','\r','\n'};
    static const uint8_t status7[]={0x0a,0,6,0,0x0e,0x0b,1,2,0,7};
    static const uint8_t error_rsp[]={0x0a,0,6,0,1,3,0x0d,2,0,2};
    for (int fault=0;fault<11;fault++) {
        reset_app(&a); scenario=ACCESS_TEST;
        l=calloc(1,sizeof *l); CHECK(l!=NULL); if (!l) abort();
        a.prop_handle=2; a.ssap_state=3;
        uint8_t first[]="one\r\n";
        fake_mono=250000000;
        CHECK(!queue_write(&a,l,first,sizeof first-1));
        CHECK(a.ssap_state==2 && !a.ssap_write_verified && !a.ssap_failed);
        CHECK(a.write_len==5 && !memcmp(a.write_value,"one\r\n",5));
        uint64_t first_deadline=a.write_deadline_ms;
        CHECK(first_deadline>=250 && l->q_len==1);
        first[0]='X'; /* the request context and queued PDU own their bytes */
        CHECK(!memcmp(a.write_value,"one\r\n",5));
        const sle_link_pdu_t *q=&l->q[l->q_head];
        CHECK(q->ptype==SLE_PTYPE_DATA && q->len==16 && q->data!=NULL);
        if (q->data && q->len==16) {
            CHECK(q->data[6]==SLE_SSAP_WRITE_REQ && q->data[7]==SLE_SSAP_FRAG_NONE);
            CHECK(q->data[8]==2 && !q->data[9] && !q->data[10]);
            CHECK(!memcmp(q->data+11,"one\r\n",5));
        }
        ssap_on_sdu(&a,l,first_rsp,sizeof first_rsp);
        CHECK(a.ssap_state==3 && a.ssap_write_verified && !a.ssap_failed);
        fake_mono=350000000;
        CHECK(!queue_write(&a,l,second,sizeof second-1));
        CHECK(a.ssap_state==2 && !a.ssap_write_verified && !a.ssap_failed);
        CHECK(a.write_len==sizeof second-1 && !memcmp(a.write_value,second,sizeof second-1));
        CHECK(a.write_deadline_ms>first_deadline && a.write_deadline_ms>=350);
        CHECK(l->q_len==2);
        q=&l->q[(l->q_head+1)%SLE_LINK_QUEUE_MAX];
        CHECK(q->len==sizeof second+10 && q->data!=NULL);
        if (q->data && q->len==sizeof second+10)
            CHECK(!memcmp(q->data+11,second,sizeof second-1));
        uint8_t rsp[sizeof second_rsp]; size_t rn=sizeof second_rsp;
        memcpy(rsp,second_rsp,rn);
        switch (fault) {
        case 1: rn=sizeof first_rsp; memcpy(rsp,first_rsp,rn); break; /* stale value/length */
        case 2: rsp[6]=3; break; /* handle */
        case 3: rsp[9]^=1; break; /* equal length, different value */
        case 4: rsp[8]=1; break; /* type */
        case 5: rsp[5]=0; break; /* incomplete fragment */
        case 6: rn=sizeof status7; memcpy(rsp,status7,rn); break;
        case 7: rn=sizeof status7; memcpy(rsp,status7,rn); rsp[9]=0; break;
        case 8: rn=sizeof error_rsp; memcpy(rsp,error_rsp,rn); break;
        case 9: rn--; rsp[2]--; break; /* matching prefix is insufficient */
        case 10: rn=sizeof status7; memcpy(rsp,status7,rn); rsp[7]=3; break;
        default: break;
        }
        ssap_on_sdu(&a,l,rsp,rn);
        if (!fault) CHECK(a.ssap_write_verified && a.ssap_state==3 && !a.ssap_failed);
        else if (fault==6) {
            CHECK(!a.ssap_write_verified && a.ssap_state==3 && !a.ssap_failed);
            CHECK(strstr(a.log,"\"status\":7")!=NULL);
            CHECK(!queue_write(&a,l,second,sizeof second-1));
            CHECK(a.ssap_state==2 && !a.ssap_write_verified && !a.ssap_failed);
            ssap_on_sdu(&a,l,second_rsp,sizeof second_rsp);
            CHECK(a.ssap_state==3 && a.ssap_write_verified && !a.ssap_failed);
        } else CHECK(!a.ssap_write_verified && a.ssap_failed);
        free(l); free_app(&a);
    }
    opt=saved;
}
static void interactive_pump_regression(void)
{
    options saved=opt;
    opt.interactive=opt.pair=1; opt.ssap_write=NULL; opt.ssap_mtu=520;
    app a; reset_app(&a); scenario=ACCESS_TEST;
    sle_link_t *l=calloc(1,sizeof *l); CHECK(l!=NULL); if (!l) abort();
    a.g_runtime=calloc(1,sizeof *a.g_runtime); CHECK(a.g_runtime!=NULL); if (!a.g_runtime) abort();
    a.g_runtime->pair.state=SLE_PAIR_ENCRYPTED; a.g_runtime->pair.secure=1;
    a.prop_handle=2; a.peer_mtu=520; a.ssap_state=3;
    int saved_stdin=dup(STDIN_FILENO), input[2];
    CHECK(saved_stdin>=0);
    if (saved_stdin<0) goto done;
    int rc=pipe(input); CHECK(!rc);
    if (rc) { CHECK(!close(saved_stdin)); goto done; }
    rc=dup2(input[0],STDIN_FILENO); CHECK(rc==STDIN_FILENO);
    CHECK(!close(input[0]));
    if (rc<0) { CHECK(!close(input[1])); CHECK(!close(saved_stdin)); goto done; }

    /* Input is buffered before readiness/encryption, but is not sent yet. */
    CHECK(write(input[1],"one\n",4)==4);
    CHECK(!chat_pump(&a,l) && !l->q_len && a.chat_len==4);
    CHECK(!memcmp(a.chat,"one\n",4));
    a.chat_ready=1; a.g_runtime->pair.state=SLE_PAIR_WAIT_SECURITY_ACK;
    CHECK(!chat_pump(&a,l) && !l->q_len && a.chat_len==4);
    CHECK(!memcmp(a.chat,"one\n",4));
    a.g_runtime->pair.state=SLE_PAIR_ENCRYPTED;
    CHECK(!chat_pump(&a,l) && a.ssap_state==2 && l->q_len==1);
    CHECK(a.write_len==5 && !memcmp(a.write_value,"one\r\n",5));
    CHECK(write(input[1],"two\n",4)==4);
    uint64_t first_deadline=a.write_deadline_ms;
    CHECK(!chat_pump(&a,l) && a.ssap_state==2 && l->q_len==1 && a.chat_len==4);
    CHECK(!memcmp(a.chat,"two\n",4)); /* pending WRITE does not consume the next line */
    CHECK(a.write_deadline_ms==first_deadline && !memcmp(a.write_value,"one\r\n",5));
    CHECK(queue_write(&a,l,(const uint8_t *)"blocked\r\n",9)!=0);
    CHECK(l->q_len==1 && a.write_len==5 && !memcmp(a.write_value,"one\r\n",5));
    CHECK(a.write_deadline_ms==first_deadline);
    static const uint8_t one_rsp[]={0x0a,0,10,0,0x0e,3,2,0,0,'o','n','e','\r','\n'};
    static const uint8_t two_rsp[]={0x0a,0,10,0,0x0e,3,2,0,0,'t','w','o','\r','\n'};
    ssap_on_sdu(&a,l,one_rsp,sizeof one_rsp);
    CHECK(a.ssap_state==3 && a.ssap_write_verified);
    CHECK(!chat_pump(&a,l) && a.ssap_state==2 && l->q_len==2 && !a.ssap_write_verified);
    CHECK(a.write_len==5 && !memcmp(a.write_value,"two\r\n",5));

    /* Exactly at the deadline is allowed; one millisecond later times out.
     * Neither path overwrites the in-flight request or queues another one. */
    fake_mono=(int64_t)a.write_deadline_ms*1000000;
    CHECK(!chat_pump(&a,l) && l->q_len==2 && a.ssap_state==2);
    fake_mono+=1000000;
    CHECK(chat_pump(&a,l)==-1 && !strcmp(a.reason,"ssap_write_timeout"));
    CHECK(l->q_len==2 && !a.ssap_write_verified && !memcmp(a.write_value,"two\r\n",5));
    CHECK(strstr(a.log,"interactive_write_timeout")!=NULL);
    ssap_on_sdu(&a,l,two_rsp,sizeof two_rsp); /* allow subsequent independent pump cases */
    a.reason="initialization_failed"; fake_mono=0;

    /* At MTU 23, 16 text bytes + CRLF + five SSAP bytes fit exactly.
     * A 17-byte line is refused while the following valid line is retained. */
    a.peer_mtu=23;
    static const char mtu_lines[]="12345678901234567\n1234567890123456\n";
    CHECK(write(input[1],mtu_lines,sizeof mtu_lines-1)==(ssize_t)(sizeof mtu_lines-1));
    CHECK(!chat_pump(&a,l) && a.ssap_state==3 && l->q_len==2);
    CHECK(a.chat_len==17 && !memcmp(a.chat,"1234567890123456\n",17));
    CHECK(strstr(a.log,"\"mtu\":23,\"value_len\":19")!=NULL);
    CHECK(!chat_pump(&a,l) && a.ssap_state==2 && l->q_len==3 && !a.chat_len);
    CHECK(a.write_len==18 && !memcmp(a.write_value,"1234567890123456\r\n",18));
    /* The protocol also permits a successful response without an echo. */
    static const uint8_t empty_rsp[]={0x0a,0,2,0,0x0e,3};
    ssap_on_sdu(&a,l,empty_rsp,sizeof empty_rsp);
    CHECK(a.ssap_state==3 && a.ssap_write_verified);
    CHECK(!chat_pump(&a,l) && l->q_len==3 && !a.chat_eof); /* empty open pipe */

    /* EOF closes only the producer. Complete lines retain their order and
     * pending request context; the final partial line stays unsent. */
    CHECK(write(input[1],"end\nnext\npartial",16)==16);
    CHECK(!close(input[1]));
    CHECK(!chat_pump(&a,l) && l->q_len==4 && a.ssap_state==2);
    CHECK(a.write_len==5 && !memcmp(a.write_value,"end\r\n",5));
    CHECK(a.chat_len==12 && !memcmp(a.chat,"next\npartial",12));
    uint64_t eof_deadline=a.write_deadline_ms;
    CHECK(!chat_pump(&a,l) && l->q_len==4 && a.chat_eof && a.ssap_state==2);
    CHECK(!a.ssap_write_verified && a.chat_len==12);
    CHECK(a.write_deadline_ms==eof_deadline && !memcmp(a.write_value,"end\r\n",5));
    CHECK(strstr(a.log,"\"connection_continues\":true")!=NULL);
    CHECK(!strstr(a.log,"stdin_eof") && !strstr(a.log,"discarded_partial_bytes"));
    ssap_on_sdu(&a,l,empty_rsp,sizeof empty_rsp);
    CHECK(!chat_pump(&a,l) && l->q_len==5 && a.ssap_state==2 && !a.ssap_write_verified);
    CHECK(a.write_len==6 && !memcmp(a.write_value,"next\r\n",6));
    CHECK(a.chat_len==7 && !memcmp(a.chat,"partial",7));
    /* Closing stdin must not disable the pending WRITE timeout. */
    fake_mono=(int64_t)a.write_deadline_ms*1000000;
    CHECK(!chat_pump(&a,l) && a.ssap_state==2 && l->q_len==5);
    fake_mono+=1000000;
    CHECK(chat_pump(&a,l)==-1 && !strcmp(a.reason,"ssap_write_timeout"));
    CHECK(a.chat_len==7 && !memcmp(a.chat,"partial",7) && !a.ssap_write_verified);
    fake_mono=0; a.reason="initialization_failed";
    ssap_on_sdu(&a,l,empty_rsp,sizeof empty_rsp);
    CHECK(a.ssap_state==3 && a.ssap_write_verified);
    size_t journal_after_response=a.used;
    for (int i=0;i<3;i++) {
        CHECK(!chat_pump(&a,l) && a.chat_eof && l->q_len==5);
        CHECK(a.chat_len==7 && !memcmp(a.chat,"partial",7));
        CHECK(a.used==journal_after_response); /* EOF is logged once, not spun */
    }
    signal_stop(SIGINT);
    CHECK(!live(&a) && !strcmp(a.reason,"signal"));
    CHECK(a.chat_len==7 && !memcmp(a.chat,"partial",7));
    interrupted=0;

    /* Before ready, empty/partial EOF also keeps the connection. A complete
     * line waits for readiness; EOF never fabricates an SSAP milestone. */
    const char *early_input[]={"","tail","one\n"};
    for (size_t i=0;i<sizeof early_input/sizeof early_input[0];i++) {
        free(a.g_runtime); free(l); free_app(&a);
        reset_app(&a); scenario=ACCESS_TEST;
        l=calloc(1,sizeof *l); CHECK(l!=NULL); if (!l) abort();
        rc=pipe(input); CHECK(!rc);
        if (rc) break;
        size_t len=strlen(early_input[i]);
        if (len) CHECK(write(input[1],early_input[i],len)==(ssize_t)len);
        CHECK(!close(input[1]));
        rc=dup2(input[0],STDIN_FILENO); CHECK(rc==STDIN_FILENO);
        CHECK(!close(input[0]));
        if (rc<0) break;
        CHECK(!chat_pump(&a,l));
        if (len) CHECK(!chat_pump(&a,l)); /* read zero after buffered pipe data */
        CHECK(a.chat_eof && !a.chat_ready && !l->q_len);
        CHECK(a.chat_len==len && !memcmp(a.chat,early_input[i],len));
        CHECK(!a.ssap_state && !a.ssap_validated && !a.ssap_write_verified);
        CHECK(!a.ssap_failed && !a.write_len && !a.write_deadline_ms);
        CHECK(live(&a) && !strcmp(a.reason,"initialization_failed"));
        size_t before=a.used;
        CHECK(!chat_pump(&a,l) && a.used==before && a.chat_len==len && !l->q_len);
        signal_stop(SIGINT);
        CHECK(!live(&a) && !strcmp(a.reason,"signal"));
        CHECK(!a.ssap_write_verified && !l->q_len);
        interrupted=0;
    }
    CHECK(dup2(saved_stdin,STDIN_FILENO)==STDIN_FILENO);
    CHECK(!close(saved_stdin));
done:
    free(a.g_runtime); free(l); free_app(&a); opt=saved;
}
static void interactive_retry_regression(void)
{
    options saved=opt;
    opt.interactive=opt.pair=1; opt.ssap_write=NULL; opt.ssap_mtu=520;
    app a; reset_app(&a); scenario=ACCESS_TEST;
    sle_link_t *l=calloc(1,sizeof *l); CHECK(l!=NULL); if (!l) abort();
    a.g_runtime=calloc(1,sizeof *a.g_runtime); CHECK(a.g_runtime!=NULL); if (!a.g_runtime) abort();
    a.g_runtime->rng_fd=-1;
    a.g_runtime->pair.state=SLE_PAIR_ENCRYPTED; a.g_runtime->pair.secure=1;
    a.chat_ready=1; a.ssap_state=3; a.prop_handle=2; a.peer_mtu=520;
    int input[2], saved_stdin=dup(STDIN_FILENO);
    CHECK(saved_stdin>=0); if (saved_stdin<0) abort();
    int rc=pipe(input); CHECK(!rc); if (rc) abort();
    CHECK(dup2(input[0],STDIN_FILENO)==STDIN_FILENO); CHECK(!close(input[0]));
    static const char lines[]="unknown\nqueued\npar";
    CHECK(write(input[1],lines,sizeof lines-1)==(ssize_t)(sizeof lines-1));
    CHECK(!chat_pump(&a,l) && a.ssap_state==2 && l->q_len==1);
    CHECK(a.write_len==9 && !memcmp(a.write_value,"unknown\r\n",9));
    CHECK(a.chat_len==10 && !memcmp(a.chat,"queued\npar",10));

    /* Re-enter the real connection initializer without running RF scheduling.
     * Unacknowledged 'unknown' must never be reinserted into the input queue. */
    sle_access_plan_t plan={.req_sync_ns=0};
    signal_stop(SIGTERM); CHECK(connection(&a,&plan)==-1); interrupted=0;
    CHECK(!a.chat_ready && !a.ssap_state && !a.write_len && !a.write_deadline_ms);
    CHECK(!a.ssap_write_verified && !a.chat_eof && !a.chat_dropping);
    for (size_t i=0;i<sizeof a.write_value;i++) CHECK(!a.write_value[i]);
    CHECK(a.chat_len==10 && !memcmp(a.chat,"queued\npar",10));
    memset(l,0,sizeof *l); /* a new connection has its own empty transmit queue */
    CHECK(!chat_pump(&a,l) && !l->q_len && a.chat_len==10);
    a.chat_ready=1; a.ssap_state=3; a.prop_handle=2; a.peer_mtu=520;
    CHECK(!chat_pump(&a,l) && l->q_len==1 && a.ssap_state==2);
    CHECK(a.write_len==8 && !memcmp(a.write_value,"queued\r\n",8));
    CHECK(a.chat_len==3 && !memcmp(a.chat,"par",3));
    CHECK(write(input[1],"tial\ntail",9)==9); CHECK(!close(input[1]));
    CHECK(!chat_pump(&a,l) && l->q_len==1 && a.chat_len==12);
    CHECK(!chat_pump(&a,l) && a.chat_eof && a.ssap_state==2);
    static const uint8_t empty_rsp[]={0x0a,0,2,0,0x0e,3};
    ssap_on_sdu(&a,l,empty_rsp,sizeof empty_rsp);
    CHECK(!chat_pump(&a,l) && l->q_len==2 && a.ssap_state==2);
    CHECK(a.write_len==9 && !memcmp(a.write_value,"partial\r\n",9));
    CHECK(a.chat_len==4 && !memcmp(a.chat,"tail",4));

    /* Another retry preserves EOF and its unterminated tail, and does not
     * replay the now-unknown 'partial' WRITE or fabricate success. */
    signal_stop(SIGTERM); CHECK(connection(&a,&plan)==-1); interrupted=0;
    CHECK(a.chat_eof && !a.chat_ready && !a.write_len && !a.write_deadline_ms);
    CHECK(a.chat_len==4 && !memcmp(a.chat,"tail",4));
    memset(l,0,sizeof *l);
    a.chat_ready=1; a.ssap_state=3; a.prop_handle=2; a.peer_mtu=520;
    CHECK(!chat_pump(&a,l) && !l->q_len && !a.ssap_write_verified && a.chat_len==4);

    /* A discarded oversized prefix must remain rejected after reconnect:
     * do not turn its buffered suffix into a valid short WRITE. */
    memcpy(a.chat,"suffix\nnext\n",12); a.chat_len=12; a.chat_dropping=1;
    signal_stop(SIGTERM); CHECK(connection(&a,&plan)==-1); interrupted=0;
    CHECK(a.chat_eof && a.chat_dropping && a.chat_len==12 && !a.chat_ready);
    a.chat_ready=1; a.ssap_state=3; a.prop_handle=2; a.peer_mtu=520;
    CHECK(!chat_pump(&a,l) && !l->q_len && !a.chat_dropping);
    CHECK(a.chat_len==5 && !memcmp(a.chat,"next\n",5));
    CHECK(!chat_pump(&a,l) && l->q_len==1 && a.write_len==6);
    CHECK(!memcmp(a.write_value,"next\r\n",6) && !a.chat_len && a.chat_eof);
    CHECK(dup2(saved_stdin,STDIN_FILENO)==STDIN_FILENO); CHECK(!close(saved_stdin));
    free(a.g_runtime); free(l); free_app(&a); opt=saved;
}
static void interactive_started_signal_regression(void)
{
    options saved=opt;
    /* The radio-start wrapper succeeds, marks the radio started, then injects
     * SIGINT. This covers actual main cleanup, not encryption/readiness or DMA. */
    opt.interactive=0; opt.mode=0; opt.hw_status=0; opt.event_log=NULL;
    scenario=SIGNAL_TEST; prepare_fault=3; post_start_signal=SIGINT;
    interrupted=setup_calls=start_calls=stop_calls=restore_calls=destroy_calls=cleanup_step=0;
    settling=cleanup_error=compute_delay_samples=0;
    int in_flags=fcntl(STDIN_FILENO,F_GETFL), out_flags=fcntl(STDOUT_FILENO,F_GETFL);
    CHECK(in_flags>=0 && out_flags>=0);
    char path[]="/tmp/sle-gnode-started-signal-XXXXXX";
    int fd=mkstemp(path); CHECK(fd>=0); if (fd<0) abort(); CHECK(!close(fd));
    char *args[]={"sle_gnode","--interactive","1","--attempts","3","--log",path,NULL};
    CHECK(sle_rt_program_main(7,args)==1);
    CHECK(interrupted==SIGINT && setup_calls==1 && start_calls==1 && stop_calls==1);
    CHECK(destroy_calls==1 && restore_calls==1 && cleanup_step==3);
    CHECK(fcntl(STDIN_FILENO,F_GETFL)==in_flags && fcntl(STDOUT_FILENO,F_GETFL)==out_flags);
    FILE *f=fopen(path,"r"); CHECK(f!=NULL); if (!f) abort();
    char log[32768]={0}; size_t n=fread(log,1,sizeof log-1,f);
    CHECK(n>0 && n<sizeof log-1 && !ferror(f));
    CHECK(strstr(log,"\"kind\":\"radio_started\""));
    CHECK(strstr(log,"\"kind\":\"attempt_stopping\"") && strstr(log,"\"result\":\"signal\""));
    CHECK(strstr(log,"\"milestone_observed\":false") && !strstr(log,"\"milestone_observed\":true"));
    CHECK(strstr(log,"\"kind\":\"cleanup\",\"attributes_restored\":true"));
    CHECK(!strstr(log,"\"attempt\":2") && !strstr(log,"\"kind\":\"interactive_ready\""));
    char sig[32]; snprintf(sig,sizeof sig,"\"signal\":%d",SIGINT); CHECK(strstr(log,sig));
    CHECK(!fclose(f) && !unlink(path));
    post_start_signal=prepare_fault=interrupted=0; opt=saved;
}
static void interactive_signal_regression(void)
{
    options saved=opt;
    const int signals[]={SIGINT,SIGTERM,SIGHUP,SIGPIPE};
    for (size_t i=0;i<sizeof signals/sizeof signals[0];i++) {
        opt=saved; prepare_fault=2; prepare_signal=signals[i];
        interrupted=setup_calls=start_calls=restore_calls=0;
        int in_flags=fcntl(STDIN_FILENO,F_GETFL), out_flags=fcntl(STDOUT_FILENO,F_GETFL);
        CHECK(in_flags>=0 && out_flags>=0);
        char path[]="/tmp/sle-gnode-interactive-signal-XXXXXX";
        int fd=mkstemp(path); CHECK(fd>=0); if (fd<0) abort();
        CHECK(!close(fd));
        char *args[]={"sle_gnode","--interactive","1","--attempts","1","--log",path,NULL};
        CHECK(sle_rt_program_main(7,args)==1);
        CHECK(interrupted==signals[i] && restore_calls==1 && !setup_calls && !start_calls);
        CHECK(fcntl(STDIN_FILENO,F_GETFL)==in_flags && fcntl(STDOUT_FILENO,F_GETFL)==out_flags);
        FILE *f=fopen(path,"r"); CHECK(f!=NULL); if (!f) abort();
        char log[16384]={0}; size_t n=fread(log,1,sizeof log-1,f);
        CHECK(n>0 && n<sizeof log-1 && !ferror(f));
        CHECK(strstr(log,"\"result\":\"signal\"") && strstr(log,"\"milestone_observed\":false"));
        CHECK(strstr(log,"\"kind\":\"cleanup\",\"attributes_restored\":true"));
        char sig[32]; snprintf(sig,sizeof sig,"\"signal\":%d",signals[i]); CHECK(strstr(log,sig));
        CHECK(!fclose(f) && !unlink(path));
    }
    prepare_fault=prepare_signal=interrupted=0; opt=saved;
}
static void interactive_cli_regression(void)
{
    /* Called before other application regressions so saved is the real CLI
     * default; every parse starts from it, including after rejected input. */
    options saved=opt;
    CHECK(!saved.interactive && saved.pair && !saved.ssap_mtu && !saved.ssap_write && !saved.mode);
    CHECK(saved.resource_layout==SLE_RESOURCE_STANDARD && !saved.pair_variants);
    struct {
        int argc, rc, interactive, pair, mtu;
        char *argv[8];
    } cases[]={
        {1,0,0,1,0,{"sle_gnode",NULL}},
        {3,0,0,1,0,{"sle_gnode","--interactive","0",NULL}},
        {3,0,1,1,520,{"sle_gnode","--interactive","1",NULL}},
        {4,0,1,1,520,{"sle_gnode","--pair","--interactive","1",NULL}},
        {5,0,1,1,23,{"sle_gnode","--interactive","1","--ssap-mtu","23",NULL}},
        {5,0,1,1,23,{"sle_gnode","--ssap-mtu","23","--interactive","1",NULL}},
        {5,0,1,1,520,{"sle_gnode","--interactive","1","--mode","connect",NULL}},
        {5,0,0,1,520,{"sle_gnode","--interactive","0","--ssap-write","test",NULL}},
        {5,0,0,0,0,{"sle_gnode","--interactive","0","--mode","access",NULL}},
        {5,-1,0,0,0,{"sle_gnode","--interactive","1","--ssap-write","test",NULL}},
        {5,-1,0,0,0,{"sle_gnode","--ssap-write","test","--interactive","1",NULL}},
        {5,-1,0,0,0,{"sle_gnode","--interactive","1","--mode","access",NULL}},
        {5,-1,0,0,0,{"sle_gnode","--mode","access","--interactive","1",NULL}},
        {5,-1,0,0,0,{"sle_gnode","--interactive","1","--mode","calibrate",NULL}},
        {5,-1,0,0,0,{"sle_gnode","--mode","calibrate","--interactive","1",NULL}},
        {2,-1,0,0,0,{"sle_gnode","--interactive",NULL}},
        {3,-1,0,0,0,{"sle_gnode","--interactive","2",NULL}},
        {3,-1,0,0,0,{"sle_gnode","--interactive","-1",NULL}},
        {3,-1,0,0,0,{"sle_gnode","--interactive","0.5",NULL}},
        {3,-1,0,0,0,{"sle_gnode","--interactive","yes",NULL}},
        {3,-1,0,0,0,{"sle_gnode","--interactive","",NULL}},
    };
    for (size_t i=0;i<sizeof cases/sizeof cases[0];i++) {
        opt=saved;
        int rc=parse(cases[i].argc,cases[i].argv);
        CHECK(rc==cases[i].rc);
        if (!rc) {
            CHECK(opt.interactive==cases[i].interactive && opt.pair==cases[i].pair);
            CHECK(opt.ssap_mtu==cases[i].mtu);
        }
    }
    opt=saved;
}
static void sdu_application_regression(void)
{
    options saved=opt;
    app a; reset_app(&a);
    sle_link_t *l=calloc(1,sizeof *l); CHECK(l!=NULL); if (!l) abort();
    /* Authenticated WS63 captures, original official 18-byte failure run,
     * k72/74 write echo and k75/77 first UART notification. */
    static const uint8_t first[]={0xc2,0,0x0a,0,0x17,0,0x0e,3,2,0,0,
        'E','3','1','0','-','P','6','-','O','F','F','I','C','I','A'};
    static const uint8_t last[]={0x1e,0,'L','-','A'};
    static const uint8_t nf[]={0xc2,0,0x0a,0,0x18,0,0x0f,3,2,0,0x12,0,
        'P','6','-','O','F','F','I','C','I','A','L','-','A','-'};
    static const uint8_t nl[]={0x26,0,'0','0','\r','\n'};
    opt.ssap_write="E310-P6-OFFICIAL-A"; a.prop_handle=2; a.ssap_state=2;
    ssap_on_deliver(&a,l,first,sizeof first);
    CHECK(a.sdu_rx.pending && a.sdu_rx.len==24 && !a.ssap_write_verified);
    CHECK(!strstr(a.log,"sdu_deliver") && !a.ssap_failed && !connection_accepted(&a));
    ssap_on_deliver(&a,l,last,sizeof last);
    CHECK(a.ssap_write_verified && a.ssap_state==3 && !a.sdu_rx.pending && connection_accepted(&a));
    CHECK(strstr(a.log,"\"fragments\":2") && !strstr(a.log,"ssap_rx_unparsed"));
    ssap_on_deliver(&a,l,nf,sizeof nf);
    CHECK(!strstr(a.log,"ssap_notify") && !connection_accepted(&a));
    ssap_on_deliver(&a,l,nl,sizeof nl);
    CHECK(strstr(a.log,"\"value_hex\":\"50362d4f4646494349414c2d412d30300d0a\""));
    CHECK(connection_accepted(&a));
    /* A tail alone cannot reuse the previous complete message. */
    ssap_on_deliver(&a,l,nl,sizeof nl);
    CHECK(a.ssap_failed && !connection_accepted(&a));
    free(l); free_app(&a);

    reset_app(&a); l=calloc(1,sizeof *l); if (!l) abort();
    /* A missing middle fragment can form a syntactically complete SDU, but
     * DTAP's exact length must prevent delivery to the SSAP consumer. */
    uint8_t short_first[sizeof nf]; memcpy(short_first,nf,sizeof nf);
    short_first[4]++; /* claimed DTAP total one byte longer */
    ssap_on_deliver(&a,l,short_first,sizeof short_first);
    ssap_on_deliver(&a,l,nl,sizeof nl);
    CHECK(!strstr(a.log,"ssap_notify") && strstr(a.log,"ssap_rx_unparsed"));
    free(l); free_app(&a);

    reset_app(&a); l=calloc(1,sizeof *l); if (!l) abort();
    /* Long notification includes bytes after the old 48-character preview.
     * Use FIRST/MIDDLE/LAST, including zero/nonprintable bytes in the value. */
    uint8_t dtap[90]={0x0a,0,86,0,0x0f,3,2,0,80,0}, packet[40];
    for (size_t i=0;i<80;i++) dtap[10+i]=(uint8_t)i;
    for (size_t off=0;off<sizeof dtap;off+=30) {
        unsigned seg=off==0 ? 1:off==60 ? 3:2;
        packet[0]=(uint8_t)((30u<<3)|(seg<<1)); packet[1]=0;
        memcpy(packet+2,dtap+off,30);
        ssap_on_deliver(&a,l,packet,32);
        if (off<60) CHECK(!strstr(a.log,"ssap_notify"));
    }
    char value[161]; hex(value,sizeof value,dtap+10,80);
    CHECK(strstr(a.log,value) && strstr(a.log,"\"value_len\":80"));
    CHECK(strstr(a.log,"\"fragments\":3") && !a.ssap_failed && !a.sdu_rx.pending);
    free(l); free_app(&a);

    /* Actual connection entry drops a previous attempt's partial SDU and
     * exit disables/wipes the receiver even when the attempt fails. */
    reset_app(&a); l=calloc(1,sizeof *l); if (!l) abort();
    ssap_on_deliver(&a,l,first,sizeof first); CHECK(a.sdu_rx.pending);
    opt.ssap_write=NULL; opt.ssap_mtu=0; scenario=ONE_REPLY; opt.connect_seconds=1;
    sle_access_plan_t plan={.req_sync_ns=0};
    CHECK(connection(&a,&plan)==-1);
    CHECK(!a.sdu_rx.pending && !a.sdu_rx.len && !a.sdu_rx.limit);
    CHECK(strstr(a.log,"\"kind\":\"sdu_rx_end\",\"pending\":false"));
    free(l); free_app(&a); opt=saved;
}
/* An unbuffered failing FILE makes any accidental event-file write visible,
 * without accessing a device or creating a filesystem artifact. */
static ssize_t event_cookie_write(void *cookie,const char *data,size_t n)
{
    unsigned *calls=cookie;
    (void)data; (void)n; (*calls)++; errno=EIO; return -1;
}
static void interactive_event_buffer_regression(void)
{
    options saved=opt;
    app a; reset_app(&a); scenario=ACCESS_TEST; event_fault=0;
    unsigned file_writes=0;
    cookie_io_functions_t io={.write=event_cookie_write};
    a.event_output=fopencookie(&file_writes,"w",io);
    CHECK(a.event_output!=NULL); if (!a.event_output) abort();
    CHECK(!setvbuf(a.event_output,NULL,_IONBF,0));
    static const char row[]="{\"kind\":\"cleanup\"}\n";
    const size_t rn=sizeof row-1;
    /* Extra storage is a guard, not capacity: even a corrupt event_used
     * regression must report a failed check rather than corrupt the heap. */
    size_t allocation=EVENT_CAP+sizeof row+1;
    a.event_buffer=malloc(allocation); CHECK(a.event_buffer!=NULL);
    if (!a.event_buffer) abort();
    memset(a.event_buffer,0x5a,allocation);
    record(&a,"attempt_start",",\"mode\":0");
    CHECK(!a.event_failed && a.event_used==a.used && a.event_used>0);
    CHECK(!memcmp(a.event_buffer,a.log,a.event_used));
    CHECK(!file_writes && !ferror(a.event_output));
    size_t used=a.event_used;
    record(&a,"ssap_write_rsp",",\"ok\":false,\"status\":7");
    CHECK(a.event_used>used && a.event_used==a.used);
    CHECK(!memcmp(a.event_buffer,a.log,a.event_used));
    CHECK(!file_writes && !ferror(a.event_output));

    /* Exactly fitting succeeds; the next row fails and latches the error. */
    a.event_used=EVENT_CAP-rn;
    event_write(&a,row,rn);
    CHECK(!a.event_failed && a.event_used==EVENT_CAP);
    CHECK(!memcmp(a.event_buffer+EVENT_CAP-rn,row,rn));
    event_write(&a,row,rn);
    CHECK(a.event_failed && a.event_used==EVENT_CAP);
    CHECK(!live(&a) && !strcmp(a.reason,"event_journal_write"));
    CHECK(journal_failed(&a));
    a.event_used=0; /* available space must not clear the failed latch */
    char first=a.event_buffer[0];
    event_write(&a,row,rn);
    CHECK(a.event_failed && !a.event_used && a.event_buffer[0]==first);

    /* Reject a row exceeding remaining room, and an already invalid offset.
     * Neither case may copy any bytes, including into the guard allocation. */
    const size_t offsets[]={EVENT_CAP-rn+1,EVENT_CAP+1};
    for (size_t k=0;k<sizeof offsets/sizeof offsets[0];k++) {
        memset(a.event_buffer,0x5a,allocation);
        a.event_used=offsets[k]; a.event_failed=0;
        event_write(&a,row,rn);
        CHECK(a.event_failed && a.event_used==offsets[k]);
        int unchanged=1;
        for (size_t i=0;i<allocation;i++) if ((unsigned char)a.event_buffer[i]!=0x5a) { unchanged=0; break; }
        CHECK(unchanged);
        CHECK(!live(&a) && !strcmp(a.reason,"event_journal_write"));
    }
    CHECK(!file_writes && !ferror(a.event_output));
    CHECK(!fclose(a.event_output)); a.event_output=NULL;
    CHECK(!file_writes);
    free(a.event_buffer); a.event_buffer=NULL;
    free_app(&a); opt=saved;
}
static void interactive_display_regression(void)
{
    options saved=opt;
    opt.interactive=opt.pair=1; opt.ssap_write=NULL; opt.ssap_mtu=520;
    app a; reset_app(&a); scenario=ACCESS_TEST;
    sle_link_t *l=calloc(1,sizeof *l); CHECK(l!=NULL); if (!l) abort();
    int output[2], saved_stdout=dup(STDOUT_FILENO);
    CHECK(saved_stdout>=0); if (saved_stdout<0) abort();
    int rc=pipe2(output,O_NONBLOCK); CHECK(!rc); if (rc) abort();
    CHECK(!fflush(stdout));
    rc=dup2(output[1],STDOUT_FILENO); CHECK(rc==STDOUT_FILENO); if (rc<0) abort();
    CHECK(!close(output[1])); a.console_active=1;
    /* Synthetic protocol inputs only: no captured keys or standard vectors. */
    static const uint8_t mtu[]={0x0a,0,6,0,3,3,8,2,1,0};
    static const uint8_t property[]={0x0a,0,4,0,5,3,2,0};
    static const uint8_t notify[]={0x0a,0,19,0,0x0f,3,2,0,13,0,
        'A',0x1b,'[','3','1','m','\\','"',0,0x7f,0x80,'\r','\n'};
    static const uint8_t empty_rsp[]={0x0a,0,2,0,0x0e,3};
    a.probe_queued=1;
    ssap_on_sdu(&a,l,mtu,sizeof mtu); ssap_on_sdu(&a,l,property,sizeof property);
    CHECK(!queue_write(&a,l,(const uint8_t *)"go\r\n",4));
    ssap_on_sdu(&a,l,notify,sizeof notify);
    CHECK(a.ssap_state==2 && !a.ssap_write_verified); /* notify is not a WRITE_RSP */
    ssap_on_sdu(&a,l,empty_rsp,sizeof empty_rsp);
    char text[2048]={0}; ssize_t n=read(output[0],text,sizeof text-1);
    CHECK(n>0 && (size_t)n<sizeof text-1 && !a.console_dropped);
    CHECK(strstr(text,"[E310] 已连接并加密（MTU 520）。输入一行按回车发给 WS63；WS63 键入的字符会显示在下面。Ctrl+C 退出。\n"));
    CHECK(strstr(text,"[E310 -> WS63 写入已排队 4 B]\n"));
    CHECK(strstr(text,"[WS63 -> E310] A\\x1b[31m\\x5c\"\\x00\\x7f\\x80\\x0d\\x0a\n"));
    CHECK(strstr(text,"[WS63 写入响应] 成功\n") && !strchr(text,0x1b));
    CHECK(strstr(a.log,"\"value_hex\":\"411b5b33316d5c22007f800d0a\""));
    CHECK(a.ssap_state==3 && a.ssap_write_verified);
    CHECK(dup2(saved_stdout,STDOUT_FILENO)==STDOUT_FILENO);
    CHECK(!close(saved_stdout)); CHECK(!close(output[0]));
    free(l); free_app(&a); opt=saved;
}
static void interactive_console_regression(void)
{
    options saved=opt;
    app a; reset_app(&a);
    int saved_stdout=dup(STDOUT_FILENO), output[2];
    CHECK(saved_stdout>=0);
    if (saved_stdout<0) goto done;
    int rc=pipe2(output,O_NONBLOCK); CHECK(!rc);
    if (rc) { CHECK(!close(saved_stdout)); goto done; }
    char padding[4096]; memset(padding,'x',sizeof padding);
    ssize_t sent;
    do { sent=write(output[1],padding,sizeof padding); } while (sent>0);
    CHECK(sent==-1 && (errno==EAGAIN || errno==EWOULDBLOCK));
    /* Fill any sub-block remainder as well, making even a one-byte write fail. */
    do { sent=write(output[1],padding,1); } while (sent>0);
    CHECK(sent==-1 && (errno==EAGAIN || errno==EWOULDBLOCK));
    CHECK(!fflush(stdout));
    rc=dup2(output[1],STDOUT_FILENO); CHECK(rc==STDOUT_FILENO);
    CHECK(!close(output[1]));
    if (rc<0) { CHECK(!close(output[0])); CHECK(!close(saved_stdout)); goto done; }
    CHECK(fcntl(STDOUT_FILENO,F_GETFL)&O_NONBLOCK);
    a.console_active=1;
    static const char message[]="offline console backpressure\n";
    struct timespec before,after;
    int before_ok=clock_gettime(CLOCK_MONOTONIC,&before); CHECK(!before_ok);
    console_write(&a,message,sizeof message-1);
    int after_ok=clock_gettime(CLOCK_MONOTONIC,&after); CHECK(!after_ok);
    CHECK(a.console_dropped==sizeof message-1);
    if (!before_ok && !after_ok) {
        int64_t elapsed=(int64_t)(after.tv_sec-before.tv_sec)*1000000000+after.tv_nsec-before.tv_nsec;
        CHECK(elapsed>=0 && elapsed<1000000000); /* prompt return, no terminal wait */
    }
    console_write(&a,"again",5);
    CHECK(a.console_dropped==sizeof message-1+5);
    a.console_active=0;
    console_write(&a,"inactive",8);
    CHECK(a.console_dropped==sizeof message-1+5);
    /* Like T, a closed consumer stops the session; still count display loss. */
    CHECK(!close(output[0]));
    CHECK(!install_signals()); a.console_active=1;
    console_write(&a,"closed",6);
    CHECK(interrupted==SIGPIPE && a.console_dropped==sizeof message-1+11);
    CHECK(!live(&a) && !strcmp(a.reason,"signal")); interrupted=0;
    CHECK(dup2(saved_stdout,STDOUT_FILENO)==STDOUT_FILENO);
    CHECK(!close(saved_stdout));
done:
    free_app(&a); opt=saved;
}
static void event_journal_regression(void)
{
    options saved=opt;
    app a; reset_app(&a); a.attempt=1;
    a.event_output=tmpfile(); CHECK(a.event_output!=NULL); if (!a.event_output) abort();
    CHECK(!setvbuf(a.event_output,NULL,_IONBF,0));
    record(&a,"attempt_start",",\"mode\":0");
    size_t first=a.used;
    record(&a,"frame",",\"seq\":1"); /* PHY records must stay in the main journal. */
    size_t response_at=a.used;
    record(&a,"ssap_write_rsp",",\"ok\":true,\"status\":-1,\"protected\":true");
    size_t response_end=a.used;
    record(&a,"attempt_stopping",",\"result\":\"complete\"");
    record(&a,"attempt_end",",\"milestone_observed\":true");
    CHECK(!a.event_failed && live(&a));
    long count=ftell(a.event_output); CHECK(count>0 && (size_t)count<a.used);
    char text[2048]={0}; rewind(a.event_output);
    CHECK(fread(text,1,sizeof text-1,a.event_output)==(size_t)count);
    CHECK(!memcmp(text,a.log,first));
    CHECK(!memcmp(text+first,a.log+response_at,response_end-response_at));
    CHECK(!strstr(text,"\"kind\":\"frame\"") && strstr(text,"\"kind\":\"attempt_end\""));
    CHECK(strstr(text,"\"status\":-1") && strstr(a.log,"\"kind\":\"frame\""));
    CHECK(strstr(text,"\"kind\":\"attempt_stopping\"") < strstr(text,"\"kind\":\"attempt_end\""));
    fclose(a.event_output);

    /* Capacity is latched by a real oversized ordinary record. The reserved
     * tail must still publish stopping/end with the same main-journal bytes. */
    a.event_output=tmpfile(); CHECK(a.event_output!=NULL); if (!a.event_output) abort();
    CHECK(!setvbuf(a.event_output,NULL,_IONBF,0));
    a.used=LOG_CAP-LOG_TAIL; a.log_full=0;
    record(&a,"frame",",\"seq\":2");
    CHECK(a.log_full && a.used==LOG_CAP-LOG_TAIL);
    size_t tail_at=a.used;
    record(&a,"attempt_stopping",",\"result\":\"journal_capacity\"");
    record(&a,"attempt_end",",\"milestone_observed\":false");
    CHECK(a.used>tail_at && a.used<=LOG_CAP && !a.event_failed);
    count=ftell(a.event_output); CHECK(count>0 && (size_t)count==a.used-tail_at);
    memset(text,0,sizeof text); rewind(a.event_output);
    CHECK(fread(text,1,sizeof text-1,a.event_output)==(size_t)count);
    CHECK(!memcmp(text,a.log+tail_at,(size_t)count));
    CHECK(strstr(text,"\"kind\":\"attempt_stopping\"") && strstr(text,"\"kind\":\"attempt_end\""));
    CHECK(journal_failed(&a) && !strcmp(a.reason,"journal_capacity") && !live(&a));
    CHECK(!strcmp(a.reason,"journal_capacity"));
    /* Even a precomputed successful milestone must fail the common gate. */
    int ok=1; if (journal_failed(&a)) ok=0; CHECK(!ok);
    fclose(a.event_output); a.log_full=0; a.used=0;
    a.event_output=fopen("/dev/full","w"); CHECK(a.event_output!=NULL); if (!a.event_output) abort();
    record(&a,"ssap_write_rsp",",\"ok\":true");
    CHECK(a.event_failed && !live(&a) && !strcmp(a.reason,"event_journal_write"));
    fclose(a.event_output); a.event_output=NULL; free_app(&a);

    /* Real main-path cleanup publishes the boundary even on a signal; an
     * existing event file is rejected before touching the mocked radio. */
    char directory[]="build/gnode-events-test-XXXXXX", path[128];
    CHECK(mkdtemp(directory)!=NULL);
    snprintf(path,sizeof path,"%s/events.jsonl",directory);
    opt=saved; interrupted=setup_calls=restore_calls=0;
    scenario=SIGNAL_TEST; signal_to_raise=SIGTERM;
    char *cli[]={"sle_gnode","--attempts","1","--log","/dev/null","--event-log",path,NULL};
    CHECK(sle_rt_program_main(7,cli)==128+SIGTERM);
    CHECK(restore_calls==1 && setup_calls==1);
    FILE *f=fopen(path,"r"); CHECK(f!=NULL); if (!f) abort();
    size_t n=fread(text,1,sizeof text-1,f); text[n]=0; fclose(f);
    CHECK(strstr(text,"\"kind\":\"attempt_start\"") && strstr(text,"\"kind\":\"attempt_stopping\"") &&
        strstr(text,"\"kind\":\"attempt_end\"") && strstr(text,"\"kind\":\"cleanup\"") &&
        strstr(text,"\"attributes_restored\":true"));
    CHECK(strstr(text,"\"kind\":\"attempt_stopping\"") < strstr(text,"\"kind\":\"attempt_end\""));
    interrupted=setup_calls=restore_calls=0;
    CHECK(sle_rt_program_main(7,cli)==1 && setup_calls==0 && restore_calls==0);
    f=fopen(path,"r"); CHECK(f!=NULL); if (!f) abort();
    char after[2048]={0}; CHECK(fread(after,1,sizeof after-1,f)==n && !memcmp(after,text,n)); fclose(f);
    CHECK(!unlink(path));
    /* Run the real main exit path with event startup/capacity faults: neither
     * may reach radio setup/start, and both must preserve restore/cleanup. */
    for (int fault=1;fault<=2;fault++) {
        char mainpath[128]; snprintf(mainpath,sizeof mainpath,"%s/main.jsonl",directory);
        opt=saved; interrupted=setup_calls=start_calls=restore_calls=0; event_fault=fault;
        char *failed_cli[]={"sle_gnode","--attempts","1","--log",mainpath,"--event-log",path,NULL};
        CHECK(sle_rt_program_main(7,failed_cli)==1);
        CHECK(!setup_calls && !start_calls && restore_calls==1);
        f=fopen(mainpath,"r"); CHECK(f!=NULL); if (!f) abort();
        if (fault==2) {
            /* main prefixes the buffered journal with a capacity marker.
             * Skip the fault-injected padding relative to that marker. */
            CHECK(fgets(text,sizeof text,f)!=NULL);
            CHECK(strstr(text,"\"kind\":\"journal_capacity\""));
            CHECK(!fseek(f,(long)(LOG_CAP-LOG_TAIL),SEEK_CUR));
        }
        n=fread(text,1,sizeof text-1,f); text[n]=0; fclose(f);
        CHECK(strstr(text,"\"kind\":\"attempt_stopping\"") && strstr(text,"\"kind\":\"attempt_end\""));
        CHECK(strstr(text,fault==1 ? "event_journal_write":"journal_capacity"));
        CHECK(strstr(text,"\"milestone_observed\":false") && strstr(text,"\"attributes_restored\":true"));
        CHECK(strstr(text,"\"dropped_display_bytes\":0")); /* reserved attempt_end survives full journal */
        f=fopen(path,"r"); CHECK(f!=NULL); if (!f) abort();
        n=fread(text,1,sizeof text-1,f); text[n]=0; fclose(f);
        if (fault==1) CHECK(!n); /* failed writer is permanently latched */
        else CHECK(strstr(text,"\"kind\":\"attempt_stopping\"") && strstr(text,"\"kind\":\"attempt_end\""));
        CHECK(!unlink(path) && !unlink(mainpath));
        event_fault=0;
    }
    CHECK(!rmdir(directory));
    interrupted=0; opt=saved;
}

int main(void)
{
    checks=failures=0;
    interactive_cli_regression();
    options defaults=opt;
    char *empty[]={"sle_gnode",NULL};
    CHECK(!parse(1,empty) && opt.pair && opt.resource_layout==SLE_RESOURCE_STANDARD);
    CHECK(!opt.pair_variants && opt.cal_depth==6);
    const char *removed[]={"--capture","--cal-capture","--pair-debug-keys"};
    for(size_t i=0;i<sizeof removed/sizeof removed[0];i++) {
        char *args[]={"sle_gnode",(char *)removed[i],NULL};
        CHECK(parse(2,args)==-1);
    }
    char *sdk[]={"sle_gnode","--resource-layout","standard","--pair-variant","0x200",NULL};
    CHECK(!parse(5,sdk) && opt.pair && opt.pair_variants==1 && opt.pair_variant[0]==0x200);
    opt=defaults;
    char *cal[]={"sle_gnode","--mode","calibrate",NULL};
    CHECK(!parse(3,cal) && opt.mode && !opt.pair);
    opt=defaults;
    char *access[]={"sle_gnode","--mode","access",NULL};
    CHECK(!parse(3,access) && opt.mode && !opt.pair);
    opt=defaults;
    char *bad_pair[]={"sle_gnode","--mode","calibrate","--pair",NULL};
    CHECK(parse(4,bad_pair)==-1);
    opt=defaults;
    CHECK(!install_signals());
    /* Legacy unencrypted mock scenarios remain useful unit coverage. */
    opt.pair=0; opt.resource_layout=SLE_RESOURCE_LEGACY_WS63;
    cache_regression(); access_regression(); calibration_recovery_regression();
    connection_regression(); signal_regression();
    sle_rt_application_regression();
    interactive_chat_regression(); interactive_write_regression(); interactive_pump_regression();
    sdu_application_regression();
    interactive_event_buffer_regression(); interactive_display_regression();
    interactive_console_regression(); interactive_signal_regression();
    interactive_retry_regression(); interactive_started_signal_regression();
    event_journal_regression();
    printf("G application audit regressions: %u checks, %u failures (scripted I/O, no hardware)\n",checks,failures);
    return failures ? 1:0;
}
