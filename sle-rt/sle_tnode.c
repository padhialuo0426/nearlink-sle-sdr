/* Experimental T-node. CPU1 uses the validated radio DMA/DSP engine;
 * CPU0 serves advertisements and follows the peer's requested schedule.
 * Delayed conditional replies are an experiment, not a compliance claim. */
#define _GNU_SOURCE
#include "sle_radio.h"
#include "sle_hwstat.h"
#include "sle_t_runtime.h"
#include "sle_cmtc.h"
#include "sle_ssap_server.h"
#include "sle_t_wave.h"
#include "sle_sdu.h"
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>

#define US(x) ((int64_t)(x)*4)
#define JOURNAL (32u*1024u*1024u)
#define ACCESS_RSP_US 12500
/* Connection establishment: in 20 connected attempts (logs/e310, 2026-09-28..29)
 * the first peer frame arrived at event 1 (19) or 2 (1); the three link_down
 * attempts never saw one and waited ~5 s of supervision. End the attempt
 * after this many events without any peer frame so the next attempt
 * re-calibrates and advertises afresh (t-regress r02/1). */
#define SLE_T_CONN_ESTABLISH_EVENTS 6
/* After an establishment failure the client keeps requesting (t-probe: next
 * request 0.17-9 s later within its 10 s connect cycle; 2.5 s probes saw no
 * client connection traffic), so advertise again inside the same attempt
 * instead of re-calibrating: at most this many times, each with this scan
 * budget. The calibration stays valid on the continuous stream and every
 * advertisement still re-checks it through its own-TX witness. */
#define SLE_T_READVERTISE_LIMIT 2
/* Outgoing link SDUs are split into records of at most --tx-frag data bytes
 * (default 24, WS63's own split) and fed to the 8-slot TX store as slots
 * free up, keeping SLE_T_TX_RESERVE slots for link/pairing control PDUs. */
#define SLE_T_TX_SDUS 4
#define SLE_T_TX_RESERVE 2
#define SLE_T_READVERTISE_SECONDS 10
/* Connection replies without the own-TX witness. Misses run 2-4% and
 * cluster (t-readv r04: 3 in a row ended a healthy link with 365 peer
 * frames). Keep the strict limit when the peer is also missing; allow a
 * longer run while the peer frame of every one of those events arrived.
 * The next witness still passes observe_cal, so a real TX slip still ends
 * the connection as connection_offset_jump. */
#define SLE_T_CONN_WITNESS_MISS_LIMIT 3
#define SLE_T_CONN_WITNESS_MISS_LIMIT_PEER 8
#define SLE_T_ADV_WITNESS_MISS_LIMIT 3 /* consecutive advertisements, as G's SLE_RT_WITNESS_MISS_LIMIT */
static volatile sig_atomic_t interrupted;
static void stop_signal(int sig) { interrupted=sig; }
typedef struct {
    sle_rt_radio r; sle_rt_cal cal; unsigned seq, attempt;
    char *journal; size_t used; const char *reason;
    int64_t deadline; unsigned peer_frames, events;
    uint8_t local[6], peer[6]; sle_tx_indication_t txi;
    int64_t request_sample; double peer_cfo;
    sle_t_runtime crypto; sle_rt_tx_store store; sle_link_t *link;
    sle_ssap_server ssap; sle_sdu_rx sdu;
    int crypto_ready, pair_state, ready_emitted, notified, worker_unjoined;
    unsigned cal_restarts, adv_miss_run, adv_misses, readvertises, conn_miss_run, conn_miss_peer;
    struct { uint8_t data[SLE_SDU_MAX]; size_t len, off; unsigned frags; } txq[SLE_T_TX_SDUS];
    unsigned txq_head, txq_len; uint64_t tx_records;
    char chat[1024]; size_t chat_len; int chat_eof;
    uint64_t discovered_ms, notify_ms, last_peer_ms;
    FILE *output;
} t_app;
static struct { int seconds, connect_seconds, attempts, reply_delay_us;
    double tx_gain,rx_gain; const char *log; int predictive; const char *notify_prefix;
    sle_resource_layout_t resource_layout; unsigned pair_variant;
    int hw_status, hw_prio, hw_period_us, cal_depth, local_mtu, tx_frag, notify_len, interactive; } opt={40,20,2,1250,-10,30,"/tmp/sle_tnode.jsonl",1,"SLE-SERVER",SLE_RESOURCE_STANDARD,SLE_PAIR_V_COUNT_PLAIN,0,0,200,SLE_RT_CAL_DEPTH,520,24,0,0};
static sle_rt_hwstat *hw;
static const char *resource_layout_name(sle_resource_layout_t layout)
{
    return layout == SLE_RESOURCE_STANDARD ? "standard" : "legacy-ws63";
}
static void log_event(t_app *a,const char *kind,const char *fmt,...)
{
    char row[10000]; int n=snprintf(row,sizeof row,"{\"kind\":\"%s\",\"attempt\":%u,\"mono_ns\":%" PRId64,kind,a->attempt,sle_iio_now_ns());
    va_list ap; va_start(ap,fmt); int m=vsnprintf(row+n,sizeof row-(size_t)n,fmt,ap); va_end(ap);
    if (m<0 || (size_t)m>=sizeof row-(size_t)n-3 || a->used+(size_t)n+(size_t)m+2>JOURNAL) { a->reason="journal_full"; return; }
    n+=m; row[n++]='}'; row[n++]='\n'; memcpy(a->journal+a->used,row,(size_t)n); a->used+=(size_t)n;
}
static void nap(void) { struct timespec t={0,50000}; nanosleep(&t,NULL); }
static int alive(t_app *a)
{
    if (interrupted) a->reason="signal";
    else if (atomic_load(&a->r.error)) a->reason=sle_rt_io_error_name(atomic_load(&a->r.error));
    else if (sle_iio_now_ns()>a->deadline) a->reason="budget_exhausted";
    else if(a->crypto_ready) {
        int e=sle_t_runtime_poll(&a->crypto,(uint64_t)(sle_iio_now_ns()/1000000));
        if(a->pair_state!=(int)a->crypto.pair.state || e){
            a->pair_state=(int)a->crypto.pair.state;
            log_event(a,"pair_state",",\"state\":%d,\"error\":%d,\"tx_next\":%" PRIu64 ",\"rx_next\":%" PRIu64,a->pair_state,e,a->crypto.pair.tx_next,a->crypto.pair.rx_next);
        }
        if(e)a->reason="pair_failed";
    }
    return a->reason==NULL;
}
static int wait_sample(t_app *a,int64_t sample)
{
    while (alive(a) && atomic_load(&a->r.rx_head)<sample) nap();
    return alive(a) ? 0:-1;
}
static int issue(t_app *a,sle_rt_command *c)
{
    if(!alive(a))return -1;
    c->seq=++a->seq;
    int e=sle_rt_radio_submit(&a->r,c); int64_t end=sle_iio_now_ns()+20000000;
    while (!e && alive(a) && atomic_load_explicit(&a->r.ack_seq,memory_order_acquire)!=c->seq) {
        if (sle_iio_now_ns()>end) { a->reason="command_ack_timeout"; return -1; } nap();
    }
    if (!alive(a)) return -1;
    if (!e) e=atomic_load(&a->r.ack_result);
    log_event(a,"command",",\"seq\":%u,\"result\":\"%s\",\"tx_start\":%" PRId64 ",\"wave_samples\":%zu,\"rx_start\":%" PRId64 ",\"rx_end\":%" PRId64,c->seq,sle_rt_result_name(e),c->tx_start,c->wave.n,c->rx_start,c->rx_end);
    if (e) a->reason=sle_rt_result_name(e);
    else atomic_store(&a->r.mute,0);
    return e ? -1:0;
}
static int tune(t_app *a,int mhz)
{
    atomic_store(&a->r.mute,1);
    int64_t start=sle_iio_now_ns();
    int e=sle_rt_radio_retune(1,mhz) || sle_rt_radio_retune(0,mhz);
    log_event(a,"retune",",\"mhz\":%d,\"elapsed_ns\":%" PRId64 ",\"error\":%d",mhz,sle_iio_now_ns()-start,e);
    if (e) a->reason="retune_failed";
    return !e && alive(a) ? 0:-1;
}
static void hex(char *o,const uint8_t *p,size_t n) { static const char d[]="0123456789abcdef"; for(size_t i=0;i<n;i++){o[2*i]=d[p[i]>>4];o[2*i+1]=d[p[i]&15];}o[2*n]=0; }
static int frame(t_app *a,unsigned seq,sle_rt_received *f)
{
    while (!sle_rt_ring_pop(&a->r.frames,f)) {
        char h[SLE_MAX_CONNECT_PAYLOAD_BYTES*2+1]; hex(h,f->f.frame.payload,f->f.frame.payload_len);
        const sle_frame_t *v=&f->f.frame;
        if(!isfinite(f->cfo_hz))f->cfo_hz=0;
        log_event(a,"frame",",\"seq\":%u,\"sample\":%" PRIu64 ",\"mhz\":%d,\"seed\":%u,\"a2\":%d,\"ptype\":%u,\"empty\":%u,\"sn\":%u,\"nesn\":%u,\"crc12\":%d,\"crc24\":%d,\"payload\":\"%s\",\"cfo\":%.1f",f->seq,f->f.sample_index,f->f.channel_mhz,v->seed,v->kind,v->kind?v->conn_pkt_type:v->packet_type,v->conn_empty,v->conn_sn,v->conn_nesn,v->crc12_ok,v->crc24_ok,h,f->cfo_hz);
        if(f->seq==seq) return 1;
    }
    return 0;
}
static int bcast_wave(sle_rt_wave *w,const uint8_t *p,size_t n,int seed,int btype,int ptype)
{
    uint8_t bits[2048]; size_t nb=sle_access_encode_frame(bits,sizeof bits,p,n,(uint8_t)seed,(uint8_t)btype,(uint8_t)ptype);
    return !nb || sle_t_modulate(w,bits,nb) ? -1:0;
}
/* Failed witness updates also clear the mapping. Preserve the rejected
 * measurement and the stable run before observing; successful event updates
 * incur no extra timestamp or journal formatting. */
static int observe_cal(t_app *a, int64_t tx, int64_t rx)
{
    sle_rt_cal before=a->cal;
    int e=sle_rt_cal_observe(&a->cal,tx,rx);
    if (e) log_event(a,"calibration_failure",",\"tx_sync\":%" PRId64 ",\"rx_sync\":%" PRId64
        ",\"candidate_offset\":%" PRId64 ",\"offset_before\":%" PRId64 ",\"count_before\":%d,"
        "\"valid_before\":%s,\"offset\":%" PRId64 ",\"count\":%d,\"valid_after\":%s,"
        "\"cleared\":%s,\"result\":\"%s\"",tx,rx,rx-tx,before.offset,before.count,
        before.valid ? "true":"false",a->cal.offset,a->cal.count,a->cal.valid ? "true":"false",
        !a->cal.count ? "true":"false",sle_rt_result_name(e));
    return e;
}
/* One matched calibration marker. Returns -1 only for a fail-closed error.
 * T always starts without an established RX/TX mapping. A DAC underflow
 * shifts TX later (docs/experiments/hwstat-probe-2026-09-29.md), so an
 * offset jump discards this marker and requires three fresh stable bursts
 * within the same 12-trial budget, as G does. Any other error fails. */
static int cal_decide(t_app *a,int trial,int64_t tx_sync,int64_t rx_sync)
{
    sle_rt_cal before=a->cal;
    int e=observe_cal(a,tx_sync,rx_sync);
    log_event(a,"calibration",",\"offset\":%" PRId64 ",\"count\":%d,\"error\":%d,"
        "\"trial\":%d,\"tx_sync\":%" PRId64 ",\"rx_sync\":%" PRId64
        ",\"candidate_offset\":%" PRId64 ",\"offset_before\":%" PRId64
        ",\"count_before\":%d,\"valid_before\":%s,\"valid_after\":%s,\"cleared\":%s",
        a->cal.offset,a->cal.count,e,trial,tx_sync,rx_sync,rx_sync-tx_sync,before.offset,before.count,
        before.valid ? "true":"false",a->cal.valid ? "true":"false",
        e && !a->cal.count ? "true":"false");
    if(!e) return 0;
    if(e!=SLE_RT_OFFSET_JUMP){a->reason="calibration_invalid";return -1;}
    a->cal_restarts++;
    log_event(a,"calibration_restart",",\"trial\":%d,\"remaining_trials\":%d,\"reason\":\"initial_offset_jump\",\"restarts\":%u",
        trial,11-trial,a->cal_restarts);
    return 0;
}
static int calibrate_trials(t_app *a)
{
    /* Retained calibration payload bytes; not a public phase identifier. */
    uint8_t marker[16]="P7CAL"; memcpy(marker+5,a->local,6);
    uint64_t nonce=(uint64_t)sle_iio_now_ns(); memcpy(marker+11,&nonce,5);
    sle_rt_cal_clear(&a->cal);
    for(int trial=0;trial<12 && !a->cal.valid && alive(a);trial++) {
        marker[15]++;
        sle_rt_command c={.mhz=2424,.seed=77,.rx_start=0,.rx_end=INT64_MAX};
        if(bcast_wave(&c.wave,marker,sizeof marker,77,0,0)) return -1;
        c.tx_start=atomic_load(&a->r.tx_head)+SLE_RT_BLOCK*5;
        if(issue(a,&c)) return -1;
        {char mk[2*sizeof marker+1];hex(mk,marker,sizeof marker);
        log_event(a,"calibration_detail",",\"trial\":%d,\"cmd_seq\":%u,\"tx_start\":%" PRId64 ",\"tx_sync\":%" PRId64 ",\"wave_samples\":%zu,\"marker\":\"%s\",\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64,
            trial,c.seq,c.tx_start,c.tx_start+sle_rt_sync_in_wave(),c.wave.n,mk,(int64_t)atomic_load(&a->r.rx_head),(int64_t)atomic_load(&a->r.tx_head));}
        int64_t end=sle_iio_now_ns()+30000000; int found=0;
        while(alive(a) && sle_iio_now_ns()<end) {
            sle_rt_received f; if(!frame(a,c.seq,&f)){nap();continue;}
            if(f.f.frame.kind || !f.f.frame.crc24_ok || f.f.frame.payload_len!=sizeof marker || memcmp(f.f.frame.payload,marker,sizeof marker))continue;
            int64_t tx_sync=c.tx_start+sle_rt_sync_in_wave();
            if(cal_decide(a,trial,tx_sync,(int64_t)f.f.sample_index)) return -1;
            found=1; break;
        }
        if(!found) {
            log_event(a,"calibration_miss",",\"trial\":%d,\"candidate_offset\":null,"
                "\"offset_before\":%" PRId64 ",\"count_before\":%d,\"cleared\":true,\"count\":0",
                trial,a->cal.offset,a->cal.count);
            sle_rt_cal_clear(&a->cal);
        }
        if(wait_sample(a,atomic_load(&a->r.rx_head)+US(3000)))return -1;
    }
    if(!a->cal.valid){a->reason="calibration_failed";return -1;}
    atomic_store(&a->r.guard,1);
    return 0;
}
/* Hold the --cal-depth TX reserve only while calibrating
 * (docs/experiments/sw-opt-cpu0-2026-09-29.md); the stream stays continuous
 * so the RX/TX mapping is unchanged. Success then grows to the 4 ms
 * connection reserve; any shrink waits until the extra blocks have drained. */
static int calibrate(t_app *a)
{
    int keep=atomic_load(&a->r.depth), deep=opt.cal_depth>keep ? opt.cal_depth:keep;
    atomic_store(&a->r.depth,deep);
    log_event(a,"cal_depth",",\"phase\":\"raise\",\"depth\":%d,\"restore_depth\":%d,\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64,
        deep,keep,(int64_t)atomic_load(&a->r.rx_head),(int64_t)atomic_load(&a->r.tx_head));
    int rc=calibrate_trials(a);
    int next=rc ? keep : 16*1024/SLE_RT_BLOCK; /* 4ms TX reserve through gated RX bursts */
    atomic_store(&a->r.depth,next);
    int64_t rx=atomic_load(&a->r.rx_head), tx=atomic_load(&a->r.tx_head);
    int w=rc || next>=deep ? 0 : wait_sample(a,rx+(int64_t)(deep+1)*SLE_RT_BLOCK);
    log_event(a,"cal_depth",",\"phase\":\"restore\",\"depth\":%d,\"result\":%d,\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64
        ",\"settled_rx_head\":%" PRId64 ",\"settled_tx_head\":%" PRId64 ",\"settle_error\":%d",
        next,rc,rx,tx,(int64_t)atomic_load(&a->r.rx_head),(int64_t)atomic_load(&a->r.tx_head),w);
    return rc ? rc : w;
}
static int build_adv(t_app *a,sle_rt_wave *primary,sle_rt_wave *aux)
{
    sle_bcast_pdu_t p; sle_bcast_pdu_init(&p); p.present=SLE_PRESENT_LOCAL_ID|SLE_PRESENT_RESOURCE;
    memcpy(p.local_id,a->local,6);
    sle_resource_word_t rw={.channel=22,.unit=0,.offset=160}; /*2426 MHz, +20ms*/
    if(sle_resource_word_encode_layout(&rw,opt.resource_layout,&p.resource_word))return -1;
    uint8_t bytes[256],tlv[64]; size_t n=sle_bcast_pdu_build(&p,bytes,sizeof bytes);
    if(!n || bcast_wave(primary,bytes,n,77,1,0))return -1;
    sle_bcast_pdu_init(&p);p.present=SLE_PRESENT_LOCAL_ID;memcpy(p.local_id,a->local,6);
    sle_access_resource_t u={.req_offset_us=2500,.req_max_len=255,.rsp_offset_us=ACCESS_RSP_US,.count=1,.req_type=1};
    n=sle_access_resource_build(&u,1,tlv,sizeof tlv);
    if(!n || sle_bcast_pdu_add_tlv(&p,SLE_TLV_DISC_ACCESS_CFG,tlv,n))return -1;
    const uint8_t name[]={0x01,0x02,0x01,0x10,0x0b,'s','l','e','_','u','a','r','t','_','s','e','r','v','e','r'};
    if(sle_bcast_pdu_add_tlv(&p,SLE_TLV_HIGH_LAYER,name,sizeof name))return -1;
    n=sle_bcast_pdu_build(&p,bytes,sizeof bytes);
    return !n || bcast_wave(aux,bytes,n,22,1,1) ? -1:0;
}
static int tx_at(t_app *a,sle_rt_command *c,int64_t rx_sync)
{
    int e=sle_rt_tx_index(&a->cal,rx_sync,atomic_load(&a->r.tx_head),&c->tx_start);
    log_event(a,"tx_slack",",\"desired_rx_sync\":%" PRId64 ",\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64 ",\"cal_offset\":%" PRId64 ",\"result\":%d",rx_sync,(int64_t)atomic_load(&a->r.rx_head),(int64_t)atomic_load(&a->r.tx_head),a->cal.offset,e);
    if(e){a->reason=sle_rt_result_name(e);return -1;}return issue(a,c);
}
static void txq_clear(t_app *a)
{
    sle_rt_wipe(a->txq,sizeof a->txq); a->txq_head=a->txq_len=0;
}
/* Push queued SDU records while TX slots allow. 0 = done or waiting for
 * slots, -1 = hard queue error (reason set). */
static int tx_pump(t_app *a)
{
    while(a->txq_len && a->link){
        __typeof__(a->txq[0]) *q=&a->txq[a->txq_head];
        while(q->off<q->len){
            if(sle_rt_free_slots(&a->store,a->link)<=SLE_T_TX_RESERVE) return 0;
            uint8_t rec[SLE_RT_TX_MAX];size_t off=q->off;
            size_t m=sle_sdu_tx_fragment(q->data,q->len,&off,(size_t)opt.tx_frag,rec,sizeof rec-4);
            if(!m){a->reason="sdu_fragment";return -1;}
            int e=sle_rt_queue(&a->store,a->link,SLE_PTYPE_DATA,rec,m);
            if(e==-2) return 0;
            if(e){a->reason="sdu_queue";return -1;}
            q->off=off;q->frags++;a->tx_records++;
        }
        log_event(a,"sdu_tx",",\"len\":%zu,\"fragments\":%u,\"tx_frag\":%d",q->len,q->frags,opt.tx_frag);
        sle_rt_wipe(q,sizeof *q);a->txq_head=(a->txq_head+1)%SLE_T_TX_SDUS;a->txq_len--;
    }
    return 0;
}
static int queue_sdu(t_app *a,const uint8_t *p,size_t n)
{
    if(!n || n>SLE_SDU_MAX || a->txq_len>=SLE_T_TX_SDUS)return -1;
    __typeof__(a->txq[0]) *q=&a->txq[(a->txq_head+a->txq_len)%SLE_T_TX_SDUS];
    memcpy(q->data,p,n);q->len=n;q->off=0;q->frags=0;a->txq_len++;
    return tx_pump(a);
}
/* Deterministic notification value of opt.notify_len bytes (0: legacy
 * short text). scripts/sle_t_verify_trial.py rebuilds it the same way. */
static int notify_value(t_app *a,char *out,size_t cap)
{
    int n=snprintf(out,cap,"%s-%u-%02d%s",opt.notify_prefix,a->attempt,a->notified,opt.notify_len?"-":"\r\n");
    if(!opt.notify_len) return n;
    static const char fill[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if(n<0 || (size_t)opt.notify_len>=cap || opt.notify_len<n+2) return -1;
    for(int i=n;i<opt.notify_len-2;i++) out[i]=fill[(i-n)%36];
    out[opt.notify_len-2]='\r';out[opt.notify_len-1]='\n';out[opt.notify_len]=0;
    return opt.notify_len;
}
static void on_sdu(void *ctx,const uint8_t *p,size_t n,unsigned fragments)
{
    t_app *a=ctx;uint8_t reply[1028];size_t len=0;
    if(a->reason)return;
    char text[2057];hex(text,p,n);
    log_event(a,"sdu_deliver",",\"len\":%zu,\"fragments\":%u,\"payload\":\"%s\"",n,fragments,text);
    if(n>=2 && p[0]==(SLE_CMTC_TCID&0xff) && p[1]==(SLE_CMTC_TCID>>8) && n>4 && p[4]==2){
        uint8_t id=0;uint16_t mps=0,ver=0;int e=sle_cmtc_capability_parse_rsp(p,n,&id,&mps,&ver);
        log_event(a,"cmtc_capability_peer_rsp",",\"identifier\":%u,\"mps\":%u,\"version\":%u,\"error\":%d",id,mps,ver,e);
        if(e){a->reason="cmtc_failed";}
        return;
    }
    if(n>=2 && p[0]==(SLE_CMTC_TCID&0xff) && p[1]==(SLE_CMTC_TCID>>8)){
        int e=sle_cmtc_capability_reply(p,n,reply,sizeof reply,&len);
        log_event(a,"cmtc_capability_req",",\"identifier\":%u,\"bitmap\":%u,\"pair_state\":%d,\"encrypted\":%s,\"error\":%d",n>5?p[5]:0,n>=12?(unsigned)p[8]:0,(int)a->crypto.pair.state,sle_t_runtime_encrypted(&a->crypto)?"true":"false",e);
        if(e || queue_sdu(a,reply,len)){a->reason="cmtc_failed";return;}
        log_event(a,"cmtc_capability_rsp",",\"identifier\":%u,\"mps\":%u,\"version\":%u,\"queued\":true",p[5],SLE_CMTC_MPS,SLE_CMTC_VERSION);
        return;
    }
    uint64_t writes=a->ssap.writes;
    int e=sle_ssap_server_rx(&a->ssap,sle_t_runtime_encrypted(&a->crypto),p,n,reply,sizeof reply,&len);
    log_event(a,"ssap_rx",",\"opcode\":%u,\"error\":%d,\"reply_len\":%zu",n>4?p[4]:0,e,len);
    if(e || (len && queue_sdu(a,reply,len))){a->reason="ssap_failed";return;}
    if(a->ssap.discovered && !a->discovered_ms)a->discovered_ms=(uint64_t)(sle_iio_now_ns()/1000000);
    if(a->ssap.writes>writes){
        hex(text,a->ssap.value,a->ssap.value_len);
        log_event(a,"ssap_write",",\"len\":%zu,\"value_hex\":\"%s\",\"encrypted\":true",a->ssap.value_len,text);
        if(opt.interactive){fwrite(a->ssap.value,1,a->ssap.value_len,stdout);fflush(stdout);}
    }
}
/* --interactive 1: take one notification value from the typed input. A
 * complete line (LF, optional CR stripped) is sent as line+CRLF; a line
 * longer than maxv-2 bytes is sent in maxv-2 byte pieces. Consumed bytes
 * leave buf. Returns the value length, 0 when no value is ready. */
static size_t chat_next(char *buf,size_t *len,size_t maxv,char *out)
{
    if(maxv<3 || !*len) return 0;
    char *nl=memchr(buf,'\n',*len);
    size_t take,line;
    if(nl){ line=(size_t)(nl-buf); take=line+1; if(line && buf[line-1]=='\r') line--; }
    else if(*len>=maxv-2){ line=take=maxv-2; }
    else return 0;
    if(line>maxv-2){ line=take=maxv-2; }
    memcpy(out,buf,line); out[line]='\r'; out[line+1]='\n';
    memmove(buf,buf+take,*len-take); *len-=take;
    return line+2;
}
static int chat_pump(t_app *a)
{
    if(!a->chat_eof && a->chat_len<sizeof a->chat){
        struct pollfd pf={.fd=0,.events=POLLIN};
        if(poll(&pf,1,0)>0){
            ssize_t r=read(0,a->chat+a->chat_len,sizeof a->chat-a->chat_len);
            if(r>0) a->chat_len+=(size_t)r; else a->chat_eof=1;
        }
    }
    size_t maxv=a->ssap.mtu>6 ? (size_t)a->ssap.mtu-6:0; if(maxv>SLE_SSAP_SERVER_VALUE_MAX) maxv=SLE_SSAP_SERVER_VALUE_MAX;
    char value[SLE_SSAP_SERVER_VALUE_MAX];size_t n;
    while(a->txq_len<SLE_T_TX_SDUS && (n=chat_next(a->chat,&a->chat_len,maxv,value))){
        uint8_t sdu[SLE_SDU_MAX];size_t len=0;
        if(sle_ssap_server_notify(&a->ssap,1,(const uint8_t*)value,n,sdu,sizeof sdu,&len) || queue_sdu(a,sdu,len)){a->reason="notify_queue";return -1;}
        char text[2*SLE_SSAP_SERVER_VALUE_MAX+1];hex(text,(const uint8_t*)value,n);
        log_event(a,"ssap_notify_queued",",\"value_hex\":\"%s\",\"len\":%zu,\"interactive\":true",text,n);
        printf("  [E310 -> WS63 通知已排队 %zu B]\n",n);fflush(stdout);
    }
    return 0;
}
static int business(t_app *a)
{
    uint64_t now=(uint64_t)(sle_iio_now_ns()/1000000);
    if(a->discovered_ms && now>a->discovered_ms+1000 && !a->ready_emitted){
        a->ready_emitted=1;log_event(a,"ssap_ready",",\"encrypted\":true");
        if(opt.interactive){printf("[E310] 已连接并加密（MTU %u）。输入一行按回车发给 WS63；WS63 键入的字符会显示在下面。Ctrl+C 退出。\n",a->ssap.mtu);fflush(stdout);}
        if(fwrite(a->journal,1,a->used,a->output)!=a->used || fflush(a->output)){a->reason="journal_write";return -1;}
        a->used=0;
    }
    if(opt.interactive){
        /* Long sessions: keep the 32 MiB journal from filling. */
        if(a->used>(4u<<20)){ if(fwrite(a->journal,1,a->used,a->output)!=a->used || fflush(a->output)){a->reason="journal_write";return -1;} a->used=0; }
        return a->ready_emitted ? chat_pump(a):0;
    }
    if(a->ready_emitted && a->notified<4 && now>a->notify_ms+750 && !a->link->q_len && !a->txq_len){
        char value[SLE_SSAP_SERVER_VALUE_MAX+1];int n=notify_value(a,value,sizeof value);
        uint8_t sdu[SLE_SDU_MAX];size_t len=0;
        if(n<0 || sle_ssap_server_notify(&a->ssap,1,(const uint8_t*)value,(size_t)n,sdu,sizeof sdu,&len) || queue_sdu(a,sdu,len)){a->reason="notify_queue";return -1;}
        char text[2*SLE_SSAP_SERVER_VALUE_MAX+1];hex(text,(const uint8_t*)value,(size_t)n);
        log_event(a,"ssap_notify_queued",",\"value_hex\":\"%s\",\"len\":%d",text,n);
        a->notified++;a->notify_ms=now;
    }
    return 0;
}
/* One advertisement's own-TX witness. A single CRC24 error or an external
 * collision used to end the attempt (t-cal-restart r01/2, r02/1). Now, as
 * on G, only SLE_T_ADV_WITNESS_MISS_LIMIT consecutive misses fail; a miss skips
 * that advertisement's request window, so no response is ever scheduled on
 * an unverified TX mapping. A present witness still passes observe_cal, so
 * a real TX slip still fails as advertisement_offset_jump.
 * Returns 1 = listen, 0 = skip this window, -1 = abort. */
static int adv_witness_decide(t_app *a,int64_t sync,int witness,int near,int near_rejected)
{
    if(witness){a->adv_miss_run=0;return 1;}
    a->adv_miss_run++;a->adv_misses++;
    log_event(a,"advertisement_witness_miss",",\"sync\":%" PRId64 ",\"run\":%u,\"limit\":%d,\"total\":%u,"
        "\"near_frames\":%d,\"near_rejected\":%d,\"action\":\"%s\"",sync,a->adv_miss_run,SLE_T_ADV_WITNESS_MISS_LIMIT,
        a->adv_misses,near,near_rejected,a->adv_miss_run>=SLE_T_ADV_WITNESS_MISS_LIMIT ? "abort":"skip_request_window");
    if(a->adv_miss_run>=SLE_T_ADV_WITNESS_MISS_LIMIT){a->reason="advertisement_witness_missing";return -1;}
    return 0;
}
static int advertise(t_app *a)
{
    sle_rt_wave primary,aux;if(build_adv(a,&primary,&aux)){a->reason="advertisement_build";return -1;}
    int first_adv=1;
    while(alive(a)) {
        if(tune(a,2424))return -1;
        int64_t sync=atomic_load(&a->r.tx_head)+a->cal.offset+US(6000);
        sle_rt_command c={.mhz=2424,.seed=77,.rx_start=sync-US(50),.rx_end=sync+US(1000),.wave=primary};
        if(tx_at(a,&c,sync))return -1;
        if(first_adv) {
            log_event(a,"advertisement_start",",\"seq\":%u,\"sync\":%" PRId64
                ",\"tx_start\":%" PRId64 ",\"scheduled\":true",c.seq,sync,c.tx_start);
            first_adv=0;
        }
        if(wait_sample(a,sync+US(1500)))return -1;
        sle_rt_received f;int witness=0,near=0,near_rejected=0;
        while(frame(a,c.seq,&f)) {
            if(f.f.frame.kind || llabs((int64_t)f.f.sample_index-sync)>=40) continue;
            near++;
            if(!f.f.frame.crc24_ok || f.f.frame.packet_type!=0){near_rejected++;continue;}
            int e=observe_cal(a,c.tx_start+sle_rt_sync_in_wave(),(int64_t)f.f.sample_index);
            if(e){a->reason="advertisement_offset_jump";return -1;}witness=1;
        }
        log_event(a,"advertisement",",\"sync\":%" PRId64 ",\"witness\":%d",sync,witness);
        int listen=adv_witness_decide(a,sync,witness,near,near_rejected);
        if(listen<0)return -1;
        if(!listen){if(wait_sample(a,sync+US(90000)))return -1;continue;} /* same cadence as a listened advertisement */
        if(tune(a,2426))return -1;
        /* Decode the known request window only; decoding quiet samples until
         * the later response deadline overloads the scalar ARM demodulator. */
        sync+=US(20000);c=(sle_rt_command){.mhz=2426,.seed=22,.estimate_cfo=1,.rx_start=sync-US(50),.rx_end=sync+US(4500),.wave=aux};
        if(tx_at(a,&c,sync))return -1;
        log_event(a,"adv_listen_window",",\"seq\":%u,\"rx_start\":%" PRId64
            ",\"rx_end\":%" PRId64 ",\"sync\":%" PRId64,c.seq,c.rx_start,c.rx_end,sync);
        while(alive(a) && atomic_load(&a->r.rx_head)<sync+US(5000)){
            if(!frame(a,c.seq,&f)){nap();continue;}
            const sle_frame_t *v=&f.f.frame;
            if(v->kind || !v->crc24_ok || v->packet_type!=SLE_PTYPE_ACCESS_REQ)continue;
            sle_bcast_pdu_t req;int parse_error=sle_bcast_pdu_parse(v->payload,v->payload_len,&req);
            if(parse_error) {
                log_event(a,"access_request_reject",",\"seq\":%u,\"sample\":%" PRIu64
                    ",\"reason\":\"bcast_parse\",\"parse_error\":%d",f.seq,f.f.sample_index,parse_error);
                continue;
            }
            if(memcmp(req.peer_id,a->local,6)) {
                char peer[13],expected[13];hex(peer,req.peer_id,6);hex(expected,a->local,6);
                log_event(a,"access_request_reject",",\"seq\":%u,\"sample\":%" PRIu64
                    ",\"reason\":\"peer_mismatch\",\"peer_id\":\"%s\",\"expected_peer_id\":\"%s\"",
                    f.seq,f.f.sample_index,peer,expected);
                continue;
            }
            size_t n=0;const uint8_t *t=sle_bcast_pdu_find_tlv(&req,SLE_TLV_TX_INDICATION,&n);
            parse_error=t ? sle_tx_indication_parse(t,n,&a->txi):0;
            if(!t || parse_error) {
                log_event(a,"access_request_reject",",\"seq\":%u,\"sample\":%" PRIu64
                    ",\"reason\":\"%s\",\"tlv_len\":%zu,\"parse_error\":%d",f.seq,f.f.sample_index,
                    t ? "tx_indication_parse":"tx_indication_missing",n,parse_error);
                a->reason="request_parse";return -1;
            }
            memcpy(a->peer,req.local_id,6);a->request_sample=(int64_t)f.f.sample_index;a->peer_cfo=f.cfo_hz;
            log_event(a,"access_request",",\"request_sample\":%" PRId64 ",\"offset_us\":%u,\"base_slot\":%u,\"period_slots\":%u,\"gap_us\":%u,\"lid\":%u,\"crc\":%u,\"peer_cfo\":%.1f",a->request_sample,a->txi.start_offset_us,a->txi.base_slot,a->txi.group_period_slots,a->txi.intra_event_gap_us,a->txi.first_lid,a->txi.first_crc_init,a->peer_cfo);
            if(a->txi.event_count!=1 || a->txi.first_lid!=a->txi.second_lid || a->txi.first_crc_init!=a->txi.second_crc_init || a->txi.first_frame_type || a->txi.second_frame_type || a->txi.first_crc_type || a->txi.second_crc_type){a->reason="unsupported_schedule";return -1;}
            sle_access_rsp_info_t rsp={.count=1};memcpy(rsp.unit[0].peer_id,a->peer,6);rsp.unit[0].repeat=1;rsp.unit[0].has_capability=1;
            const uint8_t cap[6]={0xff,0xcc,0x81,0x6a,0x43,0x18};memcpy(rsp.unit[0].capability,cap,6);
            uint8_t data[64];n=sle_access_response_build(a->local,&rsp,data,sizeof data);
            c=(sle_rt_command){.mhz=2426,.seed=22,.rx_start=sync+US(ACCESS_RSP_US-100),.rx_end=sync+US(ACCESS_RSP_US+750)};
            if(!n || bcast_wave(&c.wave,data,n,22,1,5)||tx_at(a,&c,sync+US(ACCESS_RSP_US)) || wait_sample(a,sync+US(ACCESS_RSP_US+750)))return -1;
            log_event(a,"access_response_sent",",\"sync\":%" PRId64,sync+US(ACCESS_RSP_US));
            return 0;
        }
        if(wait_sample(a,sync+US(70000)))return -1;
    }
    return -1;
}
/* Predictive interop experiment: alternate a receive-only event with a
 * prearranged reply to the expected retry. A missing G does NOT cancel the
 * already scheduled T wave. This deliberately does not implement 6.4.1.1f. */
/* Measurement only (t-regress2: some responses are followed by a client
 * establishment attempt that T never hears). Record every schedule input
 * and the computed events 0..7 so they can be compared offline with the
 * client's own schedule. */
#define SLE_T_SCHED_LOG_EVENTS 8
static void log_schedule(t_app *a,const sle_conn_sched_t *s)
{
    const sle_tx_indication_t *x=&a->txi;
    char map[2*sizeof x->hop_map+1],used[4*76+1],ev[SLE_T_SCHED_LOG_EVENTS*112+1];
    hex(map,x->hop_map,x->hop_map_len<=sizeof x->hop_map?x->hop_map_len:sizeof x->hop_map);
    size_t n=0;used[0]=0;
    for(unsigned i=0;i<s->n_used;i++) n+=(size_t)snprintf(used+n,sizeof used-n,"%s%u",i?",":"",s->used[i]);
    n=0;ev[0]=0;
    for(uint32_t k=0;k<SLE_T_SCHED_LOG_EVENTS;k++){
        sle_conn_event_t e;sle_conn_event(s,k,&e);
        n+=(size_t)snprintf(ev+n,sizeof ev-n,"%s{\"k\":%u,\"sync\":%" PRId64 ",\"slot\":%u,\"phys\":%u,\"mhz\":%d,\"seed\":%u}",
            k?",":"",k,sle_ns_to_samples(e.t_ns,SLE_RT_FS),e.slot,e.phys,e.mhz,e.white_seed);
    }
    log_event(a,"conn_schedule",",\"anchor_sample\":%" PRId64 ",\"start_offset_us\":%u,\"t0_sample\":%" PRId64
        ",\"base_slot_raw\":%u,\"base_slot\":%u,\"period_slots\":%u,\"sched_slot\":%u,\"slot_ns\":%" PRId64
        ",\"lid\":%u,\"sync32\":\"%08x\",\"crc_init\":%u,\"intra_gap_us\":%u,\"timeout_10ms\":%u,\"latency_groups\":%u"
        ",\"first_second\":%u,\"sca\":%u,\"frame_types\":[%u,%u],\"pdu_max\":[%u,%u],\"max_time_offset\":[%u,%u]"
        ",\"hop_map_len\":%u,\"hop_map\":\"%s\",\"n_used\":%u,\"used\":[%s],\"events\":[%s]",
        a->request_sample,x->start_offset_us,sle_ns_to_samples(s->t0_ns,SLE_RT_FS),x->base_slot,s->base_slot,s->period_slots,
        x->sched_slot,s->slot_ns,s->lid,s->sync32,x->first_crc_init,x->intra_event_gap_us,x->timeout_10ms,x->latency_groups,
        x->first_second,x->sleep_clock_accuracy,x->first_frame_type,x->second_frame_type,x->first_pdu_max,x->second_pdu_max,
        x->first_max_time_offset,x->second_max_time_offset,x->hop_map_len,map,s->n_used,used,ev);
}
static void log_event_plan(t_app *a,const sle_link_tx_t *plan)
{
    if(a->events>=SLE_T_SCHED_LOG_EVENTS) return;
    log_event(a,"conn_event_plan",",\"i\":%u,\"k\":%" PRId64 ",\"sync\":%" PRId64 ",\"slot\":%u,\"phys\":%u,\"mhz\":%d,\"seed\":%u",
        a->events,plan->k,sle_ns_to_samples(plan->ev.t_ns,SLE_RT_FS),plan->ev.slot,plan->ev.phys,plan->ev.mhz,plan->ev.white_seed);
}
/* Called after each connection event is counted. 1 = give up establishing. */
static int establish_failed(t_app *a)
{
    if(a->peer_frames || a->events<SLE_T_CONN_ESTABLISH_EVENTS) return 0;
    log_event(a,"connection_establish_failed",",\"events\":%u,\"limit\":%d,\"request_sample\":%" PRId64,
        a->events,SLE_T_CONN_ESTABLISH_EVENTS,a->request_sample);
    a->reason="connection_establish_failed";
    return 1;
}

/* One predictive reply's witness. got = the peer frame of this event was
 * received. Returns -1 to abort (reason set), 0 to continue. */
static int conn_witness_decide(t_app *a,int64_t k,int witness,int got)
{
    if(witness){a->conn_miss_run=0;a->conn_miss_peer=1;return 0;}
    if(!a->conn_miss_run)a->conn_miss_peer=1;
    a->conn_miss_run++;a->conn_miss_peer&=got?1u:0u;
    int limit=a->conn_miss_peer?SLE_T_CONN_WITNESS_MISS_LIMIT_PEER:SLE_T_CONN_WITNESS_MISS_LIMIT;
    int abort=(int)a->conn_miss_run>=limit;
    if(a->conn_miss_run>=2)
        log_event(a,"conn_witness_miss",",\"k\":%" PRId64 ",\"run\":%u,\"peer_seen_all\":%u,\"limit\":%d,\"action\":\"%s\"",
            k,a->conn_miss_run,a->conn_miss_peer,limit,abort?"abort":"continue");
    if(abort){a->reason="predict_witness_missing";return -1;}
    return 0;
}
static int predictive_loop(t_app *a,sle_link_t *l)
{
    int phase=0,have_prediction=0,previous_empty=1;
    a->conn_miss_run=0;a->conn_miss_peer=1;
    size_t previous_len=0;
    static const uint8_t features[]={11,0,10,1,0,0,0,0,0,0,0,0,0};
    static const uint8_t version[]={13,0,5,1,0xff,0xff,1,0};
    while(alive(a)){
        if(sle_t_runtime_queue(&a->crypto,&a->store,l) || business(a) || tx_pump(a)){if(!a->reason)a->reason="protocol_queue";break;}
        sle_link_tx_t plan;
        if(sle_link_t_listen(l,sle_samples_to_ns(sle_rt_radio_now(&a->r),SLE_RT_FS),9000000,&plan)){a->reason="link_down";break;}
        log_event_plan(a,&plan);
        int sending=phase && have_prediction;
        int64_t sync=sle_ns_to_samples(plan.ev.t_ns,SLE_RT_FS),target=0;
        sle_rt_command c={.mhz=plan.ev.mhz,.seed=plan.ev.white_seed,.connect=1,.lid=l->s.lid,.crc=l->crc_init,.rx_start=sync-US(60),.rx_end=sync+US(1300)};
        sle_link_tx_t tx={0};
        if(sending){
            /* Preview existing ARQ state, without fabricating a receive or
             * updating supervision. The physical G condition is not enforced. */
            l->rx_hdr_ok=1;int e=sle_link_t_reply(l,&tx);l->rx_hdr_ok=0;
            if(e || sle_t_runtime_tx(&a->crypto,&tx)){a->reason="predict_prepare";break;}
            uint8_t bits[2048];size_t nb=sle_link_encode(l,&tx,bits,sizeof bits);
            if(!nb || sle_t_modulate(&c.wave,bits,nb)){a->reason="modulation";break;}
            target=sync+sle_ns_to_samples(sle_second_sender_offset_ns(&l->s,(uint32_t)previous_len,previous_empty),SLE_RT_FS)-US(3);
            c.rx_end=target+(int64_t)c.wave.n+US(500);
        }
        if(tune(a,plan.ev.mhz))break;
        if(sending ? tx_at(a,&c,target):issue(a,&c))break;
        sle_rt_received g={0};int got=0,witness=0;
        while(alive(a) && atomic_load(&a->r.rx_head)<c.rx_end+SLE_RT_BLOCK){
            sle_rt_received f;if(!frame(a,c.seq,&f)){nap();continue;}
            const sle_frame_t *v=&f.f.frame;
            if(!v->kind || !v->crc12_ok || (!v->conn_empty && !v->crc24_ok))continue;
            if(llabs((int64_t)f.f.sample_index-sync)<US(50)){g=f;got=1;}
            if(sending && llabs((int64_t)f.f.sample_index-target)<US(40) &&
               v->conn_empty==tx.empty && v->conn_sn==tx.sn && v->conn_nesn==tx.nesn &&
               v->conn_pkt_type==tx.ptype && v->payload_len==tx.len && (!tx.len || !memcmp(v->payload,tx.data,tx.len))){
                witness=1;int e=observe_cal(a,c.tx_start+sle_rt_sync_in_wave(),(int64_t)f.f.sample_index);
                log_event(a,"tx_witness",",\"k\":%" PRId64 ",\"error_samples\":%" PRId64 ",\"cal_error\":%d",plan.k,(int64_t)f.f.sample_index-target,e);
                if(e){a->reason="connection_offset_jump";break;}
            }
        }
        if(!alive(a))break;
        if(sending){
            log_event(a,"t_reply",",\"k\":%" PRId64 ",\"delay_us\":%.2f,\"conditional\":false,\"witness\":%d,\"g_seen\":%d,\"len\":%u",plan.k,(target-sync)/4.0,witness,got,tx.len);
            if(conn_witness_decide(a,plan.k,witness,got))break;
            if(sle_t_runtime_submitted(&a->crypto,&tx)){a->reason="pair_submitted";break;}
        }
        if(got){
            const sle_frame_t *v=&g.f.frame;
            sle_link_rx_t rx={.kind=SLE_RX_OK,.empty=v->conn_empty,.sn=v->conn_sn,.nesn=v->conn_nesn,.ptype=v->conn_pkt_type,.data=v->payload,.len=(uint16_t)v->payload_len};
            sle_link_rx_out_t out;sle_rt_rx authenticated;
            int e=sle_t_runtime_rx(&a->crypto,l,&rx,&out,&authenticated,(uint64_t)(sle_iio_now_ns()/1000000));
            log_event(a,"crypto_rx",",\"error\":%d,\"protected\":%d,\"duplicate\":%d,\"opcode\":%u,\"mic\":%d",e,authenticated.protected_frame,authenticated.duplicate,authenticated.opcode,authenticated.mic);
            if(e<0){a->reason="pair_rx";break;}
            if(!e){
                int64_t error=(int64_t)g.f.sample_index-sync;l->s.t0_ns+=sle_samples_to_ns(error,SLE_RT_FS);a->peer_frames++;
                a->last_peer_ms=(uint64_t)(sle_iio_now_ns()/1000000);
                previous_len=v->payload_len;previous_empty=v->conn_empty;have_prediction=1;
                log_event(a,"peer_event",",\"k\":%" PRId64 ",\"error_samples\":%" PRId64 ",\"deliver\":%d,\"acked\":%d",plan.k,error,out.deliver,out.acked);
                if(out.deliver && out.ptype==SLE_PTYPE_CTRL && out.len==13 && out.data[0]==10 && !out.data[1]){
                    if(sle_rt_queue(&a->store,l,SLE_PTYPE_CTRL,features,sizeof features)){a->reason="feature_queue";break;}
                }
                if(out.deliver && out.ptype==SLE_PTYPE_CTRL && out.len==8 && out.data[0]==13 && !out.data[1]){
                    if(sle_rt_queue(&a->store,l,SLE_PTYPE_CTRL,version,sizeof version)){a->reason="version_queue";break;}
                }
                if(out.deliver && out.ptype==SLE_PTYPE_DATA && out.len && sle_sdu_rx_feed(&a->sdu,out.data,out.len,on_sdu,a)){a->reason="sdu_reassembly";break;}
                if(a->reason)break;
            }
        }else{
            sle_link_rx_t rx={.kind=SLE_RX_NONE};sle_link_rx_out_t out;sle_link_on_rx(l,&rx,&out);
            log_event(a,"event_miss",",\"k\":%" PRId64,plan.k);
        }
        a->events++;phase=sending?0:(have_prediction?1:0);
        if(establish_failed(a))break;
        uint64_t now=(uint64_t)(sle_iio_now_ns()/1000000);
        if(!opt.interactive && !l->down && !a->reason && sle_t_runtime_encrypted(&a->crypto) && a->crypto.encrypted_ms &&
           now-a->crypto.encrypted_ms>=10000 && now-a->last_peer_ms<=100 &&
           a->ssap.writes && a->notified==4 && a->crypto.protected_tx_acked>=7 &&
           !a->crypto.mic_failed && !a->sdu.pending && !a->txq_len && !l->q_len && !l->cq_len &&
           !a->crypto.pair.count && !l->arq.has_cur){
            a->reason="protected_server_business";return 0;
        }
    }
    return -1;
}
static int readvertise_allowed(const t_app *a)
{
    return !interrupted && a->reason && !strcmp(a->reason,"connection_establish_failed") &&
           a->readvertises<SLE_T_READVERTISE_LIMIT;
}
/* Fresh session state for another advertising round within the attempt:
 * the same resets as an attempt start, without touching radio or mapping. */
static int session_reset(t_app *a)
{
    const char *why=a->reason; a->reason=NULL;
    a->crypto_ready=0;
    if(sle_t_runtime_destroy(&a->crypto)){a->reason="worker_join";a->worker_unjoined=1;return -1;}
    sle_rt_wipe(&a->store,sizeof a->store);txq_clear(a);sle_sdu_rx_init(&a->sdu,(size_t)opt.local_mtu+4);sle_ssap_server_init(&a->ssap,(uint16_t)opt.local_mtu);
    if(sle_t_runtime_init_variant(&a->crypto,a->local,0,opt.pair_variant)){a->reason="pair_init";return -1;}
    a->crypto_ready=1;
    a->peer_frames=a->events=0;a->ready_emitted=a->notified=0;a->discovered_ms=a->notify_ms=a->last_peer_ms=0;
    a->pair_state=-1;a->adv_miss_run=0;a->readvertises++;
    a->deadline=sle_iio_now_ns()+(int64_t)SLE_T_READVERTISE_SECONDS*1000000000;
    log_event(a,"readvertise",",\"n\":%u,\"limit\":%d,\"after\":\"%s\",\"scan_seconds\":%d,\"rx_head\":%" PRId64,
        a->readvertises,SLE_T_READVERTISE_LIMIT,why,SLE_T_READVERTISE_SECONDS,(int64_t)atomic_load(&a->r.rx_head));
    return 0;
}
static int connection(t_app *a)
{
    int result=-1;
    sle_conn_sched_t s;if(sle_conn_sched_init(&s,sle_samples_to_ns(a->request_sample,SLE_RT_FS),&a->txi)){a->reason="schedule_invalid";return -1;}
    sle_link_t *l=calloc(1,sizeof *l);if(!l){a->reason="allocation";return -1;}
    sle_link_init(l,SLE_LINK_ROLE_T,&s,a->txi.first_crc_init);
    log_schedule(a,&s);
    a->link=l;
    if(sle_t_runtime_bind(&a->crypto,a->peer,s.sync32)){a->reason="pair_bind";free(l);a->link=NULL;return -1;}
    {   /* Like 1.10.108 gle_tm_lcid_init: our own CMTC request on link creation. */
        uint8_t req[SLE_CMTC_REQ_SDU_LEN];size_t rn;
        if(sle_cmtc_capability_request(0,req,sizeof req,&rn) || queue_sdu(a,req,rn)){a->reason="cmtc_failed";return -1;}
        log_event(a,"cmtc_capability_req_queued",",\"identifier\":0,\"bitmap\":%u",SLE_CMTC_BITMAP);
    }
    const uint8_t features[]={0x0b,0,10,1,0,0,0,0,0,0,0,0,0};
    a->deadline=sle_iio_now_ns()+(int64_t)(opt.interactive ? 86400:opt.connect_seconds)*1000000000;
    if(opt.predictive){result=predictive_loop(a,l);goto done;}
    while(alive(a)){
        if(sle_t_runtime_queue(&a->crypto,&a->store,l) || business(a) || tx_pump(a)){if(!a->reason)a->reason="protocol_queue";break;}
        sle_link_tx_t plan;if(sle_link_t_listen(l,sle_samples_to_ns(sle_rt_radio_now(&a->r),SLE_RT_FS),6000000,&plan)){a->reason="link_down";break;}
        log_event_plan(a,&plan);
        int64_t sync=sle_ns_to_samples(plan.ev.t_ns,SLE_RT_FS);
        if(tune(a,plan.ev.mhz))break;
        sle_rt_command c={.mhz=plan.ev.mhz,.seed=plan.ev.white_seed,.connect=1,.lid=s.lid,.crc=l->crc_init,.estimate_cfo=1,.rx_start=sync-US(100),.rx_end=sync+US(4000)};
        if(issue(a,&c))break;
        sle_rt_received f;int got=0;
        while(alive(a) && atomic_load(&a->r.rx_head)<sync+US(3500)){
            if(!frame(a,c.seq,&f)){nap();continue;}
            const sle_frame_t *v=&f.f.frame;
            if(!v->kind || !v->crc12_ok || (!v->conn_empty && !v->crc24_ok) || llabs((int64_t)f.f.sample_index-sync)>US(100))continue;
            int64_t error=(int64_t)f.f.sample_index-sync;
            sle_link_rx_t rx={.kind=SLE_RX_OK,.empty=v->conn_empty,.sn=v->conn_sn,.nesn=v->conn_nesn,.ptype=v->conn_pkt_type,.data=v->payload,.len=(uint16_t)v->payload_len};
            sle_link_rx_out_t out;sle_rt_rx authenticated;
            int pe=sle_t_runtime_rx(&a->crypto,l,&rx,&out,&authenticated,(uint64_t)(sle_iio_now_ns()/1000000));
            log_event(a,"crypto_rx",",\"error\":%d,\"protected\":%d,\"duplicate\":%d,\"opcode\":%u,\"mic\":%d",pe,authenticated.protected_frame,authenticated.duplicate,authenticated.opcode,authenticated.mic);
            if(pe<0){a->reason="pair_rx";goto done;}
            if(pe)continue;
            got=1;a->peer_frames++;
            l->s.t0_ns+=sle_samples_to_ns(error,SLE_RT_FS);sync=(int64_t)f.f.sample_index;
            if(out.deliver && out.ptype==SLE_PTYPE_DATA && out.len && sle_sdu_rx_feed(&a->sdu,out.data,out.len,on_sdu,a)){a->reason="sdu_reassembly";goto done;}
            if(a->reason)goto done;
            if(out.deliver && out.ptype==SLE_PTYPE_CTRL && out.len==13 && out.data[0]==10 && !out.data[1]) {
                if(sle_link_push(l,SLE_PTYPE_CTRL,features,sizeof features)){a->reason="feature_queue";goto done;}
            }
            log_event(a,"peer_event",",\"k\":%" PRId64 ",\"error_samples\":%" PRId64 ",\"deliver\":%d,\"acked\":%d",plan.k,error,out.deliver,out.acked);
            if(sle_t_runtime_queue(&a->crypto,&a->store,l)){a->reason="pair_queue";goto done;}
            sle_link_tx_t tx;if(sle_link_t_reply(l,&tx))break;
            if(sle_t_runtime_tx(&a->crypto,&tx)){a->reason="pair_tx";goto done;}
            /* Earliest eligible grid point after ARM/DMA lead. This is kept
             * explicit in logs and must be tested against the official G. */
            uint8_t bits[2048];size_t nb=sle_link_encode(l,&tx,bits,sizeof bits);
            c=(sle_rt_command){.mhz=plan.ev.mhz,.seed=plan.ev.white_seed,.connect=1,.lid=s.lid,.crc=l->crc_init};
            if(!nb || sle_t_modulate(&c.wave,bits,nb)){a->reason="modulation";goto done;}
            int64_t slot=US(sle_sched_slot_us(a->txi.sched_slot));
            int64_t earliest=sle_rt_radio_now(&a->r)+US(opt.reply_delay_us);
            int64_t minimum=sync+sle_ns_to_samples(sle_second_sender_offset_ns(&l->s,v->payload_len,v->conn_empty),SLE_RT_FS);
            if(earliest<minimum)earliest=minimum;
            int64_t target=sync+((earliest-sync+slot-1)/slot)*slot;
            c.rx_start=target-US(50);c.rx_end=target+US(1600);
            if(tx_at(a,&c,target))goto done;
            if(sle_t_runtime_submitted(&a->crypto,&tx)){a->reason="pair_submitted";goto done;}
            log_event(a,"t_reply",",\"k\":%" PRId64 ",\"delay_us\":%.2f,\"conditional\":true,\"len\":%u",plan.k,(target-sync)/4.0,tx.len);
            if(wait_sample(a,target+US(1000)))goto done;
            break;
        }
        a->events++;
        if(!got){sle_link_rx_t rx={.kind=SLE_RX_NONE};sle_link_rx_out_t out;sle_link_on_rx(l,&rx,&out);log_event(a,"event_miss",",\"k\":%" PRId64,plan.k);}
        if(establish_failed(a))break;
    }
done:
    {uint64_t now=(uint64_t)(sle_iio_now_ns()/1000000);
    log_event(a,"acceptance",",\"stage_achieved\":%s,\"encrypted\":%s,\"encrypted_ms\":%" PRIu64 ",\"hold_ms\":%" PRIu64 ",\"writes\":%" PRIu64 ",\"notifications\":%d,\"protected_tx_acked\":%" PRIu64 ",\"mic_failed\":%" PRIu64 ",\"sdu_pending\":%d,\"predictive\":%s",result==0?"true":"false",sle_t_runtime_encrypted(&a->crypto)?"true":"false",a->crypto.encrypted_ms,a->crypto.encrypted_ms?now-a->crypto.encrypted_ms:0,a->ssap.writes,a->notified,a->crypto.protected_tx_acked,a->crypto.mic_failed,a->sdu.pending,opt.predictive?"true":"false");}
    log_event(a,"sdu_rx_end",",\"pending\":%d,\"bytes\":%zu",a->sdu.pending,a->sdu.len);
    sle_sdu_rx_init(&a->sdu,0);
    log_event(a,"pair_final",",\"mic_probe\":%d,\"rx_next\":%" PRIu64 ",\"state\":%d,\"error\":%d,\"mic_ok\":%" PRIu64 ",\"mic_failed\":%" PRIu64 ",\"protected_tx_acked\":%" PRIu64 ",\"writes\":%" PRIu64,a->crypto.pair.mic_probe,(uint64_t)a->crypto.pair.rx_next,a->crypto.pair.state,a->crypto.error,a->crypto.mic_ok,a->crypto.mic_failed,a->crypto.protected_tx_acked,a->ssap.writes);
    a->link=NULL;
    free(l);return result;
}
/* 1: valid options, 0: help, 2: invalid CLI. No device access. */
static int parse(int argc,char **argv)
{
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--help")){puts("sle_tnode --log PATH --seconds N --connect-seconds N --attempts N --reply-mode delayed|predictive (default predictive) --reply-delay-us N --notify-prefix TEXT --resource-layout standard|legacy-ws63 (default standard) --pair-variant 0x300|0x200 (default 0x200: 1.10.108 AES-CMAC session key) --tx-gain DB --rx-gain DB --hw-status 0|1 --hw-prio N (default 0=OTHER) --hw-period-us N (default 200) --cal-depth N (TX blocks while calibrating, default 6, 3..16) --local-mtu N (SSAP MTU, default 520 = the official client's request) --tx-frag N (SDU record data bytes, default 24 as WS63) --notify-len N (0 short text; 32..512 deterministic padded values) --interactive 0|1 (typed lines become notifications, received writes are printed live, no business exit)");return 0;}
        if(i+1==argc)return 2;
        const char *k=argv[i++],*v=argv[i];
        if(!strcmp(k,"--log"))opt.log=v;else if(!strcmp(k,"--seconds"))opt.seconds=atoi(v);
        else if(!strcmp(k,"--reply-mode")){if(!strcmp(v,"predictive"))opt.predictive=1;else if(!strcmp(v,"delayed"))opt.predictive=0;else return 2;}
        else if(!strcmp(k,"--notify-prefix")){if(!*v || strlen(v)>16)return 2;for(const char *p=v;*p;p++)if(!((*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='-'))return 2;opt.notify_prefix=v;}
        else if(!strcmp(k,"--pair-variant")){char *e;unsigned long x=strtoul(v,&e,0);if(*e || (x!=SLE_PAIR_PROFILE_WS63 && x!=SLE_PAIR_V_COUNT_PLAIN))return 2;opt.pair_variant=(unsigned)x;}
        else if(!strcmp(k,"--resource-layout")){if(!strcmp(v,"standard"))opt.resource_layout=SLE_RESOURCE_STANDARD;else if(!strcmp(v,"legacy-ws63"))opt.resource_layout=SLE_RESOURCE_LEGACY_WS63;else return 2;}
        else if(!strcmp(k,"--connect-seconds"))opt.connect_seconds=atoi(v);else if(!strcmp(k,"--attempts"))opt.attempts=atoi(v);
        else if(!strcmp(k,"--reply-delay-us"))opt.reply_delay_us=atoi(v);
        else if(!strcmp(k,"--hw-status"))opt.hw_status=atoi(v);
        else if(!strcmp(k,"--cal-depth"))opt.cal_depth=atoi(v);
        else if(!strcmp(k,"--local-mtu"))opt.local_mtu=atoi(v);else if(!strcmp(k,"--tx-frag"))opt.tx_frag=atoi(v);else if(!strcmp(k,"--notify-len"))opt.notify_len=atoi(v);else if(!strcmp(k,"--interactive"))opt.interactive=atoi(v);
        else if(!strcmp(k,"--hw-prio"))opt.hw_prio=atoi(v);else if(!strcmp(k,"--hw-period-us"))opt.hw_period_us=atoi(v);
        else if(!strcmp(k,"--tx-gain"))opt.tx_gain=atof(v);else if(!strcmp(k,"--rx-gain"))opt.rx_gain=atof(v);else return 2;
    }
    if(opt.seconds<1 || opt.seconds>120 || opt.connect_seconds<1 || opt.connect_seconds>120 || opt.attempts<1 || opt.attempts>10 || opt.reply_delay_us<500 || opt.reply_delay_us>5000 || opt.tx_gain>0 || opt.tx_gain< -80 || opt.rx_gain<0 || opt.rx_gain>73 ||
       (opt.hw_status!=0 && opt.hw_status!=1) || opt.hw_prio<0 || opt.hw_prio>=80 || opt.hw_period_us<20 || opt.hw_period_us>1000 ||
       opt.cal_depth<SLE_RT_ACCESS_DEPTH || opt.cal_depth>SLE_RT_TX_BUFFERS ||
       opt.local_mtu<23 || opt.local_mtu>1024 || opt.tx_frag<8 || opt.tx_frag>(int)SLE_RT_TX_MAX-6 ||
       (opt.interactive!=0 && opt.interactive!=1) || (opt.notify_len && (opt.notify_len<32 || opt.notify_len>(int)SLE_SSAP_SERVER_VALUE_MAX || opt.notify_len+6>opt.local_mtu)))return 2;
    return 1;
}
int main(int argc,char **argv)
{
    int parsed=parse(argc,argv);
    if(parsed!=1)return parsed;
    if(opt.hw_status){hw=calloc(1,sizeof *hw);if(!hw || sle_rt_hwstat_open(hw)){fprintf(stderr,"hw-status: /dev/mem map or core version check failed\n");free(hw);return 2;}}
    t_app *a=calloc(1,sizeof *a);if(!a)return 1;a->journal=calloc(1,JOURNAL);if(!a->journal){free(a);return 1;}
    const uint8_t local[6]={0xc2,0x53,0x4c,0x45,0,0x20};memcpy(a->local,local,6);
    FILE *log=fopen(opt.log,"a");if(!log){free(a->journal);free(a);return 1;}
    a->output=log;
    struct sigaction sa={.sa_handler=stop_signal};sle_rt_stop_signals(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL);sigaction(SIGTERM,&sa,NULL);sigaction(SIGHUP,&sa,NULL);sigaction(SIGPIPE,&sa,NULL);
    int rc=1;
    sle_t_wave_init();
    if(sle_iio_realtime(0,60))goto out;
    for(a->attempt=1;a->attempt<=(unsigned)opt.attempts && !interrupted;a->attempt++){
        int timing_ready=0;
        a->reason=NULL;a->peer_frames=a->events=0;a->deadline=sle_iio_now_ns()+(int64_t)opt.seconds*1000000000;
        a->ready_emitted=a->notified=0;a->cal_restarts=a->adv_miss_run=a->adv_misses=a->readvertises=0;a->discovered_ms=a->notify_ms=a->last_peer_ms=0;a->pair_state=-1;
        sle_rt_wipe(&a->store,sizeof a->store);txq_clear(a);sle_sdu_rx_init(&a->sdu,(size_t)opt.local_mtu+4);sle_ssap_server_init(&a->ssap,(uint16_t)opt.local_mtu);
        if(sle_t_runtime_init_variant(&a->crypto,a->local,0,opt.pair_variant)){a->reason="pair_init";goto finish;}
        a->crypto_ready=1;
        log_event(a,"attempt_start",",\"role\":\"T\",\"local\":\"c2:53:4c:45:00:20\",\"tx_gain\":%.2f,\"reply_delay_us\":%d",opt.tx_gain,opt.reply_delay_us);
        log_event(a,"config",",\"predictive\":%s,\"fs\":%d,\"tx_blocks\":16,\"cal_tx_blocks\":%d,\"req_offset_us\":2500,\"rsp_offset_us\":%d,\"local_mtu\":%d,\"tx_frag\":%d,\"notify_len\":%d,\"notify_prefix\":\"%s\",\"hold_ms\":10000,\"rng\":\"OS\",\"debug_keys\":false,\"resource_layout\":\"%s\",\"pair_variant\":%u",opt.predictive?"true":"false",SLE_RT_FS,opt.cal_depth,ACCESS_RSP_US,opt.local_mtu,opt.tx_frag,opt.notify_len,opt.notify_prefix,resource_layout_name(opt.resource_layout),opt.pair_variant);
        if(sle_rt_radio_setup(opt.tx_gain,opt.rx_gain)){a->reason="setup";goto finish;}
        int hw_running=0;
        if(hw){if(sle_rt_hwstat_start(hw,&a->r,0,opt.hw_prio,(int64_t)opt.hw_period_us*1000)){a->reason="hw_status_start";goto finish;}
            else{hw_running=1;log_event(a,"hw_status_started",",\"cpu\":0,\"prio\":%d,\"period_us\":%d,\"dac_initial\":%u,\"adc_initial\":%u,\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64,opt.hw_prio,opt.hw_period_us,hw->dac_initial,hw->adc_initial,(int64_t)atomic_load(&a->r.rx_head),(int64_t)atomic_load(&a->r.tx_head));}}
        log_event(a,"radio_start_call",",\"mono_before_ns\":%" PRId64,sle_iio_now_ns());
        if(sle_rt_radio_start(&a->r,1,80)){a->reason="radio_start";if(hw_running){sle_rt_hwstat_stop(hw);hw_running=0;}goto finish;}
        log_event(a,"radio_started",",\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64,(int64_t)atomic_load(&a->r.rx_head),(int64_t)atomic_load(&a->r.tx_head));
        if(!a->reason && !calibrate(a)){
            for(;;){
                if(advertise(a))break;
                if(!connection(a)){rc=0;break;}
                if(!readvertise_allowed(a) || session_reset(a))break;
            }
        }
        if(hw_running){if(sle_rt_hwstat_stop(hw)){a->reason="hw_status_stop";rc=1;}hw_running=0;}
        if(sle_rt_radio_stop(&a->r)){a->reason="radio_stop";rc=1;}
        if(hw){char path[4096];snprintf(path,sizeof path,"%s.a%u.hw.jsonl",opt.log,a->attempt);FILE *f=fopen(path,"w");int err=!f||sle_rt_hwstat_write(hw,f,(int)a->attempt);if(f&&fclose(f))err=1;
            log_event(a,"hw_status",",\"path\":\"%s\",\"polls\":%" PRIu64 ",\"max_gap_ns\":%" PRId64 ",\"dac_hits\":%" PRIu64 ",\"adc_hits\":%" PRIu64 ",\"events\":%" PRIu64 ",\"dropped\":%" PRIu64 ",\"start_ns\":%" PRId64 ",\"end_ns\":%" PRId64 ",\"write_error\":%d",
                path,hw->polls,hw->max_gap_ns,hw->dac_hits,hw->adc_hits,hw->n_events,hw->dropped,hw->start_ns,hw->end_ns,err);
            hw->n_events=hw->dropped=hw->polls=hw->dac_hits=hw->adc_hits=0;hw->max_gap_ns=0;}
        timing_ready=1;
        log_event(a,"radio_stats",",\"max_lag_ns\":%" PRId64 ",\"max_work_ns\":%" PRId64 ",\"rx_blocks\":%" PRIu64 ",\"tx_blocks\":%" PRIu64,a->r.rx_stats[SLE_RT_RX_WINDOW].max_lag_ns,a->r.rx_stats[SLE_RT_RX_WINDOW].max_work_ns,a->r.n_rx,a->r.n_tx);
        {
            const sle_rt_rx_stats *s=&a->r.rx_stats[SLE_RT_RX_CAL]; char h[SLE_RT_DRAIN_LOG*48+3]; size_t n=0; h[n++]='[';
            for(uint64_t i=0;i<a->r.tx_drain_unguarded && i<SLE_RT_DRAIN_LOG;i++)
                n+=(size_t)snprintf(h+n,sizeof h-n,"%s[%" PRId64 ",%" PRId64 "]",i?",":"",a->r.tx_drain_head[i],a->r.tx_drain_rx_head[i]);
            snprintf(h+n,sizeof h-n,"]");
            log_event(a,"tx_drain",",\"unguarded\":%" PRIu64 ",\"tx_rx_heads\":%s,\"cal_max_lag_ns\":%" PRId64 ",\"cal_max_lag_sample\":%" PRId64 ",\"cal_max_work_ns\":%" PRId64 ",\"cal_max_work_sample\":%" PRId64,
                a->r.tx_drain_unguarded,h,s->max_lag_ns,s->max_lag_sample,s->max_work_ns,s->max_work_sample);
        }
finish:
        a->crypto_ready=0;
        if(a->worker_unjoined || sle_t_runtime_destroy(&a->crypto)){a->reason="worker_join";a->worker_unjoined=1;rc=1;break;}
        log_event(a,"attempt_end",",\"reason\":\"%s\",\"events\":%u,\"peer_frames\":%u,\"stage_achieved\":%s,\"readvertises\":%u",a->reason?a->reason:"incomplete",a->events,a->peer_frames,rc==0?"true":"false",a->readvertises);
        if(fwrite(a->journal,1,a->used,log)!=a->used ||
            (timing_ready && sle_rt_radio_timing_write(&a->r,log,a->attempt)) || fflush(log)){rc=1;break;}
        a->used=0;fprintf(stderr,"attempt %u: %s events=%u peer=%u\n",a->attempt,a->reason?a->reason:"incomplete",a->events,a->peer_frames);
        if(!rc)break;
    }
out:
    {int e=sle_rt_radio_restore();if(fprintf(log,"{\"kind\":\"cleanup\",\"restore_result\":%d}\n",e)<0 || e)rc=1;}
    if(fclose(log))rc=1;
    if(hw){sle_rt_hwstat_close(hw);free(hw);}
    if(!a->worker_unjoined){free(a->journal);free(a);}
    return rc;
}
