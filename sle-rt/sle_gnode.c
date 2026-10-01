/* radio E310 G-node experiment, O4/O5 WS63 profile. See --help for staged runs.
 * CPU0: control, sysfs, modulation, in-memory journal. CPU1: mmap DMA copies,
 * command mailbox, sample-domain renderer, gated demodulator (no file I/O).
 * Optional low-volume orchestration events are written on CPU0, not the DMA thread.
 * Live acceptance requires an actual WS63 response and subsequent peer frames.
 * Selftest is strictly offline and never counts as interoperability evidence.
 */
#define _GNU_SOURCE
#include "sle_radio.h"
#include "sle_hwstat.h"
#include "sle_ssap.h"
#include "sle_sdu.h"
#include "sle_g_runtime.h"
#include "sle_cmtc.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define SAMPLES_US(us) ((int64_t)(us)*4)
#define LOG_CAP (32u*1024u*1024u)
#define LOG_TAIL 4096u /* reserved for stopping/end after ordinary journal capacity */
#define EVENT_CAP (256u*1024u)
#define CAL_TTL (SLE_RT_FS/4)
#define RETUNE_LEAD SAMPLES_US(4500)
#define TX_GUARD SLE_RT_TX_GUARD
#define PEER_FRESH_NS 100000000LL /* eight nominal events */
#define CFO_TTL (SLE_RT_FS/4)
#define CFO_CHANGE_HZ 2000.0 /* cache reuse limit, NOT estimator accuracy */
#define EMPTY_SAMPLES 512
#define SLE_RT_WITNESS_MISS_LIMIT 3 /* consecutive events without local TX witness */
#define SLE_RT_WITNESS_MARGIN SAMPLES_US(500) /* bounded DMA/demod processing after frame end */

typedef struct { size_t n; int16_t iq[2*EMPTY_SAMPLES]; } empty_wave;
typedef struct {
    sle_rt_wave request[76];
    empty_wave base_empty[64][2], empty[64][2];
    int valid;
    double cfo;
    int64_t source_sample, ready_sample, build_ns;
} wave_cache;
typedef struct {
    const char *stage;
    int64_t mono, now, tx_slack, rx_slack, cal_sample;
    int submitted;
} slack_trace;

static volatile sig_atomic_t interrupted;
static void signal_stop(int s)
{
    if (!interrupted) interrupted=s;
}
static int install_signals(void)
{
    struct sigaction sa={.sa_handler=signal_stop}; sle_rt_stop_signals(&sa.sa_mask);
    const int signals[]={SIGINT,SIGTERM,SIGHUP,SIGPIPE};
    for (size_t i=0;i<sizeof signals/sizeof signals[0];i++)
        if (sigaction(signals[i],&sa,NULL)) return -1;
    return 0;
}
typedef struct {
    int attempts, seconds, connect_seconds, hold_seconds, cpu_rt, cpu_ctl, prio_rt, prio_ctl;
    int auto_cfo, mode, exclude_lo, exclude_hi, ssap_mtu, ssap_frame, pair;
    int hw_status, hw_prio, hw_period_us, hw_cpu, hw_dma, cal_depth, interactive;
    const char *ssap_write;
    sle_resource_layout_t resource_layout;
    unsigned pair_variant[100]; int pair_variants;
    double tx_gain, rx_gain, cfo, shift_us;
    const char *log, *event_log;
    uint8_t local[6], server[6];
    uint32_t lid, crc, slot;
} options;
static const char *resource_layout_name(sle_resource_layout_t layout)
{
    return layout == SLE_RESOURCE_STANDARD ? "standard" : "legacy-ws63";
}
static options opt = { .attempts=3, .seconds=60, .connect_seconds=15, .hold_seconds=10, .cpu_rt=1, .cpu_ctl=0,
    .prio_rt=80, .prio_ctl=60, .hw_prio=0, .hw_period_us=200, .cal_depth=SLE_RT_CAL_DEPTH, .tx_gain=-30, .rx_gain=30, .log="/tmp/sle_gnode.jsonl",
    .local={0xc2,0x53,0x4c,0x45,0,0x10}, .server={1,2,3,4,5,6},
    .pair=1, .resource_layout=SLE_RESOURCE_STANDARD,
    .lid=0x66a275, .crc=0xe4004c6e, .slot=0x00df488c };

typedef struct {
    char *log; size_t used; int log_full, attempt;
    FILE *event_output; int event_failed;
    sle_rt_radio *radio; sle_rt_peer peer; sle_rt_cal cal;
    sle_rt_wave *requests, calwave;
    wave_cache *cache;
    uint8_t request[84], marker[16];
    unsigned seq;
    double cfo;
    int64_t deadline, connected_ns, last_peer_ns;
    int connecting, request_submitted, command_submitted, cleanup_failed, access_timing_verified;
    int64_t primary_sample;
    int primary_pending;
    sle_rt_received selected_primary;
    sle_access_plan_t selected_plan;
    int64_t primary_mono, primary_now, copy_ns, cfo_age_samples;
    double cfo_delta;
    slack_trace slack[5];
    unsigned n_slack;
    unsigned events, received, valid_received, misses, skipped;
    const char *reason;
    sle_rt_hwstat *hw; int hw_open, hw_running;
    uint8_t probe[24]; int probe_queued;
    sle_rt_tx_store tx_store;
    sle_g_runtime *g_runtime;
    sle_pair_state_t pair_logged_state;
    int pair_logged_error;
    int ssap_state, ssap_validated, ssap_write_verified, ssap_failed;
    uint16_t prop_handle, peer_mtu;
    char chat[512]; size_t chat_len;
    int chat_dropping, chat_eof, chat_ready;
    uint8_t write_value[48]; size_t write_len;
    uint64_t write_deadline_ms;
    char *event_buffer; size_t event_used;
    int stdin_active, stdin_flags;
    int console_active, console_flags;
    size_t console_dropped;
    sle_sdu_rx sdu_rx;
} app;

/* The full journal stays in memory until the radio stops. A separate optional
 * file exposes only attempt boundaries (including stopping) and WRITE_RSP, so an external UART
 * producer can act during this connection without flushing the PHY journal.
 * Interactive mode defers this file too, using a bounded memory buffer.
 * Never write to this file from CPU1; errors make the experiment fail closed. */
#ifndef SLE_RT_EVENT_WRITE_FAULT
#define SLE_RT_EVENT_WRITE_FAULT(a,row,n) 0 /* offline fault injection only */
#endif
static void event_write(app *a, const char *row, size_t n)
{
    if (a->event_buffer) {
        if (a->event_failed) return;
        if (SLE_RT_EVENT_WRITE_FAULT(a,row,n) || a->event_used>EVENT_CAP || n>EVENT_CAP-a->event_used) {
            a->event_failed=1; return;
        }
        memcpy(a->event_buffer+a->event_used,row,n); a->event_used+=n;
        return;
    }
    if (a->event_output && !a->event_failed &&
        (SLE_RT_EVENT_WRITE_FAULT(a,row,n) ||
         fwrite(row,1,n,a->event_output)!=n || fflush(a->event_output)))
        a->event_failed=1;
}

static void recordv(app *a, int64_t mono, const char *kind, const char *fmt, va_list ap)
{
    int tail=!strcmp(kind,"attempt_stopping") || !strcmp(kind,"attempt_end");
    if (a->log_full && !tail) return;
    char row[8192];
    int n=snprintf(row,sizeof row,"{\"attempt\":%d,\"mono_ns\":%" PRId64 ",\"kind\":\"%s\"",
        a->attempt,mono,kind);
    int m=vsnprintf(row+n,sizeof row-(size_t)n,fmt,ap);
    if (m<0 || (size_t)m>=sizeof row-(size_t)n-3) { a->log_full=1; return; }
    n+=m; row[n++]='}'; row[n++]='\n';
    size_t limit=tail ? LOG_CAP : LOG_CAP-LOG_TAIL;
    if (a->used>limit || (size_t)n>limit-a->used) { a->log_full=1; return; }
    memcpy(a->log+a->used,row,(size_t)n); a->used+=(size_t)n;
    if (!strcmp(kind,"attempt_start") || !strcmp(kind,"ssap_write_rsp") ||
        tail) event_write(a,row,(size_t)n);
}
static void record(app *a, const char *kind, const char *fmt, ...)
{
    va_list ap; va_start(ap,fmt); recordv(a,sle_iio_now_ns(),kind,fmt,ap); va_end(ap);
}
static void record_at(app *a, int64_t mono, const char *kind, const char *fmt, ...)
{
    va_list ap; va_start(ap,fmt); recordv(a,mono,kind,fmt,ap); va_end(ap);
}
static int pair_service(app *a)
{
    if (!a->g_runtime) return 0;
    int e=sle_g_runtime_poll(a->g_runtime,(uint64_t)(sle_iio_now_ns()/1000000));
    sle_pair_status_t s; sle_pair_status(&a->g_runtime->pair,&s);
    if (s.state!=a->pair_logged_state || e!=a->pair_logged_error) {
        record(a,"pair_state",",\"state\":%d,\"error\":%d,\"detail\":\"%s\",\"secure\":%d,"
            "\"tx_next\":%" PRIu64 ",\"rx_next\":%" PRIu64 ",\"confirm_matches\":%d",
            s.state,e,sle_pair_error_string(e),s.secure,s.tx_next,s.rx_next,s.confirm_matches);
        a->pair_logged_state=s.state; a->pair_logged_error=e;

    }
    if (e) a->reason="pair_failed";
    return e;
}
static void rx_report(app *a)
{
    /* Called only after join: no shared statistics writes or RT formatting. */
    static const char *const mode[]={"scheduled_window","scan","calibration"};
    for (int i=0;i<SLE_RT_RX_MODES;i++) {
        const sle_rt_rx_stats *s=&a->radio->rx_stats[i];
        record(a,"rx_processing",",\"mode\":\"%s\",\"blocks\":%" PRIu64
            ",\"energy_blocks\":%" PRIu64 ",\"hot\":%" PRIu64 ",\"learning\":%" PRIu64
            ",\"fail_open\":%" PRIu64 ",\"pre_blocks\":%" PRIu64 ",\"post_blocks\":%" PRIu64
            ",\"demod_blocks\":%" PRIu64 ",\"demod_samples\":%" PRIu64 ",\"cold_deferred_blocks\":%" PRIu64
            ",\"muted_blocks\":%" PRIu64 ",\"power_samples\":%" PRIu64 ",\"adc_rail_samples\":%" PRIu64
            ",\"noise_power\":%.3f,\"peak_bin_power\":%.3f,\"frames\":%" PRIu64
            ",\"cfo_estimates\":%" PRIu64 ",\"cfo_unavailable\":%" PRIu64 ",\"history_errors\":%" PRIu64
            ",\"max_lag_ns\":%" PRId64 ",\"last_lag_ns\":%" PRId64
            ",\"max_rx_refill_ns\":%" PRId64 ",\"rx_refill_total_ns\":%" PRId64
            ",\"max_lag_sample\":%" PRId64 ",\"max_rx_refill_sample\":%" PRId64,
            mode[i],s->blocks,s->energy_blocks,s->hot,s->learning,s->fail_open,s->pre,s->post,
            s->demod_blocks,s->demod_samples,s->skipped,s->muted,s->sampled,s->clipped,
            s->floor_sum/256.0,s->peak_bin_sum/32.0,s->frames,s->cfo_estimates,s->cfo_unavailable,
            s->history_errors,s->max_lag_ns,s->last_lag_ns,s->max_work_ns,s->work_ns,
            s->max_lag_sample,s->max_work_sample);
    }
    const sle_rt_radio *r=a->radio; char h[SLE_RT_DRAIN_LOG*48+3]; size_t n=0; h[n++]='[';
    for (uint64_t i=0;i<r->tx_drain_unguarded && i<SLE_RT_DRAIN_LOG;i++)
        n+=(size_t)snprintf(h+n,sizeof h-n,"%s[%" PRId64 ",%" PRId64 "]",i?",":"",
            r->tx_drain_head[i],r->tx_drain_rx_head[i]);
    snprintf(h+n,sizeof h-n,"]");
    record(a,"tx_drain",",\"unguarded\":%" PRIu64 ",\"tx_rx_heads\":%s",r->tx_drain_unguarded,h);
}
static void rf_ports(app *a)
{
    /* Diagnostic read only; routing remains the user's existing setting. */
    const char *path[]={SLE_IIO_PHY "in_voltage0_rf_port_select",SLE_IIO_PHY "out_voltage0_rf_port_select"};
    char value[2][64]={{0}};
    for (int i=0;i<2;i++) {
        if (sle_iio_read(path[i],value[i],sizeof value[i]) || !value[i][0]) strcpy(value[i],"unavailable");
        for (char *p=value[i];*p;p++)
            if (!((*p>='A' && *p<='Z') || (*p>='a' && *p<='z') || (*p>='0' && *p<='9') || *p=='_')) *p='_';
    }
    record(a,"rf_ports",",\"rx\":\"%s\",\"tx\":\"%s\",\"read_only\":true",value[0],value[1]);
}
static int journal_failed(app *a)
{
    if (a->event_failed) a->reason="event_journal_write";
    else if (a->log_full) a->reason="journal_capacity";
    else return 0;
    return 1;
}
static int live(app *a)
{
    if (interrupted) a->reason="signal";
    else if (a->log_full) a->reason="journal_capacity";
    else if (a->event_failed) a->reason="event_journal_write";
    else if (atomic_load(&a->radio->error)) a->reason=sle_rt_io_error_name(atomic_load(&a->radio->error));
    else if (sle_iio_now_ns()>a->deadline)
        a->reason=a->connecting ? "connection_budget_exhausted" : "attempt_budget_exhausted";
    else if (pair_service(a)) return 0;
    else return 1;
    return 0;
}
static void pause_ctl(void) { struct timespec t={0,50000}; nanosleep(&t,NULL); }
#ifndef SLE_RT_WAIT_HOOK
#define SLE_RT_WAIT_HOOK() pause_ctl() /* app test advances its fake clock */
#endif
static int wait_rx(app *a, int64_t sample)
{
    while (atomic_load(&a->radio->rx_head)<sample) { if (!live(a)) return -1; pause_ctl(); }
    return live(a) ? 0 : -1;
}
static int issue_with_timeout(app *a, sle_rt_command *c, int64_t timeout_ns)
{
    a->command_submitted=0;
    if (!live(a)) return -1;
    c->seq=++a->seq;
    if (!c->seq) c->seq=++a->seq;
    int64_t deadline=sle_iio_now_ns()+timeout_ns;
    int e=sle_rt_radio_submit(a->radio,c);
    if (!e) {
        a->command_submitted=1;
        for (;;) {
            if (!live(a) || sle_iio_now_ns()>deadline) {
                if (!interrupted && !atomic_load(&a->radio->error) && !a->log_full &&
                    sle_iio_now_ns()<=a->deadline) a->reason="command_ack_timeout";
                /* Acceptance is unknown: DMA may already contain the burst.
                 * Stop the device before journalling or returning to caller. */
                int stopped=sle_rt_radio_stop(a->radio);
                if (stopped) a->cleanup_failed=1;
                record(a,"command_aborted",",\"seq\":%u,\"reason\":\"%s\","
                    "\"tx_may_have_run\":%s,\"stop_result\":%d",c->seq,a->reason,
                    c->wave.n ? "true":"false",stopped);
                return -1;
            }
            if (atomic_load_explicit(&a->radio->ack_seq,memory_order_acquire)==c->seq) break;
            pause_ctl();
        }
        e=atomic_load(&a->radio->ack_result);
    }
    record(a,"command",",\"seq\":%u,\"result\":\"%s\",\"mhz\":%d,\"seed\":%d,"
        "\"tx_start\":%" PRId64 ",\"wave_samples\":%zu,\"rx_start\":%" PRId64 ",\"rx_end\":%" PRId64,
        c->seq,sle_rt_result_name(e),c->mhz,c->seed,c->tx_start,c->wave.n,c->rx_start,c->rx_end);
    if (e || !live(a)) {
        if (e) a->reason=sle_rt_result_name(e);
        int stopped=sle_rt_radio_stop(a->radio);
        if (stopped) a->cleanup_failed=1;
        record(a,"command_stopped",",\"seq\":%u,\"tx_may_have_run\":%s,\"stop_result\":%d",
            c->seq,!e && c->wave.n ? "true":"false",stopped);
        return -1;
    }
    return e ? -1 : 0;
}
static int issue(app *a, sle_rt_command *c) { return issue_with_timeout(a,c,20000000); }
static int tune(app *a, int tx, int mhz)
{
    int64_t start=sle_iio_now_ns();
    int e=sle_rt_radio_retune(tx,mhz);
    record(a,"retune",",\"tx\":%d,\"mhz\":%d,\"elapsed_ns\":%" PRId64 ",\"result\":%d"
        ",\"rx_head_after\":%" PRId64 ",\"tx_head_after\":%" PRId64,
        tx,mhz,sle_iio_now_ns()-start,e,(int64_t)atomic_load(&a->radio->rx_head),
        (int64_t)atomic_load(&a->radio->tx_head));
    if (e) a->reason="retune_failed";
    return e || !live(a) ? -1 : 0;
}
static void frame_record(app *a, unsigned seq, const sle_rt_received *r, int64_t mono)
{
    char hex[2*SLE_MAX_CONNECT_PAYLOAD_BYTES+1];
    size_t n=r->f.frame.payload_len;
    static const char digits[]="0123456789abcdef";
    for (size_t i=0;i<n;i++) {
        hex[2*i]=digits[r->f.frame.payload[i]>>4]; hex[2*i+1]=digits[r->f.frame.payload[i]&15];
    }
    hex[2*n]=0;
    record_at(a,mono,"frame",",\"seq\":%u,\"sample\":%" PRIu64 ",\"mhz\":%d,\"seed\":%u,"
        "\"a2\":%d,\"ptype\":%u,\"empty\":%u,\"sn\":%u,\"nesn\":%u,\"crc12\":%d,"
        "\"crc24\":%d,\"has_crc24\":%d,\"payload\":\"%s\",\"stale\":%d",
        r->seq,r->f.sample_index,r->f.channel_mhz,r->f.frame.seed,r->f.frame.kind,
        r->f.frame.kind ? r->f.frame.conn_pkt_type : r->f.frame.packet_type,
        r->f.frame.conn_empty,r->f.frame.conn_sn,r->f.frame.conn_nesn,
        r->f.frame.crc12_ok,r->f.frame.crc24_ok,r->f.frame.has_crc24,hex,r->seq!=seq);
}
static int read_frame(app *a, unsigned seq, sle_rt_received *r, int log_current)
{
    while (!sle_rt_ring_pop(&a->radio->frames,r)) {
        if (r->f.frame.payload_len>sizeof r->f.frame.payload) { a->reason="frame_bounds"; return -1; }
        if (log_current || r->seq!=seq) frame_record(a,seq,r,sle_iio_now_ns());
        if (r->seq==seq) return 1;
    }
    return 0;
}
static int next_frame(app *a, unsigned seq, sle_rt_received *r) { return read_frame(a,seq,r,1); }

static int cache_build(app *a, double cfo, int64_t source_sample)
{
    wave_cache *b=a->cache;
    b->valid=0;
    if (!isfinite(cfo) || fabs(cfo)>200000) return -1;
    int64_t start=sle_iio_now_ns();
    for (int seed=0;seed<76;seed++) {
        sle_rt_rotate(&b->request[seed],&a->requests[seed],cfo);
        if (!b->request[seed].n || interrupted) return -1;
    }
    sle_rt_wave base={0}, rotated={0};
    for (int seed=0;seed<64;seed++) for (int nesn=0;nesn<2;nesn++) {
        const empty_wave *src=&b->base_empty[seed][nesn];
        base.n=src->n; memcpy(base.iq,src->iq,src->n*4);
        sle_rt_rotate(&rotated,&base,cfo);
        if (!rotated.n || rotated.n>EMPTY_SAMPLES || interrupted) return -1;
        empty_wave *dst=&b->empty[seed][nesn]; dst->n=rotated.n;
        memcpy(dst->iq,rotated.iq,rotated.n*4);
    }
    b->cfo=cfo; b->source_sample=source_sample;
    b->build_ns=sle_iio_now_ns()-start;
    b->ready_sample=source_sample<0 ? -1:sle_rt_radio_now(a->radio);
    b->valid=1;
    record(a,"wave_cache_build",",\"cfo_hz\":%.3f,\"source_sample\":%" PRId64
        ",\"ready_sample\":%" PRId64 ",\"elapsed_ns\":%" PRId64
        ",\"request_channels\":76,\"empty_variants\":128,\"auto\":%s",
        cfo,source_sample,b->ready_sample,b->build_ns,source_sample<0 ? "false":"true");
    return 0;
}
static int prepare_waves(app *a)
{
    size_t n=sle_access_request_build(a->peer.local,a->peer.server,&a->peer.txi,&a->peer.req,
        a->request,sizeof a->request);
    if (n!=84) return -1;
    uint8_t bits[1024];
    for (int c=0;c<76;c++) {
        size_t nb=sle_access_encode_frame(bits,sizeof bits,a->request,n,(uint8_t)c,1,4);
        if (!nb || sle_rt_modulate(&a->requests[c],bits,nb,0)) return -1;
    }
    sle_rt_wave empty;
    for (int seed=0;seed<64;seed++) for (int nesn=0;nesn<2;nesn++) {
        sle_connect_config_t cfg={a->peer.txi.first_lid,(uint8_t)(64+seed),SLE_CRC_TYPE_24,a->peer.txi.first_crc_init,0};
        size_t nb=sle_encode_connect_config(bits,sizeof bits,NULL,0,&cfg,SLE_PTYPE_DATA,1,0,(uint8_t)nesn,0,0,0);
        if (!nb || sle_rt_modulate(&empty,bits,nb,0) || empty.n>EMPTY_SAMPLES) return -1;
        empty_wave *dst=&a->cache->base_empty[seed][nesn]; dst->n=empty.n;
        memcpy(dst->iq,empty.iq,empty.n*4);
    }
    if (!opt.auto_cfo && cache_build(a,opt.cfo,-1)) return -1;
    /* Nonconnectable diagnostic broadcast, unique to this process run. It is
     * decoded through RF leakage, never inserted into the receive path. */
    /* Retained calibration payload bytes; not a public phase identifier. */
    memcpy(a->marker,"P4CAL",5); memcpy(a->marker+5,a->peer.local,6);
    uint64_t nonce=(uint64_t)sle_iio_now_ns()^(uint64_t)getpid();
    for (int i=0;i<5;i++) a->marker[11+i]=(uint8_t)(nonce>>(8*i));
    size_t nb=sle_access_encode_frame(bits,sizeof bits,a->marker,sizeof a->marker,77,0,0);
    return !nb || sle_rt_modulate(&a->calwave,bits,nb,0) ? -1 : 0;
}
/* Failed witness updates also clear the mapping. Preserve the rejected
 * measurement and the stable run before observing; successful event updates
 * incur no extra timestamp or journal formatting. */
static int observe_cal(app *a, int64_t tx, int64_t rx)
{
    sle_rt_cal before=a->cal;
    int e=sle_rt_cal_observe(&a->cal,tx,rx);
    if (e) record(a,"calibration_failure",",\"tx_sync\":%" PRId64 ",\"rx_sync\":%" PRId64
        ",\"candidate_offset\":%" PRId64 ",\"offset_before\":%" PRId64 ",\"count_before\":%d,"
        "\"valid_before\":%s,\"offset\":%" PRId64 ",\"count\":%d,\"valid_after\":%s,"
        "\"cleared\":%s,\"result\":\"%s\"",tx,rx,rx-tx,before.offset,before.count,
        before.valid ? "true":"false",a->cal.offset,a->cal.count,a->cal.valid ? "true":"false",
        !a->cal.count ? "true":"false",sle_rt_result_name(e));
    return e;
}
static int calibrate_trials(app *a)
{
    sle_rt_radio *r=a->radio;
    sle_rt_cal previous=a->cal;
    sle_rt_cal_clear(&a->cal);
    for (int trial=0;trial<12 && !a->cal.valid;trial++) {
        if (!live(a)) return -1;
        /* Per-burst nonce prevents a delayed old marker from calibrating the
         * next trial against a different TX index. Carry across all 40 bits. */
        for (int i=11;i<16;i++) if (++a->marker[i]) break;
        uint8_t bits[256];
        size_t nb=sle_access_encode_frame(bits,sizeof bits,a->marker,sizeof a->marker,77,0,0);
        if (!nb || sle_rt_modulate(&a->calwave,bits,nb,0)) { a->reason="calibration_encode"; return -1; }
        sle_rt_command c={.mhz=2424,.seed=77,.rx_start=0,.rx_end=INT64_MAX,.wave=a->calwave};
        c.tx_start=atomic_load(&r->tx_head)+SLE_RT_BLOCK*4;
        if (issue(a,&c)) return -1;
        int64_t tx_sync=c.tx_start+sle_rt_sync_in_wave();
        int64_t until=sle_iio_now_ns()+50000000;
        int found=0;
        while (live(a) && sle_iio_now_ns()<until) {
            sle_rt_received f; int rc=next_frame(a,c.seq,&f);
            if (rc<0) return -1;
            if (!rc) { pause_ctl(); continue; }
            sle_frame_t *v=&f.f.frame;
            if (v->kind || !v->crc24_ok || v->broadcast_type || v->packet_type ||
                v->payload_len!=sizeof a->marker || memcmp(v->payload,a->marker,sizeof a->marker)) continue;
            sle_rt_cal before=a->cal;
            int64_t candidate=(int64_t)f.f.sample_index-tx_sync;
            int e=observe_cal(a,tx_sync,(int64_t)f.f.sample_index);
            if (!e && previous.valid && llabs((int64_t)f.f.sample_index-tx_sync-previous.offset)>SLE_RT_OFFSET_TOL) {
                e=SLE_RT_OFFSET_JUMP; sle_rt_cal_clear(&a->cal);
            }
            char mk[2*sizeof a->marker+1];
            char cfo_txt[32]; if (isfinite(f.cfo_hz)) snprintf(cfo_txt,sizeof cfo_txt,"%.1f",f.cfo_hz); else snprintf(cfo_txt,sizeof cfo_txt,"null");
            for (size_t k=0;k<sizeof a->marker;k++) snprintf(mk+2*k,3,"%02x",a->marker[k]);
            record(a,"calibration_detail",",\"trial\":%d,\"cmd_seq\":%u,\"tx_start\":%" PRId64
                ",\"wave_samples\":%zu,\"marker\":\"%s\",\"cfo_hz\":%s,\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64,
                trial,c.seq,c.tx_start,c.wave.n,mk,cfo_txt,
                (int64_t)atomic_load(&r->rx_head),(int64_t)atomic_load(&r->tx_head));
            record(a,"calibration",",\"trial\":%d,\"tx_sync\":%" PRId64 ",\"rx_sync\":%" PRIu64
                ",\"offset\":%" PRId64 ",\"count\":%d,\"result\":\"%s\","
                "\"candidate_offset\":%" PRId64 ",\"offset_before\":%" PRId64
                ",\"count_before\":%d,\"valid_before\":%s,\"valid_after\":%s,\"cleared\":%s,"
                "\"previous_offset\":%" PRId64 ",\"previous_valid\":%s",
                trial,tx_sync,f.f.sample_index,a->cal.offset,a->cal.count,sle_rt_result_name(e),
                candidate,before.offset,before.count,before.valid ? "true":"false",
                a->cal.valid ? "true":"false",e && !a->cal.count ? "true":"false",
                previous.offset,previous.valid ? "true":"false");
            if (e) {
                if (e!=SLE_RT_OFFSET_JUMP || previous.valid) {
                    a->reason=e==SLE_RT_OFFSET_JUMP ? "calibration_offset_jump":"calibration_invalid";
                    return -1;
                }
                /* Startup has no established RX/TX mapping to preserve.
                 * observe() cleared the candidate on this jump; discard this
                 * marker and require three fresh stable bursts within the
                 * original trial budget. Recalibration remains fail-closed. */
                record(a,"calibration_restart",",\"trial\":%d,\"remaining_trials\":%d,"
                    "\"reason\":\"initial_offset_jump\"",trial,11-trial);
            }
            /* A matched but rejected marker is not a miss. Always take the
             * inter-burst wait before collecting the next fresh nonce. */
            found=1; break;
        }
        if (!found) {
            record(a,"calibration_miss",",\"trial\":%d,\"candidate_offset\":null,"
                "\"offset_before\":%" PRId64 ",\"count_before\":%d,\"cleared\":true,\"count\":0",
                trial,a->cal.offset,a->cal.count);
            sle_rt_cal_clear(&a->cal);
        }
        if (wait_rx(a,atomic_load(&r->rx_head)+SAMPLES_US(5000))) return -1;
    }
    if (!a->cal.valid) { a->reason="calibration_failed"; return -1; }
    atomic_store(&r->guard,1);
    return 0;
}
/* Hold the deeper --cal-depth TX reserve only while calibrating. The stream
 * stays continuous, so the RX/TX index mapping is unchanged. After restoring
 * the access depth, wait until RX has advanced depth+1 blocks: the DAC has
 * then consumed every extra block and access admission sees the real TX
 * horizon (the depth check in access_peer only reads the setting). */
static int calibrate(app *a)
{
    sle_rt_radio *r=a->radio;
    int keep=atomic_load(&r->depth), deep=opt.cal_depth>keep ? opt.cal_depth:keep;
    atomic_store(&r->depth,deep);
    record(a,"cal_depth",",\"phase\":\"raise\",\"depth\":%d,\"restore_depth\":%d,\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64,
        deep,keep,(int64_t)atomic_load(&r->rx_head),(int64_t)atomic_load(&r->tx_head));
    int rc=calibrate_trials(a);
    atomic_store(&r->depth,keep);
    int64_t rx=atomic_load(&r->rx_head), tx=atomic_load(&r->tx_head);
    int w=rc || deep==keep ? 0 : wait_rx(a,rx+(int64_t)(deep+1)*SLE_RT_BLOCK);
    record(a,"cal_depth",",\"phase\":\"restore\",\"depth\":%d,\"result\":%d,\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64
        ",\"settled_rx_head\":%" PRId64 ",\"settled_tx_head\":%" PRId64 ",\"settle_error\":%d",
        keep,rc,rx,tx,(int64_t)atomic_load(&r->rx_head),(int64_t)atomic_load(&r->tx_head),w);
    return rc ? rc : w;
}

static void access_slack(app *a, const sle_access_plan_t *p, const char *stage,
                         int64_t now, int64_t request_slack, int64_t response_slack)
{
    a->selected_plan=*p;
    if (a->n_slack>=sizeof a->slack/sizeof a->slack[0]) { a->log_full=1; return; }
    a->slack[a->n_slack++]=(slack_trace){stage,sle_iio_now_ns(),now,request_slack,response_slack,
        a->cal.last_sample,a->request_submitted};
}
static void access_trace_flush(app *a)
{
    const sle_access_plan_t *p=&a->selected_plan;
    if (a->primary_pending) {
        frame_record(a,a->selected_primary.seq,&a->selected_primary,a->primary_mono);
        record_at(a,a->primary_mono,"primary",",\"result\":\"ok\",\"sample\":%" PRId64
            ",\"primary_age_us\":%.3f,\"deferred_log\":true",a->primary_sample,(a->primary_now-a->primary_sample)/4.0);
        record_at(a,a->primary_mono,"access_plan",",\"aux_mhz\":%d,\"aux_channel\":%u,\"aux_ns\":%" PRId64
            ",\"request_ns\":%" PRId64 ",\"response_ns\":%" PRId64 ",\"tx_cfo_hz\":%.3f,"
            "\"cfo_source_sample\":%" PRId64 ",\"cfo_age_us\":%.3f,\"cfo_delta_hz\":%.3f,"
            "\"profile\":\"O4_assumed_aux_2500_6250\",\"resource_layout\":\"%s\",\"deferred_log\":true",
            p->aux_mhz,p->aux_channel,p->aux_sync_ns,p->req_sync_ns,p->rsp_sync_ns,a->cfo,
            a->cache->source_sample,opt.auto_cfo ? (a->primary_now-a->cache->source_sample)/4.0:0,a->cfo_delta,
            resource_layout_name(opt.resource_layout));
        a->primary_pending=0;
    }
    for (unsigned i=0;i<a->n_slack;i++) {
        const slack_trace *s=&a->slack[i];
        record_at(a,s->mono,"access_slack",",\"stage\":\"%s\",\"primary_age_us\":%.3f,"
            "\"request_slack_us\":%.3f,\"response_slack_us\":%.3f,\"request_remaining_us\":%.3f,"
            "\"response_remaining_us\":%.3f,\"calibration_age_us\":%.3f,\"request_submitted\":%s,\"deferred_log\":true",
            s->stage,(s->now-a->primary_sample)/4.0,s->tx_slack/4.0,s->rx_slack/4.0,
            (sle_ns_to_samples(p->req_sync_ns,SLE_RT_FS)-s->now)/4.0,
            (sle_ns_to_samples(p->rsp_sync_ns,SLE_RT_FS)-s->now)/4.0,(s->now-s->cal_sample)/4.0,
            s->submitted ? "true":"false");
    }
    a->n_slack=0;
    record(a,"request_wave_copy",",\"elapsed_ns\":%" PRId64 ",\"cache_build_ns\":%" PRId64
        ",\"cfo_age_us\":%.3f,\"cfo_age_stage\":\"admission\",\"rotation_in_access\":false",
        a->copy_ns,a->cache->build_ns,a->cfo_age_samples/4.0);
}
/* Returns 1 only for a fresh frame received AFTER a completed cache build.
 * Estimator agreement bounds reuse drift, not absolute carrier accuracy. */
static int cache_primary(app *a, const sle_rt_received *f, int64_t now)
{
    wave_cache *b=a->cache;
    if (!opt.auto_cfo) return b->valid;
    if (b->valid && (int64_t)f->f.sample_index<=b->ready_sample) return 0;
    if (!isfinite(f->cfo_hz) || fabs(f->cfo_hz)>150000 || fabs(opt.cfo+f->cfo_hz)>200000) {
        record(a,"cfo_reject",",\"reason\":\"estimate_out_of_range\""); return 0;
    }
    if (now<(int64_t)f->f.sample_index || now-(int64_t)f->f.sample_index>CFO_TTL) {
        record(a,"cfo_reject",",\"reason\":\"source_expired\""); return 0;
    }
    a->cfo_delta=opt.cfo+f->cfo_hz-b->cfo;
    int expired=b->valid && (now<b->source_sample || now-b->source_sample>CFO_TTL);
    if (!b->valid || expired || fabs(a->cfo_delta)>CFO_CHANGE_HZ) {
        record(a,"cfo_cache_refresh",",\"reason\":\"%s\",\"delta_hz\":%.3f,\"change_limit_hz\":%.0f,"
            "\"estimator\":\"sync_inner_56\",\"absolute_error_bound_hz\":null",
            !b->valid ? "initial":expired ? "age":"change",a->cfo_delta,CFO_CHANGE_HZ);
        if (cache_build(a,opt.cfo+f->cfo_hz,(int64_t)f->f.sample_index)) {
            a->reason=interrupted ? "signal":"wave_cache_build"; return -1;
        }
        return 0;
    }
    return 1;
}

static int scan(app *a, sle_access_plan_t *plan)
{
    sle_rt_radio *r=a->radio;
    for (;;) {
        sle_rt_command c={.mhz=2424,.seed=77,.estimate_cfo=opt.auto_cfo,
            .rx_start=atomic_load(&r->rx_head),.rx_end=INT64_MAX};
        if (issue(a,&c)) return -1;
        while (live(a)) {
            if (!sle_rt_cal_fresh(&a->cal,sle_rt_radio_now(r),CAL_TTL)) break;
            sle_rt_received f; int got=read_frame(a,c.seq,&f,0);
            if (got<0) return -1;
            if (!got) { pause_ctl(); continue; }
            int64_t now=sle_rt_radio_now(r);
            int e=sle_rt_primary_layout(&a->peer,&f.f,now,sle_rt_access_lead(),
                (int64_t)llround(opt.shift_us*4),opt.resource_layout,plan);
            if (e!=SLE_RT_OK && e!=SLE_RT_LATE) {
                frame_record(a,c.seq,&f,sle_iio_now_ns()); continue;
            }
            int cached=cache_primary(a,&f,now);
            if (cached<0) return -1;
            if (!cached) {
                frame_record(a,c.seq,&f,sle_iio_now_ns()); continue;
            }
            a->primary_sample=(int64_t)f.f.sample_index;
            int64_t ts=sle_ns_to_samples(plan->req_tx_start_ns,SLE_RT_FS)-now-sle_rt_access_lead();
            int64_t rs=sle_ns_to_samples(plan->rsp_sync_ns,SLE_RT_FS)-now-sle_rt_access_response_lead(1);
            if (rs<0) e=SLE_RT_LATE;
            if (e) {
                frame_record(a,c.seq,&f,sle_iio_now_ns());
                record(a,"primary",",\"result\":\"%s\",\"sample\":%" PRIu64 ",\"primary_age_us\":%.3f,"
                    "\"request_slack_us\":%.3f,\"response_slack_us\":%.3f",
                    sle_rt_result_name(e),f.f.sample_index,(now-a->primary_sample)/4.0,ts/4.0,rs/4.0);
                continue;
            }
            a->cfo=a->cache->cfo;
            a->cfo_age_samples=opt.auto_cfo ? now-a->cache->source_sample:0;
            a->selected_primary=f; a->primary_pending=1; a->primary_now=now; a->primary_mono=sle_iio_now_ns();
            access_slack(a,plan,"primary",now,ts,rs);
            return 0;
        }
        if (!live(a) || calibrate(a)) return -1;
    }
}
static int access_run(app *a, const sle_access_plan_t *p)
{
    sle_rt_radio *r=a->radio;
    sle_rt_command c={.mhz=p->aux_mhz,.seed=p->aux_channel};
    int64_t req=sle_ns_to_samples(p->req_sync_ns,SLE_RT_FS), rsp=sle_ns_to_samples(p->rsp_sync_ns,SLE_RT_FS);
    if (!live(a)) return -1;
    if (p->aux_channel>=76) { a->reason="aux_channel_range"; return -1; }
    c.rx_start=req-SAMPLES_US(200); c.rx_end=rsp+SAMPLES_US(600);
    if (!a->cache->valid) { a->reason="wave_cache_missing"; return -1; }
    int64_t copy_start=sle_iio_now_ns();
    const sle_rt_wave *cached=&a->cache->request[p->aux_channel];
    c.wave.n=cached->n;
    if (c.wave.n>SLE_RT_WAVE_MAX) { a->reason="request_waveform"; return -1; }
    memcpy(c.wave.iq,cached->iq,c.wave.n*4);
    a->copy_ns=sle_iio_now_ns()-copy_start;
    if (!c.wave.n) { a->reason="request_waveform"; return -1; }
    /* Independently admit TX against the request and RX against the response.
     * Check again after TX tune, using the actual DMA head. RX may miss our
     * request leakage; only that observation can verify the TX time. */
    int64_t now=sle_rt_radio_now(r);
    if (opt.auto_cfo) {
        a->cfo_age_samples=now-a->cache->source_sample;
        if (a->cfo_age_samples<0 || a->cfo_age_samples>CFO_TTL || req-a->cache->source_sample>CFO_TTL) {
            a->reason="cfo_cache_expired"; goto not_sent;
        }
    }
    int64_t ts=req-SAMPLES_US(10)-now-sle_rt_access_lead();
    int64_t rs=rsp-now-sle_rt_access_response_lead(1);

    access_slack(a,p,"admission",now,ts,rs);
    if (ts<0 || rs<0 || atomic_load(&r->depth)!=SLE_RT_ACCESS_DEPTH) {
        a->reason=ts<0 ? "access_tx_budget":rs<0 ? "access_rx_budget":"access_dma_depth";
        goto not_sent;
    }
    if (!sle_rt_cal_fresh(&a->cal,now,CAL_TTL) || !sle_rt_cal_fresh(&a->cal,req,CAL_TTL)) {
        a->reason="calibration_expired"; goto not_sent;
    }
    atomic_store(&r->mute,1);
    if (tune(a,1,p->aux_mhz)) goto not_sent;
    now=sle_rt_radio_now(r);
    int e=sle_rt_tx_index(&a->cal,req,atomic_load(&r->tx_head)+TX_GUARD,&c.tx_start);
    ts=c.tx_start-atomic_load(&r->tx_head)-TX_GUARD;
    rs=rsp-now-sle_rt_access_response_lead(0);
    access_slack(a,p,"after_tx_retune",now,ts,rs);
    if (e || rs<0) { a->reason=e ? sle_rt_result_name(e):"access_rx_budget"; goto not_sent; }
    if (!sle_rt_cal_fresh(&a->cal,now,CAL_TTL) || !sle_rt_cal_fresh(&a->cal,req,CAL_TTL)) {
        a->reason="calibration_expired"; goto not_sent;
    }
    if (!live(a)) goto not_sent;
    /* All uncertain post-submit failures stop DMA in issue()/main. The log
     * distinguishes a never-submitted rejection from a possibly sent burst. */
    int issued=issue_with_timeout(a,&c,(int64_t)SLE_RT_ACCESS_ACK_US*1000);
    a->request_submitted=a->command_submitted;
    if (issued) return -1;
    record(a,"request_submitted",",\"predicted_sync_sample\":%" PRId64
        ",\"tx_start\":%" PRId64 ",\"timing_verified\":false,\"tx_may_have_run\":true",req,c.tx_start);
    /* 2026-09-27 captures: every RX retune that overlapped the request went
     * unanswered (13/13); the one that finished first was answered. An LO
     * write may interrupt TX, so wait until the burst has left the DAC. */
    {
        /* RX-domain end of the burst: req is its sync sample on the RX clock. */
        int64_t tx_end=req-sle_rt_sync_in_wave()+(int64_t)c.wave.n+SAMPLES_US(20);
        while (sle_rt_radio_now(r)<tx_end) {
            if (!live(a)) goto submitted_failed;
            if (sle_rt_radio_now(r)>=rsp-SLE_RT_REPLY_TOL) { a->reason="rx_retune_wait_late"; goto submitted_failed; }
            SLE_RT_WAIT_HOOK();
        }
        record(a,"rx_retune_after_request",",\"rx_end_sample\":%" PRId64 ",\"now\":%" PRId64,
            tx_end,sle_rt_radio_now(r));
    }
    if (tune(a,0,p->aux_mhz)) goto submitted_failed;
    now=sle_rt_radio_now(r);
    int64_t ready=now+SAMPLES_US(SLE_RT_ACCESS_SETTLE_US);
    int64_t rx_deadline=rsp-SLE_RT_REPLY_TOL-SAMPLES_US(10);
    rs=rx_deadline-ready-SLE_RT_BLOCK;
    access_slack(a,p,"after_rx_retune",now,req-now-sle_rt_sync_in_wave(),rs);
    if (rs<0) { a->reason="rx_retune_late_for_response"; goto submitted_failed; }
    /* Drain transition samples while muted, including the partial DMA block.
     * A delayed wakeup is checked against the response preamble once more. */
    while (atomic_load(&r->rx_head)<ready) {
        if (!live(a)) goto submitted_failed;
        if (sle_rt_radio_now(r)>=rx_deadline) {
            a->reason="rx_ready_late_for_response"; goto submitted_failed;
        }
        pause_ctl();
    }
    if (!live(a)) goto submitted_failed;
    now=sle_rt_radio_now(r);
    access_slack(a,p,"rx_ready",now,req-now-sle_rt_sync_in_wave(),rx_deadline-now);
    if (sle_rt_radio_now(r)>=rx_deadline) { a->reason="rx_ready_late_for_response"; goto submitted_failed; }
    atomic_store(&r->mute,0);
    access_trace_flush(a);
    int leak=0, response=0;
    while (live(a)) {
        sle_rt_received f; int got=next_frame(a,c.seq,&f);
        if (got<0) goto submitted_failed;
        if (got) {
            sle_frame_t *v=&f.f.frame;
            if (v->kind==SLE_FRAME_BROADCAST && v->packet_type==4 && v->broadcast_type==1 &&
                f.f.channel_mhz==p->aux_mhz && v->seed==p->aux_channel &&
                v->crc12_ok && v->has_crc24 && v->crc24_ok && v->length==84 &&
                v->payload_len==84 && !memcmp(v->payload,a->request,84)) {
                e=observe_cal(a,c.tx_start+sle_rt_sync_in_wave(),(int64_t)f.f.sample_index);
                record(a,"request_leakage",",\"error_samples\":%" PRId64 ",\"result\":\"%s\"",
                    (int64_t)f.f.sample_index-req,sle_rt_result_name(e));
                if (e) { a->access_timing_verified=0; a->reason="access_offset_jump"; goto submitted_failed; }
                a->access_timing_verified=1;
                leak=1;
            } else {
                e=sle_rt_response(&a->peer,p,&f.f);
                record(a,"response_check",",\"result\":\"%s\",\"error_samples\":%" PRId64,
                    sle_rt_result_name(e),(int64_t)f.f.sample_index-rsp);
                if (e==SLE_RT_OK) response=1;
                else if (e==SLE_RT_REJECTED) { a->reason="server_rejected_access"; goto submitted_failed; }
            }
        } else {
            /* Drain queued observations before accepting, so an observed
             * offset jump cannot be hidden by an earlier valid response. */
            if (response) {
                if (!live(a)) goto submitted_failed;
                record(a,"access_accepted",",\"peer_response_validated\":true,\"timing_verified\":%s,"
                    "\"calibration_refreshed\":%s",leak ? "true":"false",leak ? "true":"false");
                return 0;
            }
            if (sle_rt_expired(atomic_load(&r->rx_head),c.rx_end+SLE_RT_BLOCK)) {
                a->reason="access_response_timeout"; goto submitted_failed;
            }
            pause_ctl();
        }
    }
submitted_failed:;
    /* RX preparation can fail after TX has entered DMA or reached the air. */
    int stopped=sle_rt_radio_stop(r);
    if (stopped) a->cleanup_failed=1;
    record(a,"access_failed_after_submit",",\"reason\":\"%s\",\"request_submitted\":true,"
        "\"tx_may_have_run\":true,\"stop_result\":%d",a->reason,stopped);
    return -1;
not_sent:
    record(a,"access_not_sent",",\"reason\":\"%s\",\"request_submitted\":false",a->reason);
    return -1;
}
static int access_peer(app *a, const sle_access_plan_t *p)
{
    int rc=access_run(a,p);
    if (a->n_slack || a->primary_pending) access_trace_flush(a);
    return rc;
}

static void hex(char *out, size_t cap, const uint8_t *p, size_t n)
{
    static const char d[]="0123456789abcdef";
    size_t i=0;
    for (; i<n && 2*i+2<cap; i++) { out[2*i]=d[p[i]>>4]; out[2*i+1]=d[p[i]&15]; }
    out[2*i]=0;
}
/* Wrap one unsegmented SSAP PDU, then copy to ACK-owned link storage. */
static int queue_ssap(app *a, sle_link_t *l, const uint8_t *pdu, size_t n, const char *what)
{
    uint8_t b[SLE_RT_TX_MAX];
    size_t sdu=n+4;
    if (sdu+2+(a->g_runtime ? 4u:0u)>sizeof b) return -1;
    b[0]=(uint8_t)((sdu&0x1f)<<3); b[1]=(uint8_t)((sdu>>5)&0x3f);
    b[2]=0x0a; b[3]=0x00; b[4]=(uint8_t)n; b[5]=(uint8_t)(n>>8);
    memcpy(b+6,pdu,n);
    if (sle_rt_queue(&a->tx_store,l,SLE_PTYPE_DATA,b,sdu+2)) return -1;
    char h[2*96+1]; hex(h,sizeof h,b,sdu+2);
    record(a,"ssap_queued",",\"what\":\"%s\",\"bytes\":\"%s\"",what,h);
    return 0;
}
/* Best-effort console: never wait for a stalled terminal in the scheduler.
 * Exact payloads remain in the journal; account for undelivered display bytes. */
static void console_write(app *a, const char *p, size_t n)
{
    if (!a->console_active) return; /* offline tests do not own stdout */
    ssize_t sent=write(STDOUT_FILENO,p,n);
    a->console_dropped+=n-(sent>0 ? (size_t)sent:0);
}
static void console_printf(app *a, const char *fmt, ...)
{
    char row[1024]; va_list ap; va_start(ap,fmt);
    int n=vsnprintf(row,sizeof row,fmt,ap); va_end(ap);
    if (n>0) console_write(a,row,(size_t)n<sizeof row ? (size_t)n:sizeof row-1);
}
/* Interactive writes are serialized: never reuse request context before RSP.
 * Keep the existing unfragmented <=48-byte value limit. */
static int queue_write(app *a, sle_link_t *l, const uint8_t *value, size_t n)
{
    if (!n || n>sizeof a->write_value || a->ssap_state==2) return -1;
    sle_ssap_write_t w={.fragment=SLE_SSAP_FRAG_NONE,.item={.handle=a->prop_handle,.type=0,
        .value=value,.value_len=(uint16_t)n}};
    uint8_t q[80]; size_t m=sle_ssap_write_build(SLE_SSAP_WRITE_REQ,&w,q,sizeof q);
    if (!m || queue_ssap(a,l,q,m,"write_req")) return -1;
    memcpy(a->write_value,value,n); a->write_len=n;
    a->ssap_state=2; a->ssap_write_verified=0;
    a->write_deadline_ms=(uint64_t)(sle_iio_now_ns()/1000000)+5000;
    if (opt.interactive) {
        char h[97]; hex(h,sizeof h,value,n);
        record(a,"interactive_write",",\"len\":%zu,\"value_hex\":\"%s\"",n,h);
        console_printf(a,"[E310 -> WS63 写入已排队 %zu B]\n",n);
    }
    return 0;
}
/* Return 1 for one complete line, -1 for a rejected line, 0 for incomplete.
 * Reject oversized lines in their entirety; never silently split a write. */
static int chat_next(app *a, uint8_t out[48], size_t *n)
{
    *n=0;
    char *nl=memchr(a->chat,'\n',a->chat_len);
    if (!nl) {
        if (a->chat_len==sizeof a->chat) { a->chat_len=0; a->chat_dropping=1; }
        return 0;
    }
    size_t len=(size_t)(nl-a->chat), take=len+1;
    if (len && a->chat[len-1]=='\r') len--;
    int bad=a->chat_dropping || len>46 || memchr(a->chat,0,len)!=NULL;
    if (!bad) { memcpy(out,a->chat,len); out[len]='\r'; out[len+1]='\n'; *n=len+2; }
    memmove(a->chat,a->chat+take,a->chat_len-take); a->chat_len-=take;
    a->chat_dropping=0;
    return bad ? -1:1;
}
static int chat_pump(app *a, sle_link_t *l)
{
    if (!a->chat_eof && a->chat_len<sizeof a->chat) {
        struct pollfd pf={.fd=STDIN_FILENO,.events=POLLIN};
        int ready=poll(&pf,1,0);
        if (ready<0 && errno!=EINTR) { a->reason="stdin_poll"; return -1; }
        if (ready>0) {
            if (pf.revents&(POLLERR|POLLNVAL)) { a->reason="stdin_poll"; return -1; }
            if (pf.revents&(POLLIN|POLLHUP)) {
                ssize_t n=read(STDIN_FILENO,a->chat+a->chat_len,sizeof a->chat-a->chat_len);
                if (n>0) a->chat_len+=(size_t)n;
                else if (!n) {
                    a->chat_eof=1;
                    record(a,"interactive_eof",",\"buffered_bytes\":%zu,\"connection_continues\":true",a->chat_len);
                }
                else if (errno!=EINTR && errno!=EAGAIN) { a->reason="stdin_read"; return -1; }
            }
        }
    }
    /* Buffer input even during setup / an outstanding write, but never send
     * before encryption or replace request context while awaiting its RSP. */
    if (a->ssap_state==2) {
        if ((uint64_t)(sle_iio_now_ns()/1000000)>a->write_deadline_ms) {
            record(a,"interactive_write_timeout",",\"timeout_ms\":5000");
            a->reason="ssap_write_timeout"; return -1;
        }
        return 0;
    }
    /* EOF only closes input. Keep the encrypted connection and any partial
     * final line; complete buffered lines still drain one WRITE at a time. */
    if (a->chat_eof && !memchr(a->chat,'\n',a->chat_len)) return 0;
    if (!a->chat_ready || !a->g_runtime || !sle_g_runtime_encrypted(a->g_runtime) || a->ssap_state!=3) return 0;
    uint8_t value[48]; size_t n=0; int next=chat_next(a,value,&n);
    if (next<0) {
        record(a,"interactive_line_rejected",",\"max_text_bytes\":46");
        console_printf(a,"[E310] 此行未发送：最多 46 字节，不接受 NUL。请重新输入。\n");
    } else if (next>0) {
        if (a->peer_mtu && n+5>a->peer_mtu) {
            record(a,"interactive_line_rejected",",\"mtu\":%u,\"value_len\":%zu",a->peer_mtu,n);
            console_printf(a,"[E310] 此行未发送：超过协商 MTU %u，请缩短。\n",a->peer_mtu);
            return 0;
        }
        if (queue_write(a,l,value,n)) { a->reason="ssap_write_queue"; return -1; }
    }
    return 0;
}
/* Parse one reassembled SDU as [DTAP][SSAP] and advance
 * the minimal client: MTU rsp -> find properties -> write -> write rsp. */
static void ssap_on_sdu(app *a, sle_link_t *l, const uint8_t *p, size_t n)
{
    if (n>4 && p[0]==(SLE_CMTC_TCID&0xff) && p[1]==(SLE_CMTC_TCID>>8) && p[4]==2) {
        uint8_t id=0; uint16_t mps=0, ver=0;
        int e=sle_cmtc_capability_parse_rsp(p,n,&id,&mps,&ver);
        record(a,"cmtc_capability_peer_rsp",",\"identifier\":%u,\"mps\":%u,\"version\":%u,\"error\":%d",id,mps,ver,e);
        if (e) a->ssap_failed=1;
        return;
    }
    if (n>=2 && p[0]==(SLE_CMTC_TCID&0xff) && p[1]==(SLE_CMTC_TCID>>8)) {
        /* 1.10.108 server capability request; SSAP state is untouched. */
        uint8_t r[SLE_CMTC_RSP_SDU_LEN+2]; size_t rn=0;
        int e=sle_cmtc_capability_reply(p,n,r+2,sizeof r-2,&rn);
        record(a,"cmtc_capability_req",",\"identifier\":%u,\"protected\":%s,\"error\":%d",
            n>5 ? p[5]:0,a->g_runtime && sle_g_runtime_encrypted(a->g_runtime) ? "true":"false",e);
        if (e) { a->ssap_failed=1; return; }
        r[0]=(uint8_t)((rn&0x1f)<<3); r[1]=(uint8_t)((rn>>5)&0x3f);
        if (sle_rt_queue(&a->tx_store,l,SLE_PTYPE_DATA,r,rn+2)) { a->ssap_failed=1; return; }
        char h[2*sizeof r+1]; hex(h,sizeof h,r,rn+2);
        record(a,"cmtc_capability_rsp",",\"identifier\":%u,\"mps\":%u,\"version\":%u,\"bytes\":\"%s\"",
            p[5],SLE_CMTC_MPS,SLE_CMTC_VERSION,h);
        return;
    }
    if (n<6 || p[0]!=0x0a || p[1]) {
        record(a,"ssap_rx_unparsed",",\"len\":%zu",n); return;
    }
    size_t dl=(size_t)p[2]|(size_t)p[3]<<8;
    if (dl+4!=n || dl<2) {
        record(a,"ssap_rx_unparsed",",\"len\":%zu",n); return;
    }
    const uint8_t *s=p+4;
    record(a,"ssap_rx",",\"opcode\":%u,\"len\":%zu",s[0],dl);
    if (s[0]==SLE_SSAP_EXCHANGE_INFO_RSP && a->probe_queued) {
        sle_ssap_exchange_info_t x;
        if (sle_ssap_exchange_info_parse(s,dl,&x)!=SLE_SSAP_OK || !x.mtu_present || x.mtu<23) {
            record(a,"ssap_validation",",\"what\":\"mtu_response\",\"ok\":false"); return;
        }
        a->ssap_validated=1;
        a->peer_mtu=x.mtu<(unsigned)opt.ssap_mtu ? x.mtu:(uint16_t)opt.ssap_mtu;
        record(a,"ssap_validation",",\"what\":\"mtu_response\",\"ok\":true,\"protected\":%s",
            a->g_runtime ? "true":"false");
    }
    if ((s[0]==0x0f || s[0]==0x10) && dl>=6) {
        /* VALUE_NTF/IND on WS63 (04:17 capture): code | ctrl | handle(2) |
         * value length(2 LE) | value. */
        size_t vl=(size_t)(s[4]|s[5]<<8), m=vl>48 ? 48:vl;
        if (vl+6!=dl) { record(a,"ssap_rx_unparsed",",\"len\":%zu",dl); return; }
        char t[49];
        for (size_t i=0;i<m;i++) t[i]=(s[6+i]>=0x20 && s[6+i]<0x7f && s[6+i]!='"' && s[6+i]!='\\') ? (char)s[6+i]:'.';
        t[m]=0;
        char value_hex[2*SLE_SDU_MAX+1]; hex(value_hex,sizeof value_hex,s+6,vl);
        record(a,"ssap_notify",",\"opcode\":%u,\"handle\":%u,\"value_len\":%zu,\"text\":\"%s\",\"value_hex\":\"%s\"",
            s[0],(unsigned)(s[2]|s[3]<<8),vl,t,value_hex);
        if (opt.interactive) {
            /* Escape control bytes so remote UART data cannot control the terminal. */
            char display[4*SLE_SDU_MAX+32];
            size_t used=(size_t)snprintf(display,sizeof display,"[WS63 -> E310] ");
            for (size_t i=0;i<vl;i++) {
                unsigned ch=s[6+i];
                if (ch>=0x20 && ch<0x7f && ch!='\\') display[used++]=(char)ch;
                else { snprintf(display+used,sizeof display-used,"\\x%02x",ch); used+=4; }
            }
            display[used++]='\n'; console_write(a,display,used);
        }
    }
    if (!opt.ssap_write && !opt.interactive) return;
    if (s[0]==0x03 && a->ssap_state==0 && a->ssap_validated) {
        sle_ssap_find_structure_req_t f={.find_type=SLE_SSAP_FIND_TYPE_PROPERTY,
            .item_type=SLE_SSAP_ITEM_TYPE_STANDARD,.start_handle=1,.end_handle=0xffff};
        uint8_t q[32]; size_t m=sle_ssap_find_structure_req_build(SLE_SSAP_FIND_STRUCTURE_REQ,&f,q,sizeof q);
        if (m && !queue_ssap(a,l,q,m,"find_structure_req")) a->ssap_state=1;
        else a->ssap_failed=1;
    } else if (s[0]==0x05 && a->ssap_state==1) {
        /* Item layout is not yet confirmed on WS63: the raw PDU is logged via
         * link_deliver; take the handle as the first 16-bit field after the
         * 2-byte SSAP header and log both interpretations. */
        if (dl<4 || (s[1]&3)!=SLE_SSAP_FRAG_NONE) return;
        a->prop_handle=(uint16_t)(s[2]|s[3]<<8);
        if (!a->prop_handle) return;
        record(a,"ssap_property",",\"handle\":%u",a->prop_handle);
        /* Single complete PDU (ctrl 0x03) like the official client; 1.10.108
         * rejects fragment BEGIN (0x00) with ERROR_RSP 2, which 1.10.102
         * tolerated (logs/e310/cmtc-g-c-cmac-20260928). */
        if (opt.interactive) {
            a->ssap_state=3; a->chat_ready=1;
            a->deadline=sle_iio_now_ns()+86400LL*1000000000;
            record(a,"interactive_ready",",\"handle\":%u,\"max_text_bytes\":46",a->prop_handle);
            console_printf(a,"[E310] 已连接并加密（MTU %u）。输入一行按回车发给 WS63；WS63 键入的字符会显示在下面。Ctrl+C 退出。\n",a->peer_mtu);
        } else if (queue_write(a,l,(const uint8_t *)opt.ssap_write,strlen(opt.ssap_write))) a->ssap_failed=1;
    } else if (s[0]==0x0e && a->ssap_state==2) {
        /* Official WS63 returns 0e 03 | handle | type | exact written value
         * (observed write response). Use request context, not the codec's error-list/echo
         * heuristic, which is ambiguous for some short values. */
        const uint8_t *value=opt.interactive ? a->write_value:(const uint8_t *)opt.ssap_write;
        size_t value_len=opt.interactive ? a->write_len:strlen(opt.ssap_write);
        int echo_ok=dl==value_len+5 && (uint16_t)(s[2]|s[3]<<8)==a->prop_handle &&
            !s[4] && !memcmp(s+5,value,value_len);
        int ok=s[1]==SLE_SSAP_FRAG_NONE && (dl==2 || echo_ok);
        /* 1.10.108 error form 0e 0b 01 | handle | status (logs/e310/
         * cmtc-g-e-20260928): the official sample declares READ|NOTIFY, so
         * the stack answers status 7 while still delivering the value to the
         * app. Record it, never count it as verified, and keep the link up
         * so the notification direction can still be observed. */
        int status_form=!ok && dl==6 && s[1]==0x0b && s[2]==0x01 &&
            (uint16_t)(s[3]|s[4]<<8)==a->prop_handle;
        record(a,"ssap_write_rsp",",\"ok\":%s,\"status\":%d,\"protected\":%s",ok ? "true":"false",
            status_form ? s[5]:-1,a->g_runtime ? "true":"false");
        if (ok) { a->ssap_state=3; a->ssap_write_verified=1; }
        else if (status_form && s[5]) a->ssap_state=3;
        else a->ssap_failed=1;
        if (opt.interactive) {
            if (ok) console_printf(a,"[WS63 写入响应] 成功\n");
            else if (status_form) console_printf(a,"[WS63 写入响应] 失败（status=%u）\n",(unsigned)s[5]);
            else console_printf(a,"[WS63 写入响应] 失败（响应格式或回显不匹配）\n");
        }
    } else if (s[0]==0x01) {
        record(a,"ssap_error_rsp",",\"state\":%d",a->ssap_state);
        a->ssap_failed=1;
    }
}
typedef struct { app *a; sle_link_t *link; } sdu_context;
static void on_sdu(void *ctx, const uint8_t *p, size_t n, unsigned fragments)
{
    sdu_context *c=ctx;
    char h[2*SLE_SDU_MAX+1]; hex(h,sizeof h,p,n);
    record(c->a,"sdu_deliver",",\"len\":%zu,\"fragments\":%u,\"payload\":\"%s\",\"protected\":%s",
        n,fragments,h,c->a->g_runtime ? "true":"false");
    ssap_on_sdu(c->a,c->link,p,n);
}
/* Feed only authenticated, ARQ-deduplicated ptype-0 payloads, in order. */
static void ssap_on_deliver(app *a, sle_link_t *l, const uint8_t *p, size_t n)
{
    sdu_context c={a,l};
    int result=sle_sdu_rx_feed(&a->sdu_rx,p,n,on_sdu,&c);
    if (result) {
        record(a,"sdu_reassembly_error",",\"error\":%d,\"len\":%zu",result,n);
        a->ssap_failed=1;
    }
}
/* SSAP exchange, OpenHarmony layout (unverified on WS63): DTAP basic header
 * tcid | frameType:4 o c p f | length LE, no PI for fixed TCID 0x0A. */
static int queue_ssap_probe(app *a, sle_link_t *l)
{
    sle_ssap_exchange_info_t x={.mtu_present=1,.version_present=1,.fragment_capable=1,
        .multi_processing=1,.mtu=(uint16_t)opt.ssap_mtu,.version=0x0001};
    /* 46803.2 table 146 (bit column 0 = LSB, as for the verified control
     * PDUs): byte0-1 index 0xFFFF only when multiplexed (packet type 2);
     * then reserved:1 segment:2 length[4:0]:5 | length[10:5]:6 reserved:2. */
    size_t hdr=opt.ssap_frame==0 ? 2:opt.ssap_frame==1 ? 4:0;
    uint8_t *dtap=a->probe+hdr;
    size_t n=sle_ssap_exchange_info_build(SLE_SSAP_EXCHANGE_INFO_REQ,&x,dtap+4,sizeof a->probe-hdr-4);
    if (!n) return -1;
    dtap[0]=0x0a; dtap[1]=0x00; dtap[2]=(uint8_t)n; dtap[3]=(uint8_t)(n>>8);
    size_t sdu=n+4;
    uint8_t *sl=a->probe+(opt.ssap_frame==1 ? 2:0);
    if (opt.ssap_frame==1) { a->probe[0]=0xff; a->probe[1]=0xff; }
    if (opt.ssap_frame!=2) { sl[0]=(uint8_t)((0u<<1)|((sdu&0x1f)<<3)); sl[1]=(uint8_t)((sdu>>5)&0x3f); }
    uint8_t ptype=opt.ssap_frame==1 ? 2:SLE_PTYPE_DATA;
    if (sle_rt_queue(&a->tx_store,l,ptype,a->probe,hdr+sdu)) return -1;
    char h[64]; hex(h,sizeof h,a->probe,hdr+sdu);
    record(a,"ssap_probe_queued",",\"frame\":%d,\"ptype\":%u,\"bytes\":\"%s\"",opt.ssap_frame,ptype,h);
    a->probe_queued=1;
    return 0;
}
static int64_t witness_deadline(int64_t sync, size_t wave_samples)
{
    return sync-sle_rt_sync_in_wave()+(int64_t)wave_samples+SLE_RT_WITNESS_MARGIN;
}
static int connection_accepted(const app *a)
{
    if (opt.ssap_write && !a->ssap_write_verified) return 0;
    return !a->ssap_failed && !a->sdu_rx.pending && (!a->g_runtime || sle_g_runtime_accepted(a->g_runtime,opt.ssap_mtu!=0,
        a->ssap_validated,opt.ssap_write!=NULL,a->ssap_write_verified));
}
static int connection(app *a, const sle_access_plan_t *p)
{
    sle_rt_radio *r=a->radio;
    a->connecting=1;
    a->deadline=sle_iio_now_ns()+(int64_t)opt.connect_seconds*1000000000;
    a->connected_ns=a->last_peer_ns=0; a->valid_received=0;
    sle_conn_sched_t sched;
    if (sle_conn_sched_init(&sched,p->req_sync_ns,&a->peer.txi)) { a->reason="schedule_init"; return -1; }
    sle_link_t *l=calloc(1,sizeof *l);
    if (!l) { a->reason="allocation_failed"; return -1; }
    sle_link_init(l,SLE_LINK_ROLE_G,&sched,a->peer.txi.first_crc_init);
    /* Keep three blocks until event 0: the response-to-event-0 margin is only
     * ~5.5 ms. Growing to 16 before its retune would queue zeros past event 0.
     * Subsequent events have the full 12.5 ms period for retune + render lead. */
    int64_t last_k=-1;
    int witness_run=0;
    int result=-1;
    a->probe_queued=0; a->ssap_state=0; a->prop_handle=0; a->peer_mtu=0;
    a->ssap_validated=a->ssap_write_verified=a->ssap_failed=0;
    /* Unsent input belongs to the console, not this connection. Preserve EOF,
     * partial/complete lines and oversized-line draining across retries. A
     * dequeued WRITE has an unknown outcome: discard its context, never replay. */
    a->chat_ready=0;
    sle_rt_wipe(a->write_value,sizeof a->write_value);
    a->write_len=0; a->write_deadline_ms=0;
    sle_sdu_rx_init(&a->sdu_rx,opt.ssap_mtu ? (size_t)opt.ssap_mtu+4:SLE_SDU_MAX);
    sle_rt_wipe(&a->tx_store,sizeof a->tx_store);
    while (live(a)) {
        sle_link_tx_t tx;
        if (a->g_runtime) {
            sle_pair_status_t s; sle_pair_status(&a->g_runtime->pair,&s);
            if (a->valid_received>=2 && s.state==SLE_PAIR_READY &&
                sle_g_runtime_start(a->g_runtime,(uint64_t)(sle_iio_now_ns()/1000000))) {
                a->reason="pair_start"; break;
            }
            if (sle_g_runtime_queue(a->g_runtime,&a->tx_store,l)) { a->reason="pair_queue"; break; }
        }
        if (a->ssap_failed) { a->reason="ssap_failed"; break; }
        if (opt.ssap_mtu && !a->probe_queued && a->valid_received>=2 &&
            (!a->g_runtime || sle_g_runtime_encrypted(a->g_runtime)) && queue_ssap_probe(a,l)) {
            a->reason="ssap_probe_queue"; break;
        }
        if (opt.interactive && chat_pump(a,l)) break;
        int64_t lead=RETUNE_LEAD+(atomic_load(&r->depth)-SLE_RT_ACCESS_DEPTH)*SLE_RT_BLOCK;
        if (sle_link_g_prepare(l,sle_samples_to_ns(sle_rt_radio_now(r),SLE_RT_FS),
                sle_samples_to_ns(lead,SLE_RT_FS),&tx)) {
            record(a,"link_down",",\"reason_code\":%u",l->down_reason);
            a->reason=l->down_reason==7 ? "supervision_timeout" : "peer_disconnect_or_update";
            break;
        }
        if (tx.k>last_k+1) {
            a->skipped+=(unsigned)(tx.k-last_k-1);
            record(a,"events_skipped",",\"first\":%" PRId64 ",\"next\":%" PRId64 ",\"reason\":\"retune_or_pipeline_lead\"",
                last_k+1,tx.k);
        }
        last_k=tx.k;
        if (!sle_rt_cal_fresh(&a->cal,sle_rt_radio_now(r),CAL_TTL)) { a->reason="calibration_expired"; break; }
        atomic_store(&r->mute,1);
        if (tune(a,1,tx.ev.mhz) || tune(a,0,tx.ev.mhz)) break;
        size_t plain_len=tx.len;
        unsigned control_type=tx.ptype==SLE_PTYPE_CTRL && tx.len>=3 ? (unsigned)(tx.data[0]|tx.data[1]<<8):0;
        if (a->g_runtime && sle_g_runtime_tx(a->g_runtime,&tx)) { a->reason="pair_protect"; break; }
        if (a->g_runtime && tx.len) {
            sle_pair_status_t ps; sle_pair_status(&a->g_runtime->pair,&ps);
            record(a,"pair_tx",",\"control_type\":%u,\"protected\":%d,\"plain_len\":%zu,"
                "\"wire_len\":%u,\"tx_next\":%" PRIu64 ",\"rx_next\":%" PRIu64,
                control_type,ps.secure,plain_len,tx.len,ps.tx_next,ps.rx_next);
        }
        /* tx now describes actual WIRE, including MIC, for PHY and all timing. */
        int64_t sync=sle_ns_to_samples(tx.ev.t_ns,SLE_RT_FS);
        int64_t second=sle_ns_to_samples(tx.ev.t_ns+sle_second_sender_offset_ns(&l->s,tx.len,tx.empty)-3000,SLE_RT_FS);
        sle_rt_command c={.mhz=tx.ev.mhz,.seed=tx.ev.white_seed,.connect=1,
            .lid=a->peer.txi.first_lid,.crc=l->crc_init,.rx_start=sync-SAMPLES_US(40),
            .rx_end=second+SAMPLES_US(3000)};
        /* Replies longer than 3 ms cannot fit this measured retune budget. */
        if (!a->cache->valid || tx.nesn>1 || tx.ev.white_seed<64 || tx.ev.white_seed>127 ||
            l->s.lid!=a->peer.txi.first_lid) {
            a->reason="empty_wave_cache_mismatch"; break;
        }
        if (tx.empty && !tx.len && !tx.sn && !tx.flow && tx.ptype==SLE_PTYPE_DATA) {
            const empty_wave *w=&a->cache->empty[tx.ev.white_seed-64][tx.nesn];
            c.wave.n=w->n; memcpy(c.wave.iq,w->iq,w->n*4);
        } else {
            /* SSAP data/control frame: encode and modulate on CPU0 per event.
             * Only the zero-CFO path is supported for non-cached frames. */
            static uint8_t dbits[1200];
            if (opt.auto_cfo || a->cfo!=0.0 || tx.len>96) { a->reason="data_frame_unsupported"; break; }
            sle_connect_config_t cfg={a->peer.txi.first_lid,tx.ev.white_seed,SLE_CRC_TYPE_24,l->crc_init,0};
            size_t nb=sle_encode_connect_config(dbits,sizeof dbits,tx.data,tx.len,&cfg,tx.ptype,tx.empty,
                tx.sn,tx.nesn,tx.flow,0,0);
            if (!nb || sle_rt_modulate(&c.wave,dbits,nb,0)) { a->reason="data_frame_encode"; break; }
            char h[2*96+1]; hex(h,sizeof h,tx.data,tx.len);
            record(a,"data_tx",",\"k\":%" PRId64 ",\"ptype\":%u,\"sn\":%u,\"nesn\":%u,\"retx\":%d,"
                "\"len\":%u,\"plain_len\":%zu,\"samples\":%zu,\"payload\":\"%s\"",tx.k,tx.ptype,tx.sn,tx.nesn,tx.retx,
                tx.len,plain_len,c.wave.n,h);
        }
        int e=sle_rt_tx_index(&a->cal,sync,atomic_load(&r->tx_head)+TX_GUARD,&c.tx_start);
        if (e) {
            record(a,"event_not_sent",",\"k\":%" PRId64 ",\"reason\":\"%s\"",tx.k,sle_rt_result_name(e));
            a->skipped++; continue;
        }
        if (sle_rt_radio_now(r)+SAMPLES_US(100)>=c.rx_start) {
            record(a,"event_not_sent",",\"k\":%" PRId64 ",\"reason\":\"rx_retune_late\"",tx.k);
            a->skipped++; continue;
        }
        if (issue(a,&c)) break;
        if (a->g_runtime) sle_g_runtime_submitted(a->g_runtime,&tx);
        int64_t witness_end=witness_deadline(sync,c.wave.n);
        /* Retune has completed before arming; guard samples keep transition
         * data out of the demodulator. The gate starts at the future event. */
        atomic_store(&r->mute,0);
        a->events++;
        record(a,"event_scheduled",",\"k\":%" PRId64 ",\"slot\":%u,\"mhz\":%d,\"seed\":%u,"
            "\"sync_sample\":%" PRId64 ",\"reply_sample\":%" PRId64 ",\"tx_start\":%" PRId64 ",\"nesn\":%u",
            tx.k,tx.ev.slot,tx.ev.mhz,tx.ev.white_seed,sync,second,c.tx_start,tx.nesn);
        int leak=0, reply=0, bad=0, nowitness=0;
        while (live(a)) {
            sle_rt_received f; int got=next_frame(a,c.seq,&f);
            if (got<0) { bad=1; break; }
            if (got) {
                sle_frame_t *v=&f.f.frame;
                int64_t sample=(int64_t)f.f.sample_index, error=0;
                if (v->kind==SLE_FRAME_CONNECT && v->seed==tx.ev.white_seed && !v->conn_empty==!tx.empty &&
                    v->crc12_ok && sample < second-SLE_RT_REPLY_TOL && sample >= sync-SAMPLES_US(40)) {
                    /* Require the exact locally sent header, then only the
                     * early window can refresh the TX/RX offset. */
                    if (v->conn_sn!=tx.sn || v->conn_nesn!=tx.nesn || v->conn_pkt_type!=tx.ptype ||
                        v->conn_flow!=tx.flow) continue;
                    if (v->payload_len!=tx.len || (tx.len &&
                        (!v->has_crc24 || !v->crc24_ok || memcmp(v->payload,tx.data,tx.len)))) continue;
                    e=observe_cal(a,c.tx_start+sle_rt_sync_in_wave(),sample);
                    record(a,"event_leakage",",\"k\":%" PRId64 ",\"error_samples\":%" PRId64 ",\"result\":\"%s\"",
                        tx.k,sample-sync,sle_rt_result_name(e));
                    if (e) { a->reason="connection_offset_jump"; bad=1; break; }
                    leak=1; continue;
                }
                e=sle_rt_reply_matches(&tx,&l->s,&f.f,&error);
                record(a,"peer_window",",\"k\":%" PRId64 ",\"result\":\"%s\",\"error_samples\":%" PRId64,
                    tx.k,sle_rt_result_name(e),error);
                if (e || reply) continue;
                if (!leak) {
                    record(a,"peer_without_tx_witness",",\"k\":%" PRId64,tx.k);
                    continue;
                }
                /* The demod target already performs the same configured A2
                 * decode as sle_link_decode; retain BODYFAIL for header ACK. */
                sle_link_rx_t rx={.kind=v->has_crc24 && !v->crc24_ok ? SLE_RX_BODYFAIL : SLE_RX_OK,
                    .empty=v->conn_empty,.sn=v->conn_sn,.nesn=v->conn_nesn,.flow=v->conn_flow,
                    .ptype=v->conn_pkt_type,.data=v->payload,.len=v->payload_len};
                sle_link_rx_out_t out;
                sle_rt_rx authenticated;
                if (a->g_runtime) {
                    int pe=sle_g_runtime_rx(a->g_runtime,l,&rx,&out,&authenticated,(uint64_t)(sle_iio_now_ns()/1000000));
                    sle_pair_status_t ps; sle_pair_status(&a->g_runtime->pair,&ps);
                    record(a,"pair_rx",",\"result\":%d,\"ptype\":%u,\"control_type\":%u,\"pair_control\":%d,"
                        "\"duplicate\":%d,\"mic\":%d,\"tx_next\":%" PRIu64 ",\"rx_next\":%" PRIu64,
                        pe,rx.ptype,authenticated.opcode,authenticated.pair_control,
                        authenticated.duplicate,authenticated.mic,ps.tx_next,ps.rx_next);
                    if (pe<0) { a->reason="pair_rx_failed"; bad=1; break; }
                    if (pe>0) continue;
                } else sle_link_on_rx(l,&rx,&out);
                reply=1; a->received++;
                if (rx.kind==SLE_RX_OK) {
                    if (!a->valid_received) {
                        a->connected_ns=sle_samples_to_ns(sample,SLE_RT_FS);
                        record(a,"peer_link_observed",",\"k\":%" PRId64,tx.k);
                        /* Like 1.10.108 gle_tm_lcid_init: our own CMTC request,
                         * only when this run carries data (--pair or SSAP);
                         * the empty-only radio connection mode is unchanged. */
                        uint8_t q[SLE_CMTC_REQ_SDU_LEN+2]; size_t qn;
                        if (!(a->g_runtime || opt.ssap_mtu)) {}
                        else if (sle_cmtc_capability_request(0,q+2,sizeof q-2,&qn) ||
                            (q[0]=(uint8_t)((qn&0x1f)<<3), q[1]=(uint8_t)((qn>>5)&0x3f),
                             sle_rt_queue(&a->tx_store,l,SLE_PTYPE_DATA,q,qn+2)))
                            a->ssap_failed=1;
                        else record(a,"cmtc_capability_req_queued",",\"identifier\":0,\"bitmap\":%u",SLE_CMTC_BITMAP);
                    }
                    a->last_peer_ns=sle_samples_to_ns(sample,SLE_RT_FS);
                    a->valid_received++;
                }
                record(a,"link_rx",",\"k\":%" PRId64 ",\"deliver\":%u,\"badbody\":%u,\"down\":%d",
                    tx.k,out.deliver,out.badbody,out.went_down);
                if (out.deliver && out.len) {
                    char h[2*SLE_PAIR_WIRE_MAX+1]; hex(h,sizeof h,out.data,out.len);
                    record(a,"link_deliver",",\"k\":%" PRId64 ",\"ptype\":%u,\"len\":%u,\"payload\":\"%s\"",
                        tx.k,out.ptype,out.len,h);
                    if (out.ptype==SLE_PTYPE_DATA) ssap_on_deliver(a,l,out.data,out.len);
                }
                if (a->g_runtime) sle_rt_wipe(&authenticated,sizeof authenticated);
            } else {
                int64_t head=atomic_load(&r->rx_head);
                /* Leakage must be present after the complete transmitted frame.
                 * A TX slip into the peer window therefore cannot establish
                 * or sustain a connection without a separate local witness. */
                if (!leak && head>witness_end) {
                    /* No local witness: the event counts as lost (a peer reply
                     * is never accepted without it). Abort only on a run. */
                    nowitness=1; break;
                }
                if ((reply && leak) || sle_rt_expired(head,c.rx_end+SLE_RT_BLOCK)) break;
                pause_ctl();
            }
        }
        if (bad || !live(a)) break;
        if (nowitness) {
            witness_run++;
            record(a,"event_witness_missing",",\"k\":%" PRId64 ",\"run\":%d,\"limit\":%d",
                tx.k,witness_run,SLE_RT_WITNESS_MISS_LIMIT);
            if (witness_run>=SLE_RT_WITNESS_MISS_LIMIT) { a->reason="event_leakage_missing"; break; }
        } else witness_run=0;
        if (!reply) {
            sle_link_rx_t rx={.kind=SLE_RX_NONE}; sle_link_rx_out_t out;
            sle_link_on_rx(l,&rx,&out); a->misses++;
            record(a,"event_timeout",",\"k\":%" PRId64,tx.k);
        }
        if (l->down) {
            a->reason="peer_disconnect_or_bad_control";
            record(a,"link_down",",\"reason_code\":%u",l->down_reason); break;
        }
        if (!opt.interactive && a->valid_received>1 && connection_accepted(a) &&
            (!a->g_runtime || (a->g_runtime->encrypted_ms && (uint64_t)(sle_iio_now_ns()/1000000)>=
                a->g_runtime->encrypted_ms+(uint64_t)opt.hold_seconds*1000)) &&
            sle_rt_maintained(a->connected_ns,a->last_peer_ns,
                sle_samples_to_ns(sle_rt_radio_now(r),SLE_RT_FS),(int64_t)opt.hold_seconds*1000000000,
                (int64_t)l->s.timeout_ms*1000000,PEER_FRESH_NS)) {
            a->reason=a->g_runtime ? (opt.ssap_mtu ? "protected_ssap_verified":"encrypted_hold_only") :
                opt.ssap_write ? "ssap_write_verified":"connection_maintained"; result=0;
            record(a,"connection_maintained",",\"valid_peer_span_ns\":%" PRId64
                ",\"valid_peer_frames\":%u",a->last_peer_ns-a->connected_ns,a->valid_received);
            break;
        }
        atomic_store(&r->depth,16*1024/SLE_RT_BLOCK); /* 4 ms; grow with the continuous stream intact */
    }
    if (a->g_runtime) {
        sle_pair_status_t ps; sle_pair_status(&a->g_runtime->pair,&ps);
        record(a,"pair_final",",\"state\":%d,\"error\":%d,\"detail\":\"%s\",\"secure\":%d,"
            "\"tx_next\":%" PRIu64 ",\"rx_next\":%" PRIu64 ",\"mic_ok\":%" PRIu64 ",\"mic_failed\":%" PRIu64,
            ps.state,a->g_runtime->error,sle_pair_error_string(a->g_runtime->error),ps.secure,ps.tx_next,ps.rx_next,
            a->g_runtime->mic_ok,a->g_runtime->mic_failed);
    }
    record(a,"acceptance",",\"encrypted\":%s,\"ssap_validated\":%s,\"ssap_write_verified\":%s,"
        "\"protected_tx_acked\":%" PRIu64 ",\"protected_rx\":%" PRIu64 ",\"encrypted_since_ms\":%" PRIu64
        ",\"scope\":\"%s\",\"ok\":%s",
        a->g_runtime && sle_g_runtime_encrypted(a->g_runtime) ? "true":"false",a->ssap_validated ? "true":"false",
        a->ssap_write_verified ? "true":"false",a->g_runtime ? a->g_runtime->protected_tx_acked:0,
        a->g_runtime ? a->g_runtime->protected_rx:0,a->g_runtime ? a->g_runtime->encrypted_ms:0,
        a->g_runtime ? (opt.ssap_mtu ? "protected_business":"encrypted_hold_only") :
        opt.ssap_write ? "ssap_write":"link_hold",result ? "false":"true");
    record(a,"sdu_rx_end",",\"pending\":%s,\"bytes\":%zu,\"fragments\":%u",
        a->sdu_rx.pending ? "true":"false",a->sdu_rx.len,a->sdu_rx.fragments);
    sle_sdu_rx_init(&a->sdu_rx,0);
    free(l);
    sle_rt_wipe(&a->tx_store,sizeof a->tx_store);
    return result;
}

static void hw_dump(app *a)
{
    char path[4096]; snprintf(path,sizeof path,"%s.a%d.hw.jsonl",opt.log,a->attempt);
    FILE *f=fopen(path,"w"); int err=!f || sle_rt_hwstat_write(a->hw,f,a->attempt);
    if (f && fclose(f)) err=1;
    record(a,"hw_status",",\"path\":\"%s\",\"polls\":%" PRIu64 ",\"max_gap_ns\":%" PRId64
        ",\"dac_hits\":%" PRIu64 ",\"adc_hits\":%" PRIu64 ",\"events\":%" PRIu64 ",\"dropped\":%" PRIu64
        ",\"start_ns\":%" PRId64 ",\"end_ns\":%" PRId64 ",\"write_error\":%d",
        path,a->hw->polls,a->hw->max_gap_ns,a->hw->dac_hits,a->hw->adc_hits,a->hw->n_events,
        a->hw->dropped,a->hw->start_ns,a->hw->end_ns,err);
}
static void usage(const char *name)
{
    printf("Usage: %s --selftest | [options]\n"
        "  --mode calibrate|access|connect  (default connect; all three use live RF)\n"
        "  --attempts N --seconds N --log PATH (append JSONL; exclusive device use)\n"
        "  --seconds N: scan/access budget per attempt (default 60)\n"
        "  --connect-seconds N: separate connection budget (default 15)\n"
        "  --hold-seconds N: valid peer span for success (default 10, minimum 6)\n"
        "  Short connection budgets record observations only; last valid reply <=100 ms old.\n"
        "  --server 01:02:03:04:05:06 --local c2:53:4c:45:00:10\n"
        "  --lid 0x66a275 --crc-init 0xe4004c6e --base-slot 0xdf488c\n"
        "  --resource-layout standard|legacy-ws63 (default standard)\n"
        "  --tx-gain DB [-89.75,0] --rx-gain DB [0,73]\n"
        "  --tx-cfo-hz HZ (default 0); --auto-cfo adds coarse primary-sync estimate\n"
        "  --req-shift-us US [-100,100] for the auxiliary timing window\n"
        "  --hw-status: measurement only; poll DAC underflow/ADC overflow sticky bits via /dev/mem\n"
        "    (--hw-prio N CPU0 FIFO, 0=OTHER; --hw-period-us N) and write LOG.aN.hw.jsonl\n"
        "    --hw-cpu 0|1 poller CPU (default 0; 1 shares the radio CPU below its priority)\n"
        "    --hw-dma also time AXI-DMAC IRQ_PENDING (interrupt service delay; use --hw-cpu 1)\n"
        "    defaults --hw-prio 0 --hw-period-us 200 (FIFO 50 / 50 us added ~17 pts CPU0)\n"
        "  --cal-depth N TX blocks held while calibrating (default %d, access depth %d..16)\n"
        "  --ssap-mtu N: SSAP exchange; once the link is up, queue one SSAP EXCHANGE_INFO_REQ\n"
        "    (MTU N, version 0x0001) in a DTAP basic frame on TCID 0x0A (OpenHarmony layout)\n"
        "  --event-log PATH: create a separate live attempt/WRITE_RSP event file (default off)\n"
        "    Use a new local tmpfs path; interactive mode defers events until radio stops.\n"
        "  --ssap-write TEXT: after the MTU response, FIND_STRUCTURE_REQ (PROPERTY, 1..0xFFFF)\n"
        "    then WRITE_REQ of TEXT (<=48 bytes) to the first property handle found\n"
        "    Success requires a validated WRITE_RSP, not just a maintained connection.\n"
        "  --interactive 0|1: encrypted console (default off); implies --pair and MTU 520.\n"
        "    Discover the write property, then send typed lines (<=46 bytes + CRLF).\n"
        "    One pending write, 5-second RSP timeout; notifications print live.\n"
        "    Setup uses --connect-seconds; ready console cap 24 hours; no hold-success exit.\n"
        "    Conflicts with --ssap-write. Ctrl+C stops; EOF keeps the connection and partial line.\n"
        "    Complete buffered lines still send after EOF; logs bounded to 32 MiB.\n"
        "  --pair: fresh Just Works pairing and CCM; SSAP waits for verified encrypted 0007.\n"
        "    With SSAP, success requires protected bidirectional business; without, encrypted hold only.\n"
        "    Pairing is on by default; nonempty TX requires zero CFO and <=96 wire bytes.\n"
        "  --pair-variant HEX[,HEX..]: implies --pair; attempt i uses the i-th SLE_PAIR_V_*\n"
        "    explicit profile mask (default 0x200 SDK108; 0 = historical hypothesis)\n"
        "  --ssap-frame seg|idx|raw: link data header (default seg: packet type 0 with the\n"
        "    46803.2 table 146 segment/length field; idx: type 2 with index 0xFFFF; raw: none)\n"
        "  --exclude-mhz LO:HI: clear these channels from the request hop map\n"
        "    (exercises the compatibility channel remapping)\n"
        "  Connection: an event without the local TX witness is treated as lost\n"
        "    (peer reply ignored); stop after %d consecutive such events.\n"
        "  --cpu-rt 1 --cpu-ctl 0 --prio-rt 80 --prio-ctl 60\n"
        "4 MS/s, 1024-sample mmap blocks, TX 3 blocks (--cal-depth while calibrating) then 16 in connection.\n"
        "Scan/calibration use 10 dB energy gating with previous/following blocks; scheduled windows bypass it.\n"
        "Access: TX retune then submit; RX retune before response (2300 us each).\n"
        "Admission includes 512 us command ACK, DMA horizon and 128 us guard.\n"
        "Auxiliary profile (2500/6250 us, +25 us primary correction) is assumed.\n"
        "Replies limited to 3 ms; WS63 pairing profile validated for protected 0007 and SSAP.\n"
        "Exit: 0 selected milestone observed; 1 failure or interactive signal stop; 2 CLI; otherwise 128+signal.\n"
        "--selftest runs the separately built test_sle_radio_core beside this executable.\n"
        "Offline selftests do not demonstrate WS63 interoperability.\n",name,SLE_RT_CAL_DEPTH,SLE_RT_ACCESS_DEPTH,SLE_RT_WITNESS_MISS_LIMIT);
}
static int addr(const char *s,uint8_t out[6])
{
    unsigned x[6]; int n=0;
    if (sscanf(s,"%2x:%2x:%2x:%2x:%2x:%2x%n",x,x+1,x+2,x+3,x+4,x+5,&n)!=6 || s[n]) return -1;
    for (int i=0;i<6;i++) out[i]=(uint8_t)x[i];
    return 0;
}
static int parse(int argc,char **argv)
{
    int pair_explicit=0;
    for (int i=1;i<argc;i++) {
        const char *key=argv[i];
        if (!strcmp(key,"--help")) { usage(argv[0]); return 1; }
        if (!strcmp(key,"--selftest")) return argc==2 ? 3 : -1;
        if (!strcmp(key,"--auto-cfo")) { opt.auto_cfo=1; continue; }
        if (!strcmp(key,"--hw-status")) { opt.hw_status=1; continue; }
        if (!strcmp(key,"--hw-dma")) { opt.hw_dma=1; continue; }
        if (!strcmp(key,"--pair")) { opt.pair=1; pair_explicit=1; continue; }
        if (!strcmp(key,"--resource-layout") && i+1<argc) {
            const char *v=argv[++i];
            if (!strcmp(v,"standard")) opt.resource_layout=SLE_RESOURCE_STANDARD;
            else if (!strcmp(v,"legacy-ws63")) opt.resource_layout=SLE_RESOURCE_LEGACY_WS63;
            else return -1;
            continue;
        }
        if (!strcmp(key,"--ssap-frame") && i+1<argc) {
            const char *m=argv[++i];
            if (!strcmp(m,"seg")) opt.ssap_frame=0; else if (!strcmp(m,"idx")) opt.ssap_frame=1;
            else if (!strcmp(m,"raw")) opt.ssap_frame=2; else return -1;
            continue;
        }
        if (!strcmp(key,"--ssap-write") && i+1<argc) {
            opt.ssap_write=argv[++i];
            if (!*opt.ssap_write || strlen(opt.ssap_write)>48) return -1;
            continue;
        }
        if (!strcmp(key,"--pair-variant") && i+1<argc) {
            /* Comma-separated hex SLE_PAIR_V_* masks, one per attempt (diagnostic). */
            const char *s=argv[++i]; opt.pair_variants=0;
            while (*s && opt.pair_variants<100) {
                char *end; unsigned long v=strtoul(s,&end,16);
                if (end==s || v>SLE_PAIR_V_MASK || (*end && *end!=',') ||
                    ((v&SLE_PAIR_V_COUNT_PLAIN) && (v&SLE_PAIR_V_CTR1))) return -1;
                opt.pair_variant[opt.pair_variants++]=(unsigned)v;
                s=*end ? end+1 : end;
            }
            if (*s || !opt.pair_variants) return -1;
            opt.pair=1; pair_explicit=1; continue;
        }
        if (!strcmp(key,"--ssap-mtu") && i+1<argc) {
            char *end; long v=strtol(argv[++i],&end,10);
            if (*end || v<23 || v>1024) return -1;
            opt.ssap_mtu=(int)v; continue;
        }
        if (!strcmp(key,"--exclude-mhz") && i+1<argc) {
            int lo, hi, n=0;
            if (sscanf(argv[++i],"%d:%d%n",&lo,&hi,&n)!=2 || argv[i][n] || lo<2402 || hi>2480 || lo>hi) return -1;
            opt.exclude_lo=lo; opt.exclude_hi=hi; continue;
        }
        if (++i==argc) return -1;
        const char *v=argv[i];
        if (!strcmp(key,"--log")) { opt.log=v; continue; }
        if (!strcmp(key,"--event-log")) { opt.event_log=v; continue; }
        if (!strcmp(key,"--server")) { if (addr(v,opt.server)) return -1; continue; }
        if (!strcmp(key,"--local")) { if (addr(v,opt.local)) return -1; continue; }
        if (!strcmp(key,"--mode")) {
            if (!strcmp(v,"calibrate")) opt.mode=1;
            else if (!strcmp(v,"access")) opt.mode=2;
            else if (!strcmp(v,"connect")) opt.mode=0;
            else return -1;
            continue;
        }
        char *end; errno=0; double d=strtod(v,&end);
        if (errno || end==v || *end || !isfinite(d)) return -1;
#define REAL(k,field) if (!strcmp(key,k)) { opt.field=d; continue; }
        REAL("--tx-gain",tx_gain) REAL("--rx-gain",rx_gain) REAL("--tx-cfo-hz",cfo) REAL("--req-shift-us",shift_us)
#undef REAL
        if (d<0 || d>UINT32_MAX || floor(d)!=d) return -1;
        uint32_t u=(uint32_t)d;
        if (!strcmp(key,"--lid")) { opt.lid=u; continue; }
        if (!strcmp(key,"--crc-init")) { opt.crc=u; continue; }
        if (!strcmp(key,"--base-slot")) { opt.slot=u; continue; }
        if (u>INT_MAX) return -1;
#define INT(k,field) if (!strcmp(key,k)) { opt.field=(int)u; continue; }
        INT("--interactive",interactive)
        INT("--attempts",attempts) INT("--seconds",seconds) INT("--cpu-rt",cpu_rt) INT("--cpu-ctl",cpu_ctl)
        INT("--connect-seconds",connect_seconds) INT("--hold-seconds",hold_seconds)
        INT("--prio-rt",prio_rt) INT("--prio-ctl",prio_ctl)
        INT("--hw-prio",hw_prio) INT("--hw-period-us",hw_period_us) INT("--hw-cpu",hw_cpu) INT("--cal-depth",cal_depth)
#undef INT
        return -1;
    }
    /* Standalone calibration/access stop before pairing can run. */
    if (opt.mode && !pair_explicit) opt.pair=0;
    if (opt.interactive) opt.pair=1;
    if ((opt.ssap_write || opt.interactive) && !opt.ssap_mtu) opt.ssap_mtu=520;
    return (opt.interactive!=0 && opt.interactive!=1) || (opt.interactive && opt.ssap_write) ||
        (opt.pair && (opt.mode || opt.auto_cfo || opt.cfo!=0.0)) ||
        opt.attempts<1 || opt.attempts>100 || opt.seconds<1 || opt.seconds>600 ||
        opt.connect_seconds<1 || opt.connect_seconds>600 || opt.hold_seconds<6 || opt.hold_seconds>600 ||
        opt.tx_gain>0 || opt.tx_gain< -89.75 || opt.rx_gain<0 || opt.rx_gain>73 ||
        fabs(opt.cfo)>200000 || fabs(opt.shift_us)>100 || opt.cpu_rt!=1 || opt.cpu_ctl!=0 ||
        opt.prio_rt<1 || opt.prio_rt>99 || opt.prio_ctl<1 || opt.prio_ctl>=opt.prio_rt ||
        opt.hw_prio<0 || opt.hw_prio>=opt.prio_rt || opt.hw_period_us<20 || opt.hw_period_us>1000 ||
        opt.hw_cpu<0 || opt.hw_cpu>1 || (opt.hw_dma && !opt.hw_status) ||
        opt.cal_depth<SLE_RT_ACCESS_DEPTH || opt.cal_depth>SLE_RT_TX_BUFFERS ? -1 : 0;
}
/* Tests are built separately; keep --selftest as an offline launcher. */
static int run_selftest(void)
{
    char path[PATH_MAX];
    ssize_t n=readlink("/proc/self/exe",path,sizeof path-1);
    if (n<0 || (size_t)n>=sizeof path-1) { perror("selftest executable path"); return 1; }
    path[n]=0;
    char *name=strrchr(path,'/');
    const char test[]="test_sle_radio_core";
    if (!name || (size_t)(name+1-path)+sizeof test>sizeof path) return 1;
    memcpy(name+1,test,sizeof test);
    execl(path,path,(char *)NULL);
    fprintf(stderr,"Cannot run %s: %s. Build the separate test target first.\n",path,strerror(errno));
    return 1;
}
int main(int argc,char **argv)
{
    int parsed=parse(argc,argv);
    if (parsed==1) return 0;
    if (parsed==3) return run_selftest();
    if (parsed<0) { usage(argv[0]); return 2; }
    app a={.reason="initialization_failed"};
    if (sle_rt_peer_init(&a.peer,opt.local,opt.server,opt.lid,opt.crc,opt.slot)) return 2;
    if (opt.exclude_lo) {
        for (int mhz=opt.exclude_lo; mhz<=opt.exclude_hi; mhz++)
            a.peer.txi.hop_map[(mhz-2402)/8]&=(uint8_t)~(1u<<((mhz-2402)%8));
        uint8_t used[76];
        if (sle_hop_map_used(a.peer.txi.hop_map,a.peer.txi.hop_map_len,used)<2) return 2;
    }
    a.log=calloc(1,LOG_CAP); a.radio=calloc(1,sizeof *a.radio); a.requests=calloc(76,sizeof *a.requests);
    a.cache=calloc(1,sizeof *a.cache);
    if (opt.hw_status) {
        a.hw=calloc(1,sizeof *a.hw);
        if (!a.hw || sle_rt_hwstat_open(a.hw)) { fprintf(stderr,"hw-status: /dev/mem map or core version check failed\n"); free(a.hw); return 2; }
        a.hw_open=1;
        if (opt.hw_dma && sle_rt_hwstat_track_dma(a.hw)) { fprintf(stderr,"hw-dma: DMAC map or version check failed\n"); sle_rt_hwstat_close(a.hw); free(a.hw); return 2; }
    }
    if (!a.log || !a.radio || !a.requests || !a.cache) {
        free(a.log); free(a.radio); free(a.requests); free(a.cache); return 1;
    }
    if (prepare_waves(&a)) { free(a.log); free(a.radio); free(a.requests); free(a.cache); return 1; }
    FILE *log=fopen(opt.log,"a");
    if (!log) { perror(opt.log); free(a.log); free(a.radio); free(a.requests); free(a.cache); return 1; }
    if (opt.event_log) {
        /* Exclusive creation also rejects an alias of the main journal and
         * prevents an old attempt's event file from unlocking UART injection. */
        a.event_output=fopen(opt.event_log,"wx");
        if (!a.event_output || setvbuf(a.event_output,NULL,_IONBF,0)) {
            perror(opt.event_log);
            if (a.event_output) fclose(a.event_output);
            fclose(log); free(a.log); free(a.radio); free(a.requests); free(a.cache);
            return 1;
        }
    }
    int rc=1, restored=0;
    if (install_signals()) goto out;
    if (opt.interactive) {
        if (a.event_output) {
            a.event_buffer=calloc(1,EVENT_CAP);
            if (!a.event_buffer) goto out;
        }
        a.stdin_flags=fcntl(STDIN_FILENO,F_GETFL);
        if (a.stdin_flags<0 || fcntl(STDIN_FILENO,F_SETFL,a.stdin_flags|O_NONBLOCK)<0) goto out;
        a.stdin_active=1;
        a.console_flags=fcntl(STDOUT_FILENO,F_GETFL);
        if (a.console_flags<0 || fcntl(STDOUT_FILENO,F_SETFL,a.console_flags|O_NONBLOCK)<0) goto out;
        a.console_active=1;
    }
    /* Pin control before any device activity; CPU0's FIFO priority is below
     * CPU1's. Allocate the journal and wave bank before mlockall. */
    if (sle_iio_realtime(opt.cpu_ctl,opt.prio_ctl)) goto out;
    for (a.attempt=1;a.attempt<=opt.attempts && !interrupted;a.attempt++) {
        int ok=0, session_started=0;
        a.reason="initialization_failed"; a.events=a.received=a.misses=a.skipped=a.valid_received=0;
        a.connected_ns=a.last_peer_ns=0; a.connecting=a.request_submitted=a.cleanup_failed=a.access_timing_verified=0;
        sle_rt_cal_clear(&a.cal); /* DMA sample indices restart for each attempt. */
        if (opt.auto_cfo) a.cache->valid=0;
        a.primary_pending=0; a.n_slack=0; a.copy_ns=a.cfo_age_samples=0; a.cfo_delta=0;
        a.deadline=sle_iio_now_ns()+(int64_t)opt.seconds*1000000000;
        record(&a,"attempt_start",",\"mode\":%d,\"lid\":%u,\"crc_init\":%u,\"base_slot\":%u,"
            "\"tx_gain\":%.2f,\"rx_gain\":%.2f,\"shift_us\":%.3f,\"auto_cfo\":%d,"
            "\"local\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"server\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",
            opt.mode,opt.lid,opt.crc,opt.slot,opt.tx_gain,opt.rx_gain,opt.shift_us,opt.auto_cfo,
            opt.local[0],opt.local[1],opt.local[2],opt.local[3],opt.local[4],opt.local[5],
            opt.server[0],opt.server[1],opt.server[2],opt.server[3],opt.server[4],opt.server[5]);
        if (opt.interactive) record(&a,"interactive_config",",\"enabled\":true,\"max_text_bytes\":46,\"write_timeout_ms\":5000,\"connection_cap_seconds\":86400");
        if (journal_failed(&a)) goto attempt_done;
        record(&a,"config",",\"scan_access_seconds\":%d,\"connect_seconds\":%d,\"hold_seconds\":%d,"
            "\"peer_fresh_ns\":%" PRId64 ",\"supervision_ms\":%u,\"attempt_limit\":%d,"
            "\"cpu_rt\":%d,\"cpu_ctl\":%d,\"prio_rt\":%d,\"prio_ctl\":%d,\"tx_cfo_hz\":%.3f,"
            "\"fs\":%d,\"block_samples\":%d,\"access_tx_blocks\":%d,\"cal_tx_blocks\":%d,\"connection_tx_blocks\":%d,"
            "\"access_tx_retune_budget_us\":%d,\"access_rx_retune_budget_us\":%d,\"access_ack_budget_us\":%d,"
            "\"access_lead_samples\":%" PRId64 ",\"access_response_lead_samples\":%" PRId64 ",\"tx_guard_samples\":%d,"
            "\"cal_ttl_samples\":%d,\"offset_tolerance_samples\":%d,\"reply_tolerance_samples\":%d,"
            "\"energy_factor\":%u,\"energy_learn_blocks\":%u,\"lag_limit_ns\":3000000,"
            "\"reply_gate_us\":3000,\"aux_correction_us\":25,\"request_offset_us\":2500,\"response_offset_us\":6250,\"resource_layout\":\"%s\"",
            opt.seconds,opt.connect_seconds,opt.hold_seconds,(int64_t)PEER_FRESH_NS,
            a.peer.txi.timeout_10ms*10u,opt.attempts,opt.cpu_rt,opt.cpu_ctl,opt.prio_rt,opt.prio_ctl,opt.cfo,
            SLE_RT_FS,SLE_RT_BLOCK,SLE_RT_ACCESS_DEPTH,opt.cal_depth,16*1024/SLE_RT_BLOCK,SLE_RT_ACCESS_TX_RETUNE_US,SLE_RT_ACCESS_RX_RETUNE_US,SLE_RT_ACCESS_ACK_US,
            sle_rt_access_lead(),sle_rt_access_response_lead(1),TX_GUARD,
            CAL_TTL,SLE_RT_OFFSET_TOL,SLE_RT_REPLY_TOL,SLE_RT_ENERGY_FACTOR,SLE_RT_ENERGY_LEARN_BLOCKS,
            resource_layout_name(opt.resource_layout));
        record(&a,"wave_cache_policy",",\"cfo_ttl_samples\":%d,\"change_limit_hz\":%.0f,"
            "\"estimator\":\"sync_inner_56\",\"absolute_error_bound_hz\":null,"
            "\"request_channels\":76,\"empty_seeds\":64,\"empty_nesn_variants\":2,\"cache_bytes\":%zu",
            CFO_TTL,CFO_CHANGE_HZ,sizeof *a.cache);
        if (journal_failed(&a)) goto attempt_done;
        if (opt.pair) {
            a.g_runtime=calloc(1,sizeof *a.g_runtime);
            if (!a.g_runtime) { a.reason="pair_allocation"; goto attempt_done; }
            uint32_t sync_low32=sle_sync32_from_lid(a.peer.txi.first_lid);
            unsigned variant=opt.pair_variants ? opt.pair_variant[(a.attempt-1)%opt.pair_variants] : SLE_PAIR_V_COUNT_PLAIN;
            int pe=sle_g_runtime_init_variant(a.g_runtime,a.peer.local,a.peer.server,sync_low32,opt.cpu_ctl,variant);
            a.pair_logged_state=SLE_PAIR_UNINITIALIZED; a.pair_logged_error=0;
            record(&a,"pair_prepare",",\"result\":%d,\"before_radio\":true,\"rng\":\"OS\","
                "\"worker_policy\":\"SCHED_OTHER\",\"worker_cpu\":%d,\"sync_low32\":%u,"
                "\"empty_policy\":\"no_mic_no_counter_candidate\",\"witness_margin_us\":500,"
                "\"extended_control_router\":true,\"variant\":%u",pe,opt.cpu_ctl,sync_low32,variant);
            if (pe) { a.reason="pair_prepare_failed"; goto attempt_done; }
        }
        if (journal_failed(&a)) goto attempt_done;
        if (interrupted) { a.reason="signal"; goto attempt_done; }
        if (sle_rt_radio_setup(opt.tx_gain,opt.rx_gain)) {
            a.reason=interrupted ? "signal" : "attribute_setup"; goto attempt_done;
        }
        if (interrupted) { a.reason="signal"; goto attempt_done; }
        rf_ports(&a);
        if (a.hw) {
            if (sle_rt_hwstat_start(a.hw,a.radio,opt.hw_cpu,opt.hw_prio,(int64_t)opt.hw_period_us*1000)) { a.reason="hw_status_start"; goto attempt_done; }
            a.hw_running=1;
            record(&a,"hw_status_started",",\"cpu\":%d,\"prio\":%d,\"period_us\":%d,\"dma_track\":%d,\"dac_initial\":%u,\"adc_initial\":%u,\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64,
                opt.hw_cpu,opt.hw_prio,opt.hw_period_us,opt.hw_dma,a.hw->dac_initial,a.hw->adc_initial,
                (int64_t)atomic_load(&a.radio->rx_head),(int64_t)atomic_load(&a.radio->tx_head));
        }
        record(&a,"radio_start_call",",\"mono_before_ns\":%" PRId64,sle_iio_now_ns());
        if (sle_rt_radio_start(a.radio,opt.cpu_rt,opt.prio_rt)) { a.reason="radio_start"; goto attempt_done; }
        session_started=1;
        record(&a,"radio_started",",\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64,(int64_t)atomic_load(&a.radio->rx_head),(int64_t)atomic_load(&a.radio->tx_head));

        if (calibrate(&a)) goto stop;
        if (opt.mode==1) { a.reason="calibration_complete"; ok=1; goto stop; }
        sle_access_plan_t plan;
        if (scan(&a,&plan) || access_peer(&a,&plan)) goto stop;
        if (opt.mode==2) { a.reason="access_response_observed"; ok=1; goto stop; }
        ok=connection(&a,&plan)==0;
stop:
attempt_done:
        /* Invalidate orchestration before radio/crypto joins or final journal I/O.
         * This row has reserved main-journal space even after log_full. */
        record(&a,"attempt_stopping",",\"result\":\"%s\"",a.reason);
        if (a.hw_running) { if (sle_rt_hwstat_stop(a.hw)) { a.reason="hw_status_stop"; ok=0; } a.hw_running=0; }
        if (session_started) {
            atomic_store(&a.radio->stop,1);
            if (sle_rt_radio_stop(a.radio) || a.cleanup_failed) { a.reason="radio_stop_failed"; ok=0; }
        }
        /* Radio is stopped first; crypto may finish without delaying DMA
         * shutdown. Join precedes any wipe/free of the RNG context. */
        if (a.g_runtime) {
            if (sle_g_runtime_destroy(a.g_runtime)) { a.reason="pair_worker_join_failed"; ok=0; }
            else { free(a.g_runtime); a.g_runtime=NULL; }
        }
        if (opt.interactive) record(&a,"interactive_console",",\"dropped_display_bytes\":%zu",a.console_dropped);
        if (session_started) { rx_report(&a); }
        if (a.hw && session_started) hw_dump(&a);
        if (journal_failed(&a)) ok=0;
        record(&a,"attempt_end",",\"result\":\"%s\",\"milestone_observed\":%s,\"events\":%u,"
            "\"peer_frames\":%u,\"misses\":%u,\"skipped\":%u,\"observed_link_ns\":%" PRId64
            ",\"valid_peer_frames\":%u,\"request_submitted\":%s,\"access_timing_verified\":%s,\"last_peer_age_ns\":%" PRId64
            ",\"rx_blocks\":%" PRIu64 ",\"tx_blocks\":%" PRIu64 ",\"crc12_fail\":%" PRIu64
            ",\"crc24_fail\":%" PRIu64 ",\"truncated\":%" PRIu64 ",\"dropped_display_bytes\":%zu",
            a.reason,ok ? "true":"false",a.events,a.received,a.misses,a.skipped,
            a.valid_received ? a.last_peer_ns-a.connected_ns : 0,
            a.valid_received,a.request_submitted ? "true":"false",a.access_timing_verified ? "true":"false",
            a.valid_received ? sle_samples_to_ns(atomic_load(&a.radio->rx_head),SLE_RT_FS)-a.last_peer_ns : -1,
            session_started ? a.radio->n_rx : 0,session_started ? a.radio->n_tx : 0,
            session_started ? a.radio->crc12_fail : 0,session_started ? a.radio->crc24_fail : 0,
            session_started ? a.radio->truncated : 0,a.console_dropped);
        if (a.event_buffer && a.event_used) {
            if (fwrite(a.event_buffer,1,a.event_used,a.event_output)!=a.event_used || fflush(a.event_output)) a.event_failed=1;
            a.event_used=0;
        }
        if (a.log_full) fprintf(log,"{\"kind\":\"journal_capacity\",\"attempt\":%d}\n",a.attempt);
        if (fwrite(a.log,1,a.used,log)!=a.used ||
            (session_started && sle_rt_radio_timing_write(a.radio,log,(unsigned)a.attempt)) || fflush(log)) { perror("journal"); break; }
        a.used=0;
        fprintf(stderr,"attempt %d: %s; events=%u peer=%u missed=%u skipped=%u\n",
            a.attempt,a.reason,a.events,a.received,a.misses,a.skipped);
        if (journal_failed(&a)) { rc=1; break; }
        if (ok) { rc=0; break; }
        if (a.log_full || !strcmp(a.reason,"attribute_setup") || !strcmp(a.reason,"radio_start") ||
            !strcmp(a.reason,"radio_stop_failed") || a.g_runtime) break;
    }
out:
    restored=sle_rt_radio_restore();
    if (a.g_runtime && !sle_g_runtime_destroy(a.g_runtime)) { free(a.g_runtime); a.g_runtime=NULL; }
    if (fprintf(log,"{\"kind\":\"cleanup\",\"attributes_restored\":%s,\"signal\":%d}\n",
        restored ? "false":"true",(int)interrupted)<0) rc=1;
    if (a.event_output) {
        char row[160];
        int n=snprintf(row,sizeof row,"{\"kind\":\"cleanup\",\"attributes_restored\":%s,\"signal\":%d}\n",
            restored ? "false":"true",(int)interrupted);
        event_write(&a,row,(size_t)n);
        if (a.event_buffer && a.event_used &&
            fwrite(a.event_buffer,1,a.event_used,a.event_output)!=a.event_used) rc=1;
        if (fclose(a.event_output) || a.event_failed) rc=1;
    }
    /* stdout may share stdin's open file description (for example a tty),
     * so restore in reverse order to retain its original flags. */
    if (a.console_active && fcntl(STDOUT_FILENO,F_SETFL,a.console_flags)<0) rc=1;
    if (a.stdin_active && fcntl(STDIN_FILENO,F_SETFL,a.stdin_flags)<0) rc=1;
    free(a.event_buffer);
    if (fclose(log)) rc=1;
    if (restored) rc=1;
    if (a.hw_open) sle_rt_hwstat_close(a.hw);
    free(a.hw);
    munlockall(); free(a.requests); free(a.radio); free(a.log); free(a.cache);
    /* Match the T console: a user stop is not a business milestone. The
     * journal's signal/reason and cleanup fields distinguish it from failure. */
    return interrupted ? (opt.interactive ? 1:128+interrupted) : rc;
}
