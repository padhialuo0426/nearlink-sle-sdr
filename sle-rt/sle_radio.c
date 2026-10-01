#define _GNU_SOURCE
#include "sle_radio.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <math.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

void sle_rt_stop_signals(sigset_t *set)
{
    sigemptyset(set);
    sigaddset(set,SIGINT); sigaddset(set,SIGTERM);
    sigaddset(set,SIGHUP); sigaddset(set,SIGPIPE);
}

const char *sle_rt_io_error_name(int e)
{
    static const char *const names[] = {"ok", "thread_setup", "rx_dma", "tx_dma",
        "frame_queue_overflow", "tx_queue_drained", "dma_stall", "demod", "command", "rx_backlog_or_gap"};
    return e >= 0 && (size_t)e < sizeof names / sizeof names[0] ? names[e] : "unknown";
}
void sle_rt_ring_init(sle_rt_frame_ring *q)
{
    atomic_init(&q->head, 0); atomic_init(&q->tail, 0);
}
int sle_rt_ring_push(sle_rt_frame_ring *q, const sle_rt_received *f)
{
    unsigned h = atomic_load_explicit(&q->head, memory_order_relaxed);
    unsigned t = atomic_load_explicit(&q->tail, memory_order_acquire);
    if (h - t >= SLE_RT_FRAME_RING) return -1;
    q->frame[h % SLE_RT_FRAME_RING] = *f;
    atomic_store_explicit(&q->head, h + 1, memory_order_release);
    return 0;
}
int sle_rt_ring_pop(sle_rt_frame_ring *q, sle_rt_received *f)
{
    unsigned t = atomic_load_explicit(&q->tail, memory_order_relaxed);
    unsigned h = atomic_load_explicit(&q->head, memory_order_acquire);
    if (h == t) return -1;
    *f = q->frame[t % SLE_RT_FRAME_RING];
    atomic_store_explicit(&q->tail, t + 1, memory_order_release);
    return 0;
}

/* Attribute list is deliberately finite and single-thread owned. Save all
 * shared-clock attributes before changing either sampling rate or RF filters. */
static struct attr { const char *path; char old[96]; int saved; } attrs[] = {
    {SLE_IIO_PHY "out_voltage0_hardwaregain", "", 0},
    {SLE_IIO_PHY "in_voltage0_gain_control_mode", "", 0},
    {SLE_IIO_PHY "in_voltage0_hardwaregain", "", 0},
    {SLE_IIO_PHY "in_voltage_sampling_frequency", "", 0},
    {SLE_IIO_PHY "out_voltage_sampling_frequency", "", 0},
    {SLE_IIO_PHY "in_voltage_rf_bandwidth", "", 0},
    {SLE_IIO_PHY "out_voltage_rf_bandwidth", "", 0},
    {SLE_IIO_PHY "out_altvoltage0_RX_LO_frequency", "", 0},
    {SLE_IIO_PHY "out_altvoltage1_TX_LO_frequency", "", 0},
    {SLE_IIO_RXD "scan_elements/in_voltage0_en", "", 0},
    {SLE_IIO_RXD "scan_elements/in_voltage1_en", "", 0},
    {SLE_IIO_RXD "scan_elements/in_voltage2_en", "", 0},
    {SLE_IIO_RXD "scan_elements/in_voltage3_en", "", 0},
    {SLE_IIO_TXD "scan_elements/out_voltage0_en", "", 0},
    {SLE_IIO_TXD "scan_elements/out_voltage1_en", "", 0},
    {SLE_IIO_TXD "scan_elements/out_voltage2_en", "", 0},
    {SLE_IIO_TXD "scan_elements/out_voltage3_en", "", 0},
    {SLE_IIO_RXD "buffer/length", "", 0},
    {SLE_IIO_TXD "buffer/length", "", 0},
    {SLE_IIO_RXD "buffer/enable", "", 0},
    {SLE_IIO_TXD "buffer/enable", "", 0}
};
#define NATTR (sizeof attrs / sizeof attrs[0])
static int touched;
static void trim(char *v) { char *s = strpbrk(v, " \t\r\n"); if (s) *s = 0; }
static int set(const char *path, const char *v)
{
    touched = 1;
    return sle_iio_set(path, v);
}
int sle_rt_radio_setup(double tx, double rx)
{
    char v[96];
    if (!attrs[0].saved) {
        for (size_t i = 0; i < NATTR; i++) {
            if (sle_iio_read(attrs[i].path, attrs[i].old, sizeof attrs[i].old) || !attrs[i].old[0])
                return -1;
            trim(attrs[i].old); attrs[i].saved = 1;
        }
        if (strcmp(attrs[NATTR-1].old, "0") || strcmp(attrs[NATTR-2].old, "0")) {
            fprintf(stderr, "Radio refuses an already enabled RX/TX buffer\n"); return -1;
        }
    }
    snprintf(v, sizeof v, "%.2f", tx);
    if (set(attrs[0].path, v) || set(attrs[1].path, "manual")) return -1;
    snprintf(v, sizeof v, "%.0f", rx);
    if (set(attrs[2].path, v)) return -1;
    for (size_t i = 3; i <= 4; i++) if (set(attrs[i].path, "4000000")) return -1;
    for (size_t i = 5; i <= 6; i++) if (set(attrs[i].path, "1750000")) return -1;
    for (size_t i = 7; i <= 8; i++) if (set(attrs[i].path, "2424000000")) return -1;
    for (size_t i = 9; i <= 16; i++) if (set(attrs[i].path, (i-9)%4 < 2 ? "1" : "0")) return -1;
    snprintf(v, sizeof v, "%d", SLE_RT_BLOCK);
    for (size_t i = 17; i <= 18; i++) if (set(attrs[i].path, v)) return -1;
    for (size_t i = 19; i <= 20; i++) if (set(attrs[i].path, "0")) return -1;
    /* Rate readback is essential to all sample-domain scheduling. */
    for (size_t i = 3; i <= 4; i++)
        if (sle_iio_read(attrs[i].path, v, sizeof v) || strtoll(v, NULL, 10) != SLE_RT_FS) return -1;
    return 0;
}
int sle_rt_radio_retune(int tx, int mhz)
{
    if (mhz < 2402 || mhz > 2480) return -1;
    char v[32]; snprintf(v, sizeof v, "%d000000", mhz);
    return set(attrs[tx ? 8 : 7].path, v);
}
static int same_value(const char *a, const char *b)
{
    if (!strcmp(a,b)) return 1;
    char *ea, *eb; double va = strtod(a,&ea), vb = strtod(b,&eb);
    return ea != a && eb != b && !*ea && !*eb && isfinite(va) && isfinite(vb) && fabs(va-vb) < 0.00001;
}
int sle_rt_radio_restore(void)
{
    if (!touched) return 0;
    int bad = 0;
    sle_iio_restore_all();
    /* Also restore attributes with coupled side effects and those for which
     * a failed sle_iio_set might have missed its own snapshot. */
    if (attrs[1].saved && sle_iio_write(attrs[1].path,"manual")) bad=1;
    static const unsigned order[]={19,20,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,2,1,0};
    for (size_t j = 0; j < NATTR; j++) {
        size_t i = order[j];
        if (attrs[i].saved && sle_iio_write(attrs[i].path, attrs[i].old)) bad = 1;
    }
    for (size_t i = 0; i < NATTR; i++) {
        char v[96]={0};
        if (!attrs[i].saved) continue;
        int e = sle_iio_read(attrs[i].path, v, sizeof v);
        trim(v);
        /* AGC gain is a changing measurement, not a persistent setting. */
        if (i==2 && strcmp(attrs[1].old,"manual")) continue;
        if (e || !same_value(v, attrs[i].old)) {
            fprintf(stderr, "restore verification failed: %s\n", attrs[i].path); bad = 1;
        }
    }
    return bad ? -1 : 0;
}

/* Silent nonblocking variants of sle_iio_get/put on the same mapped queues.
 * sle_iio's error branches call perror; CPU1 must never perform stdio. */
#define BLOCK_ENQUEUE _IOWR('i', 0xa3, struct sle_iio_blk)
#define BLOCK_DEQUEUE _IOWR('i', 0xa4, struct sle_iio_blk)
static int dequeue(sle_iio_queue_t *q, struct sle_iio_blk *b)
{
    struct pollfd p = {.fd=q->fd, .events=q->tx ? POLLOUT : POLLIN};
    int n = poll(&p, 1, 0);
    if (n < 0) return errno == EINTR ? -2 : -1;
    if (!n) return -2;
    if (p.revents & (POLLERR|POLLHUP|POLLNVAL)) return -1;
    memset(b, 0, sizeof *b);
    if (ioctl(q->fd, BLOCK_DEQUEUE, b)) return errno == EAGAIN || errno == EINTR ? -2 : -1;
    if (b->id >= (unsigned)q->n || !q->addr[b->id] || q->b[b->id].size < q->bytes ||
        (!q->tx && b->bytes_used != q->bytes)) return -1;
    return (int)b->id;
}
static int enqueue(sle_iio_queue_t *q, int id)
{
    q->b[id].bytes_used = q->bytes;
    int rc;
    do rc = ioctl(q->fd, BLOCK_ENQUEUE, &q->b[id]); while (rc < 0 && errno == EINTR);
    return rc;
}
static void fail(sle_rt_radio *r, int error)
{
    int expected = 0;
    atomic_compare_exchange_strong(&r->error, &expected, error);
    atomic_store(&r->stop, 1);
}
static double estimate_cfo(sle_rt_radio *r, const sle_found_frame_t *f)
{
    int64_t s = (int64_t)f->sample_index;
    if (f->frame.kind != SLE_FRAME_BROADCAST || s < r->history_start+1 ||
        s+128 >= r->history_end) return NAN;
    uint8_t sync[32]; sle_sync_from_lid(0xffffff, sync);
    double sum = 0, ideal = 0;
    /* Coarse sync-only estimator. Average inner symbol samples, omit edges;
     * Gaussian transition bias and sub-sample timing remain a hardware test. */
    for (int b = 2; b < 30; b++) for (int k = 1; k <= 2; k++) {
        unsigned a = (unsigned)(s+b*4+k) & (SLE_RT_HISTORY-1), z = (a-1)&(SLE_RT_HISTORY-1);
        double i = r->history[2*a], q = r->history[2*a+1];
        double pi = r->history[2*z], pq = r->history[2*z+1];
        sum += atan2(q*pi-i*pq, i*pi+q*pq);
        ideal += sync[b] ? 250000 : -250000;
    }
    return (sum*SLE_RT_FS/6.283185307179586-ideal)/56;
}
static void on_frame(const sle_found_frame_t *f, void *user)
{
    sle_rt_radio *r = user;
    if (!f->frame.crc12_ok) return;
    sle_rt_rx_stats *st=&r->rx_stats[r->rx_mode]; st->frames++;
    sle_rt_received a = {.seq=r->seq, .f=*f, .cfo_hz=NAN};
    /* Calibration markers and A2 frames do not need atan2. Only estimate a
     * CRC-valid primary when CPU0 explicitly requests automatic CFO. */
    if (r->estimate_cfo && f->frame.kind==SLE_FRAME_BROADCAST && f->frame.crc24_ok &&
        f->frame.broadcast_type==3 && f->frame.packet_type==0 && f->frame.payload_len==12) {
        a.cfo_hz=estimate_cfo(r,f);
        if (isfinite(a.cfo_hz)) st->cfo_estimates++; else st->cfo_unavailable++;
    }
    if (sle_rt_ring_push(&r->frames,&a)) fail(r,SLE_RT_IO_OVERFLOW);
}
static void finish_demod(sle_rt_radio *r)
{
    r->truncated += sle_demod_channel_finish(&r->demod);
    r->crc12_fail += r->demod.stats.crc12_failures;
    r->crc24_fail += r->demod.stats.crc24_failures;
    memset(&r->demod.stats, 0, sizeof r->demod.stats);
}
int sle_rt_radio_rx_configure(sle_rt_radio *r, const sle_rt_command *c)
{
    int energy=!c->connect && c->rx_end==INT64_MAX;
    int keep=energy && r->energy_enabled && r->demod.channel_mhz==c->mhz && !r->was_muted;
    finish_demod(r);
    int e=sle_demod_channel_init(&r->demod,SLE_RT_FS,0,c->mhz,on_frame,r);
    if (!e && c->connect) {
        sle_connect_config_t cfg={.lid=c->lid,.white_seed=(uint8_t)c->seed,
            .crc_type=SLE_CRC_TYPE_24,.crc_init=c->crc,.max_payload_bytes=2047};
        e=sle_demod_add_connect_config_target(&r->demod,&cfg,SLE_RT_SYNC_ERRORS);
    } else if (!e) e=sle_demod_add_broadcast_target(&r->demod,(uint8_t)c->seed,0);
    if (e) return -1;
    /* All modes bypass the 63-tap FIR for CPU. Finite access/connection
     * windows add a 5-sample moving sum: plain bypass missed CRC-valid own
     * frames at ~35 LSB rms, a 15-tap FIR drained the 3-block TX queue
     * (2026-09-27 replay and board runs). Scan/calibration are unchanged. */
    sle_demod_set_fir_bypass(&r->demod,1); sle_demod_set_dedup(&r->demod,1);
    if (sle_demod_set_boxcar(&r->demod,energy ? 0:SLE_RT_WINDOW_BOXCAR)) return -1;
    r->seq=c->seq; r->gate_start=c->rx_start; r->gate_end=c->rx_end;
    r->estimate_cfo=c->estimate_cfo;
    r->rx_mode=energy ? (c->wave.n ? SLE_RT_RX_CAL:SLE_RT_RX_SCAN) : SLE_RT_RX_WINDOW;
    r->energy_enabled=energy;
    /* Preserve the quiet floor across cal -> scan and calibration nonces,
     * but never replay IQ from an old target/command as the previous block. */
    sle_rt_energy_reset(&r->energy,keep);
    return 0;
}
static int demod_history(sle_rt_radio *r, int64_t base, size_t n)
{
    sle_rt_rx_stats *st=&r->rx_stats[r->rx_mode];
    unsigned pos=(unsigned)base & (SLE_RT_HISTORY-1);
    if (base<r->history_start || n>SLE_RT_BLOCK || pos+n>SLE_RT_HISTORY || base+(int64_t)n>r->history_end) {
        st->history_errors++; return -1;
    }
    sle_stream_status_t status=sle_demod_channel_process(&r->demod,r->history+pos*2,n,(uint64_t)base);
    /* Gaps are intentional only when quiet blocks were skipped or the
     * explicit receive window starts. Overlap/backwards remains an error. */
    if (status!=SLE_STREAM_OK && status!=SLE_STREAM_GAP) return -1;
    st->demod_blocks++; st->demod_samples+=n;
    return 0;
}
int sle_rt_radio_rx_block(sle_rt_radio *r, const int16_t *iq, int64_t base)
{
    if (!iq || base<0 || base%SLE_RT_BLOCK || base>INT64_MAX-SLE_RT_BLOCK ||
        (r->history_valid && base!=r->history_end)) return -1;
    if (!r->history_valid) { r->history_start=base; r->history_valid=1; }
    unsigned pos=(unsigned)base & (SLE_RT_HISTORY-1);
    memcpy(r->history+pos*2,iq,SLE_RT_BLOCK*4);
    r->history_end=base+SLE_RT_BLOCK;
    if (r->history_start<r->history_end-SLE_RT_HISTORY) r->history_start=r->history_end-SLE_RT_HISTORY;
    int64_t cs=atomic_load_explicit(&r->cap_start,memory_order_acquire);
    if (cs>=0 && r->cap && base+SLE_RT_BLOCK>cs && r->cap_len>=SLE_RT_BLOCK && r->cap_len%SLE_RT_BLOCK==0) {
        memcpy(r->cap+(base%r->cap_len)*2,iq,SLE_RT_BLOCK*4);
        atomic_store_explicit(&r->cap_filled,base+SLE_RT_BLOCK,memory_order_release);
    }
    sle_rt_rx_stats *st=&r->rx_stats[r->rx_mode]; st->blocks++;
    if (atomic_load(&r->mute)) {
        if (!r->was_muted) { finish_demod(r); sle_rt_energy_reset(&r->energy,0); }
        r->was_muted=1; r->history_start=r->history_end; st->muted++;
        return 0;
    }
    r->was_muted=0;
    int64_t a=base>r->gate_start ? base:r->gate_start;
    int64_t end=base+SLE_RT_BLOCK<r->gate_end ? base+SLE_RT_BLOCK:r->gate_end;
    if (!r->seq || end<=a) return 0;
    if (!r->energy_enabled || a!=base || end!=base+SLE_RT_BLOCK) {
        /* Finite access/connection windows always feed every requested
         * sample, even when their power is below the learned noise floor. */
        sle_rt_energy_reset(&r->energy,1);
        return demod_history(r,a,(size_t)(end-a));
    }
    unsigned flags=sle_rt_energy_step(&r->energy,iq);
    st->energy_blocks++; st->sampled+=r->energy.sampled; st->clipped+=r->energy.clipped;
    st->floor_sum=r->energy.floor_sum; st->peak_bin_sum=r->energy.peak_bin_sum;
    st->hot+=(flags&SLE_RT_GATE_HOT)!=0; st->learning+=(flags&SLE_RT_GATE_LEARNING)!=0;
    st->fail_open+=(flags&SLE_RT_GATE_OPEN)!=0; st->post+=(flags&SLE_RT_GATE_POST)!=0;
    if (flags&SLE_RT_GATE_PREVIOUS) {
        st->pre++;
        if (demod_history(r,base-SLE_RT_BLOCK,SLE_RT_BLOCK)) return -1;
    }
    if (flags&SLE_RT_GATE_CURRENT) return demod_history(r,base,SLE_RT_BLOCK);
    st->skipped++;
    return 0;
}
static void timing_fault(sle_rt_radio *r, sle_rt_timing_log *log,
                         enum sle_rt_late_source source, const sle_rt_command *c,
                         int64_t tx_head, int64_t rx_head, int queued)
{
    sle_rt_timing_fault *d=&log->entry[log->total++ % SLE_RT_TIMING_RING];
    *d=(sle_rt_timing_fault){.seq=c->seq, .source=source,
        .mono_ns=sle_iio_now_ns(), .tx_head=tx_head, .rx_head=rx_head,
        .tx_start=c->tx_start, .rx_start=c->rx_start, .rx_end=c->rx_end,
        .wave_samples=c->wave.n, .queue_depth=atomic_load(&r->depth),
        .tx_queued=queued};
}
int sle_rt_radio_timing_write(const sle_rt_radio *r, FILE *out, unsigned attempt)
{
    if (r->started) return -1;
    const sle_rt_timing_log *logs[]={&r->submit_timing,&r->consumer_timing};
    const char *const sources[]={"submit_rx_expired","consumer_rx_expired","renderer_start_late"};
    for (unsigned owner=0;owner<2;owner++) {
        const sle_rt_timing_log *log=logs[owner];
        uint64_t first=log->total>SLE_RT_TIMING_RING ? log->total-SLE_RT_TIMING_RING : 0;
        for (uint64_t i=first;i<log->total;i++) {
            const sle_rt_timing_fault *d=&log->entry[i % SLE_RT_TIMING_RING];
            /* tx_end is null for RX-only commands and malformed TX ranges. */
            char tx_end[32]="null";
            if (d->wave_samples && d->tx_start>=0 &&
                d->tx_start<=INT64_MAX-(int64_t)d->wave_samples)
                snprintf(tx_end,sizeof tx_end,"%" PRId64,d->tx_start+(int64_t)d->wave_samples);
            if (fprintf(out,"{\"kind\":\"radio_timing_fault\",\"attempt\":%u,"
                "\"mono_ns\":%" PRId64 ",\"seq\":%u,\"result\":\"late\",\"source\":\"%s\","
                "\"tx_head\":%" PRId64 ",\"rx_head\":%" PRId64 ",\"tx_start\":%" PRId64
                ",\"tx_end\":%s,\"wave_samples\":%zu,\"rx_start\":%" PRId64
                ",\"rx_end\":%" PRId64 ",\"queue_depth\":%d,\"tx_queued\":%d,\"deferred_log\":true}\n",
                attempt,d->mono_ns,d->seq,sources[d->source],d->tx_head,d->rx_head,
                d->tx_start,tx_end,d->wave_samples,d->rx_start,d->rx_end,
                d->queue_depth,d->tx_queued)<0) return -1;
        }
        if (log->total && fprintf(out,"{\"kind\":\"radio_timing_summary\",\"attempt\":%u,"
            "\"owner\":\"%s\",\"total\":%" PRIu64 ",\"overwritten\":%" PRIu64 "}\n",
            attempt,owner ? "consumer":"submit",log->total,first)<0) return -1;
    }
    return ferror(out) ? -1 : 0;
}
static void command(sle_rt_radio *r, int64_t head, unsigned owned)
{
    if (atomic_load(&r->stop)) return;
    if (!atomic_load_explicit(&r->pending, memory_order_acquire)) return;
    const sle_rt_command *c = &r->command;
    int64_t rx_head=atomic_load(&r->rx_head);
    int rc = c->rx_end <= rx_head ? SLE_RT_LATE : SLE_RT_OK;
    if (rc==SLE_RT_LATE)
        timing_fault(r,&r->consumer_timing,SLE_RT_LATE_CONSUMER_RX,c,head,rx_head,
                     r->txq.n-__builtin_popcount(owned));
    if (!rc && c->wave.n) {
        rc = sle_rt_render_arm(&r->renderer,head,c->tx_start,&c->wave);
        if (rc==SLE_RT_LATE)
            timing_fault(r,&r->consumer_timing,SLE_RT_LATE_RENDER_START,c,head,rx_head,
                         r->txq.n-__builtin_popcount(owned));
    }
    else if (!rc && r->renderer.active) rc = SLE_RT_BUSY;
    if (!rc && sle_rt_radio_rx_configure(r,c)) { sle_rt_render_clear(&r->renderer); rc=SLE_RT_RANGE; }
    atomic_store(&r->ack_result,rc);
    unsigned seq = c->seq;
    atomic_store_explicit(&r->pending,0,memory_order_release);
    atomic_store_explicit(&r->ack_seq,seq,memory_order_release);
}
static int feed_tx(sle_rt_radio *r, unsigned *owned, int64_t *head)
{
    struct sle_iio_blk b;
    int completed = 0, before = r->txq.n - __builtin_popcount(*owned);
    for (int i = 0; i < r->txq.n; i++) {
        int id = dequeue(&r->txq,&b);
        if (id == -2) break;
        if (id < 0 || (*owned & (1u<<id))) { fail(r,SLE_RT_IO_TX); return -1; }
        *owned |= 1u<<id; completed++;
    }
    if (before > 0 && completed == before) {
        if (atomic_load(&r->guard)) { fail(r,SLE_RT_IO_UNDERFLOW); return -1; }
        if (r->tx_drain_unguarded < SLE_RT_DRAIN_LOG) {
            r->tx_drain_head[r->tx_drain_unguarded] = *head;
            r->tx_drain_rx_head[r->tx_drain_unguarded] = atomic_load(&r->rx_head);
        }
        r->tx_drain_unguarded++;
    }
    int depth = atomic_load(&r->depth);
    for (int i = 0; i < r->txq.n && r->txq.n-__builtin_popcount(*owned) < depth; i++) {
        if (atomic_load(&r->stop)) return -1;
        if (!(*owned & (1u<<i))) continue;
        command(r,*head,*owned);
        if (sle_rt_render_block(&r->renderer,r->txcopy,*head,SLE_RT_BLOCK)) { fail(r,SLE_RT_IO_COMMAND); return -1; }
        memcpy(r->txq.addr[i],r->txcopy,sizeof r->txcopy);
        if (atomic_load(&r->stop)) return -1;
        if (enqueue(&r->txq,i)) { fail(r,SLE_RT_IO_TX); return -1; }
        *owned &= ~(1u<<i); *head += SLE_RT_BLOCK; r->n_tx++;
        atomic_store(&r->tx_head,*head);
    }
    return 0;
}
static void *stream(void *arg)
{
    sle_rt_radio *r = arg;
    if (sle_iio_realtime(r->cpu,r->prio)) {
        fail(r,SLE_RT_IO_THREAD); atomic_store(&r->exited,1); return NULL;
    }
    atomic_store(&r->ready,1);
    struct timespec nap = {0,50000};
    while (!atomic_load(&r->run) && !atomic_load(&r->stop)) nanosleep(&nap,NULL);
    int64_t rx = 0, tx = SLE_RT_ACCESS_DEPTH*SLE_RT_BLOCK, last = sle_iio_now_ns();
    int64_t epoch_mono=0, epoch_sample=0;
    unsigned owned = ((1u<<(unsigned)r->txq.n)-1u) & ~((1u<<SLE_RT_ACCESS_DEPTH)-1u);
    while (!atomic_load(&r->stop)) {
        command(r,tx,owned);
        if (feed_tx(r,&owned,&tx)) break;
        struct sle_iio_blk b;
        int id = dequeue(&r->rxq,&b);
        if (id == -2) {
            if (sle_iio_now_ns()-last > 100000000) { fail(r,SLE_RT_IO_STALL); break; }
            nanosleep(&nap,NULL); continue;
        }
        if (id < 0) { fail(r,SLE_RT_IO_RX); break; }
        last = sle_iio_now_ns();
        if (!epoch_mono) { epoch_mono=last; epoch_sample=rx; }
        int64_t expected=epoch_mono+(rx-epoch_sample)*250;
        int64_t lag=last-expected;
        sle_rt_rx_stats *st=&r->rx_stats[r->rx_mode];
        st->last_lag_ns=lag;
        if (lag>st->max_lag_ns) { st->max_lag_ns=lag; st->max_lag_sample=rx; }
        if (lag>3000000 && atomic_load(&r->guard)) {
            fail(r,SLE_RT_IO_RX_LAG); break;
        }
        /* Rolling lower envelope avoids interpreting oscillator ppm over a
         * long run as DMA loss. A >3 ms delivery excursion is still fatal,
         * before the 16-block (~4.1 ms) RX ring can silently overrun. */
        if (lag<0 || rx-epoch_sample>SLE_RT_FS) { epoch_mono=last; epoch_sample=rx; }
        memcpy(r->rxcopy,r->rxq.addr[id],sizeof r->rxcopy);
        if (enqueue(&r->rxq,id)) { fail(r,SLE_RT_IO_RX); break; }
        if (sle_rt_radio_rx_block(r,r->rxcopy,rx)) { fail(r,SLE_RT_IO_DEMOD); break; }
        rx += SLE_RT_BLOCK; r->n_rx++;
        atomic_store(&r->rx_mono,last);
        atomic_store(&r->rx_head,rx);
        if (feed_tx(r,&owned,&tx)) break;
        int64_t work=sle_iio_now_ns()-last;
        st->work_ns+=work;
        if (work>st->max_work_ns) { st->max_work_ns=work; st->max_work_sample=rx-SLE_RT_BLOCK; }
    }
    finish_demod(r);
    sle_rt_render_clear(&r->renderer);
    atomic_store(&r->pending,0);
    atomic_store_explicit(&r->exited,1,memory_order_release);
    return NULL;
}
int sle_rt_radio_start(sle_rt_radio *r, int cpu, int prio)
{
    memset(r,0,sizeof *r); r->rxq.fd = r->txq.fd = -1;
    r->cpu=cpu; r->prio=prio;
#define INIT(x,v) atomic_init(&r->x,v)
    INIT(stop,0); INIT(ready,0); INIT(run,0); INIT(exited,0); INIT(error,0); INIT(mute,0);
    INIT(depth,SLE_RT_ACCESS_DEPTH); INIT(guard,0); INIT(rx_head,0); INIT(tx_head,SLE_RT_ACCESS_DEPTH*SLE_RT_BLOCK);
    INIT(rx_mono,0); INIT(pending,0); INIT(ack_seq,0); INIT(ack_result,0);
    INIT(cap_start,-1); INIT(cap_filled,0);
#undef INIT
    sle_rt_ring_init(&r->frames);
    if (!atomic_is_lock_free(&r->rx_head) || !atomic_is_lock_free(&r->frames.head)) return -1;
    if (sle_iio_open(&r->txq,SLE_IIO_TXDEV,1,16,SLE_RT_BLOCK*4) != 16 ||
        sle_iio_open(&r->rxq,SLE_IIO_RXDEV,0,16,SLE_RT_BLOCK*4) != 16) goto bad;
    for (int i = 0; i < SLE_RT_ACCESS_DEPTH; i++) {
        memset(r->txq.addr[i],0,SLE_RT_BLOCK*4);
        if (sle_iio_put(&r->txq,i)) goto bad;
    }
    int fl = fcntl(r->rxq.fd,F_GETFL);
    if (fl < 0 || fcntl(r->rxq.fd,F_SETFL,fl|O_NONBLOCK)) goto bad;
    fl = fcntl(r->txq.fd,F_GETFL);
    if (fl < 0 || fcntl(r->txq.fd,F_SETFL,fl|O_NONBLOCK)) goto bad;
    /* Block before pthread_create, including its startup window. CPU1 keeps
     * this inherited mask; restore CPU0 even when creation fails. */
    sigset_t stops, previous; sle_rt_stop_signals(&stops);
    int e=pthread_sigmask(SIG_BLOCK,&stops,&previous);
    if (e) { errno=e; perror("pthread_sigmask block"); goto bad; }
    e = pthread_create(&r->thread,NULL,stream,r);
    if (!e) r->started=1;
    int mask_error=pthread_sigmask(SIG_SETMASK,&previous,NULL);
    if (e) { errno=e; perror("pthread_create"); goto bad; }
    if (mask_error) { errno=mask_error; perror("pthread_sigmask restore"); goto bad; }
    int64_t deadline=sle_iio_now_ns()+2000000000;
    struct timespec nap={0,100000};
    while (!atomic_load(&r->ready) && !atomic_load(&r->error) && sle_iio_now_ns()<deadline)
        nanosleep(&nap,NULL);
    if (!atomic_load(&r->ready)) goto bad;
    if (set(SLE_IIO_TXD "buffer/enable","1") || set(SLE_IIO_RXD "buffer/enable","1")) goto bad;
    atomic_store(&r->run,1);
    return 0;
bad:
    sle_rt_radio_stop(r); return -1;
}
int sle_rt_radio_stop(sle_rt_radio *r)
{
    int bad=0;
    atomic_store(&r->stop,1);
    /* Quiesce already queued samples before waiting for CPU1. A rejected or
     * cancelled command must not drain its future waveform during join. */
    if (r->txq.fd>=0 && sle_iio_write(SLE_IIO_TXD "buffer/enable","0")) bad=1;
    if (r->rxq.fd>=0 && sle_iio_write(SLE_IIO_RXD "buffer/enable","0")) bad=1;
    if (r->started) {
        int e=pthread_join(r->thread,NULL);
        if (e) {
            errno=e; perror("pthread_join"); bad=1;
            /* The thread may still own mmap/waveform memory after a failed
             * join. Its final release proves it has stopped touching them. */
            struct timespec nap={0,100000};
            while (!atomic_load_explicit(&r->exited,memory_order_acquire)) nanosleep(&nap,NULL);
        }
        r->started=0;
    }
    /* Never reuse queued waveform storage until CPU1 has relinquished it. */
    sle_iio_close(&r->txq); sle_iio_close(&r->rxq);
    sle_rt_render_clear(&r->renderer);
    atomic_store(&r->pending,0);
    return bad ? -1 : 0;
}
int sle_rt_radio_submit(sle_rt_radio *r, const sle_rt_command *c)
{
    if (!c->seq || c->seq == atomic_load(&r->ack_seq) || c->seed < 0 || c->seed > 127 ||
        c->mhz < 2402 || c->mhz > 2480 || c->rx_start < 0 || c->rx_end <= c->rx_start ||
        c->wave.n > SLE_RT_WAVE_MAX) return SLE_RT_RANGE;
    if (atomic_load(&r->stop)) return SLE_RT_CANCELLED;
    int64_t rx_head=atomic_load(&r->rx_head);
    if (c->rx_end <= rx_head) {
        timing_fault(r,&r->submit_timing,SLE_RT_LATE_SUBMIT_RX,c,
                     atomic_load(&r->tx_head),rx_head,-1);
        return SLE_RT_LATE;
    }
    if (atomic_load_explicit(&r->pending,memory_order_acquire)) return SLE_RT_BUSY;
    r->command=*c;
    atomic_store_explicit(&r->pending,1,memory_order_release);
    return SLE_RT_OK;
}
int64_t sle_rt_radio_now(const sle_rt_radio *r)
{
    int64_t head=atomic_load(&r->rx_head), mono=atomic_load(&r->rx_mono);
    if (!mono) return head;
    int64_t dt=sle_iio_now_ns()-mono;
    /* Counter publication can straddle one block; the caller adds a guard.
     * This extrapolation does not claim a hardware timestamp. */
    return head + (dt>0 && dt<100000000 ? dt/250 : 0);
}
