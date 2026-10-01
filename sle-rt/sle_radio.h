/* CPU0 owns sysfs and lifecycle; CPU1 exclusively owns DMA/DSP/rendering.
 * No shared non-atomic counters. Commands own their waveform by value.
 * Mailbox ack releases the command buffer; renderer retains its own copy.
 */
#ifndef SLE_RT_RADIO_H
#define SLE_RT_RADIO_H
#include "sle_radio_core.h"
#include "sle_iio.h"
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdio.h>

#define SLE_RT_FRAME_RING 64u
#define SLE_RT_HISTORY 8192u
_Static_assert(SLE_RT_HISTORY % SLE_RT_BLOCK == 0 && SLE_RT_HISTORY >= 2u*SLE_RT_BLOCK, "history must hold two whole blocks");
#define SLE_RT_WINDOW_BOXCAR 5 /* moving-sum length for finite RX windows */
#ifndef SLE_RT_SYNC_ERRORS
#define SLE_RT_SYNC_ERRORS 1 /* connection sync-word bit errors tolerated; 0 missed a
                          * CRC-valid own frame in FIR-bypass replay (2026-09-27) */
#endif
enum sle_rt_io_error { SLE_RT_IO_OK, SLE_RT_IO_THREAD, SLE_RT_IO_RX, SLE_RT_IO_TX,
    SLE_RT_IO_OVERFLOW, SLE_RT_IO_UNDERFLOW, SLE_RT_IO_STALL, SLE_RT_IO_DEMOD, SLE_RT_IO_COMMAND,
    SLE_RT_IO_RX_LAG };
const char *sle_rt_io_error_name(int e);
typedef struct {
    unsigned seq;
    int mhz, seed, connect, estimate_cfo;
    uint32_t lid, crc;
    int64_t rx_start, rx_end; /* sample gate; INT64_MAX means continuous */
    int64_t tx_start;
    sle_rt_wave wave;            /* n == 0: receive configuration only */
} sle_rt_command;
typedef struct { unsigned seq; sle_found_frame_t f; double cfo_hz; } sle_rt_received;
typedef struct {
    atomic_uint head, tail;
    sle_rt_received frame[SLE_RT_FRAME_RING];
} sle_rt_frame_ring;
void sle_rt_ring_init(sle_rt_frame_ring *q);
int sle_rt_ring_push(sle_rt_frame_ring *q, const sle_rt_received *f);
int sle_rt_ring_pop(sle_rt_frame_ring *q, sle_rt_received *f);

enum { SLE_RT_RX_WINDOW, SLE_RT_RX_SCAN, SLE_RT_RX_CAL, SLE_RT_RX_MODES };
typedef struct {
    uint64_t blocks, energy_blocks, hot, learning, fail_open, pre, post;
    uint64_t demod_blocks, demod_samples, skipped, muted, clipped, sampled;
    uint64_t frames, cfo_estimates, cfo_unavailable, history_errors;
    int64_t max_lag_ns, last_lag_ns, max_work_ns, work_ns;
    int64_t max_lag_sample, max_work_sample;
    uint64_t floor_sum, peak_bin_sum;
} sle_rt_rx_stats;

/* Fault-only, bounded journals: submit is control-thread owned, consume is
 * radio-thread owned. Read/format only after sle_rt_radio_stop has joined CPU1.
 * queue_depth is the configured TX reserve; tx_queued counts buffers not yet
 * reclaimed by the consumer (-1 at submit, where that count is unavailable).
 * Heads/windows are sample indices, mono_ns is CLOCK_MONOTONIC nanoseconds. */
#define SLE_RT_TIMING_RING 16u
enum sle_rt_late_source { SLE_RT_LATE_SUBMIT_RX, SLE_RT_LATE_CONSUMER_RX, SLE_RT_LATE_RENDER_START };
typedef struct {
    unsigned seq;
    enum sle_rt_late_source source;
    int64_t mono_ns, tx_head, rx_head, tx_start, rx_start, rx_end;
    size_t wave_samples;
    int queue_depth, tx_queued;
} sle_rt_timing_fault;
typedef struct {
    uint64_t total;
    sle_rt_timing_fault entry[SLE_RT_TIMING_RING];
} sle_rt_timing_log;

typedef struct {
    sle_iio_queue_t rxq, txq;
    pthread_t thread;
    int started, cpu, prio;
    atomic_int stop, ready, run, exited, error, mute, depth, guard;
    atomic_llong rx_head, tx_head, rx_mono;
    atomic_uint pending, ack_seq;
    atomic_int ack_result;
    sle_rt_command command;
    sle_rt_frame_ring frames;
    sle_rt_timing_log submit_timing, consumer_timing;
    /* Only CPU1, or main after pthread_join, accesses the following fields. */
    sle_rt_renderer renderer;
    sle_demod_channel_t demod;
    unsigned seq;
    int64_t gate_start, gate_end;
    int16_t rxcopy[SLE_RT_BLOCK*2], txcopy[SLE_RT_BLOCK*2], history[SLE_RT_HISTORY*2];
    int64_t history_end;
    int history_valid, energy_enabled, rx_mode, estimate_cfo, was_muted;
    int64_t history_start;
    sle_rt_energy energy;
    sle_rt_rx_stats rx_stats[SLE_RT_RX_MODES];
    uint64_t n_rx, n_tx, truncated, crc12_fail, crc24_fail;
    /* Measurement only: TX queue found fully drained while guard is off
     * (calibration). Behaviour is unchanged; heads are TX sample indices. */
#define SLE_RT_DRAIN_LOG 8
    uint64_t tx_drain_unguarded;
    int64_t tx_drain_head[SLE_RT_DRAIN_LOG], tx_drain_rx_head[SLE_RT_DRAIN_LOG];
    /* Measurement-only raw RX ring capture, independent of mute and gating.
     * CPU0 sets cap/cap_len (a multiple of SLE_RT_BLOCK), then arms cap_start
     * (release). CPU1 overwrites sample s at index s % cap_len for every
     * s >= cap_start and publishes cap_filled = absolute end sample.
     * cap_start -1 = disarmed. Read only after the radio thread is joined. */
    int16_t *cap; int64_t cap_len;
    atomic_llong cap_start, cap_filled;
} sle_rt_radio;

/* Cached full blocks, also used by offline regression. Absolute base must be
 * block aligned and consecutive; no hardware or file operations here. */
int sle_rt_radio_rx_configure(sle_rt_radio *r, const sle_rt_command *c);
int sle_rt_radio_rx_block(sle_rt_radio *r, const int16_t *iq, int64_t base);

/* Attribute transaction persists across attempts; restore once at program exit.
 * Snapshot-before-write and readback-after-restore supplement sle_iio's void
 * restore API. Refuse to attach to an already enabled stream. */
int sle_rt_radio_setup(double tx_gain, double rx_gain);
int sle_rt_radio_retune(int tx, int mhz);
int sle_rt_radio_restore(void);
int sle_rt_radio_start(sle_rt_radio *r, int cpu, int prio);
int sle_rt_radio_stop(sle_rt_radio *r);
int sle_rt_radio_submit(sle_rt_radio *r, const sle_rt_command *c);
int64_t sle_rt_radio_now(const sle_rt_radio *r);
/* Deferred JSONL output; caller must stop/join first. Returns -1 on I/O error
 * or if the radio is still started. Older faults overwritten after 16/owner
 * are reported in radio_timing_summary, separately from retained entries. */
int sle_rt_radio_timing_write(const sle_rt_radio *r, FILE *out, unsigned attempt);
/* All shutdown signals are delivered to the control thread. */
void sle_rt_stop_signals(sigset_t *set);
#endif
