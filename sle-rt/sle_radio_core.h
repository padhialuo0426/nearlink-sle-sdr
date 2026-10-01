/* radio policy and sample-domain scheduling. No device access, clocks or allocation.
 * All protocol times denote sync bit 0; a waveform also includes the GFSK ramp.
 * The auxiliary profile's +25 us correction applies only to the WS63 2424 MHz primary descriptor.
 */
#ifndef SLE_RT_CORE_H
#define SLE_RT_CORE_H
#include "sle_demod.h"
#include "sle_gfsk.h"
#include "sle_link.h"

#define SLE_RT_FS 4000000
/* DMA block in samples; the SDK108 runtime uses 1024 (256 us). */
#ifndef SLE_RT_BLOCK
#define SLE_RT_BLOCK 1024
#endif
#if SLE_RT_BLOCK < 256 || SLE_RT_BLOCK > 4096 || SLE_RT_BLOCK % 128
#error "SLE_RT_BLOCK must be a multiple of 128 in 256..4096"
#endif
#define SLE_RT_WAVE_MAX 4096
#define SLE_RT_REPLY_TOL 160 /* 40 us either side of the predicted sync */
#define SLE_RT_OFFSET_TOL 8 /* 2 us, including demod symbol-phase quantisation */
#define SLE_RT_CAL_COUNT 3
#ifndef SLE_RT_ACCESS_DEPTH
#define SLE_RT_ACCESS_DEPTH 3 /* timing validation verified minimum; 768 us at 4 MS/s (1024 blocks) */
#endif
/* TX reserve held only while calibrating (--cal-depth). CPU1 block work of
 * 0.5-0.74 ms drained a 3-block reserve: 1024x3 underflowed in 8-10/14
 * calibration rounds, 1024x6 and 2048x3 in 0/14
 * (docs/experiments/sw-opt-cpu0-2026-09-29.md). */
#ifndef SLE_RT_CAL_DEPTH
#define SLE_RT_CAL_DEPTH 6
#endif
#define SLE_RT_TX_BUFFERS 16 /* IIO TX buffers; upper bound of any depth */
#if SLE_RT_CAL_DEPTH < SLE_RT_ACCESS_DEPTH || SLE_RT_CAL_DEPTH > SLE_RT_TX_BUFFERS
#error "SLE_RT_CAL_DEPTH must be within SLE_RT_ACCESS_DEPTH..SLE_RT_TX_BUFFERS"
#endif
/* lo-retune.out: CPU1/FIFO80 maxima 2101.3/1929.1 us. CPU0/FIFO60 control
 * still needs live validation; enforce actual deadlines after each step. */
#define SLE_RT_ACCESS_TX_RETUNE_US 2300
#define SLE_RT_ACCESS_RX_RETUNE_US 2300
#define SLE_RT_ACCESS_ACK_US 512 /* bounded submit/ack before starting RX retune */
#define SLE_RT_ACCESS_SETTLE_US 100
#define SLE_RT_TX_GUARD (SLE_RT_BLOCK/2)

/* TX retune -> submit -> RX retune. RX needs to precede the earliest
 * acceptable response preamble, not the request or its leakage. Budgets are
 * conservative admission limits, not guarantees about Linux scheduling. */
int64_t sle_rt_access_lead(void);
int64_t sle_rt_access_response_lead(int need_tx_retune);
/* Maintenance evidence uses two fully valid peer timestamps, never time since
 * an isolated first reply. Duration must exceed the supervision period. */
int sle_rt_maintained(int64_t first_ns, int64_t last_ns, int64_t now_ns,
                  int64_t hold_ns, int64_t supervision_ns, int64_t fresh_ns);

enum sle_rt_result {
    SLE_RT_OK, SLE_RT_IGNORE, SLE_RT_BAD_FRAME, SLE_RT_IDENTITY, SLE_RT_REJECTED,
    SLE_RT_LATE, SLE_RT_RANGE, SLE_RT_NO_CAL, SLE_RT_OFFSET_JUMP, SLE_RT_TIMEOUT,
    SLE_RT_BUSY, SLE_RT_OVERLAP, SLE_RT_CANCELLED
};
const char *sle_rt_result_name(int r);

typedef struct {
    uint8_t local[6], server[6];
    sle_tx_indication_t txi;
    sle_access_req_info_t req;
} sle_rt_peer;
int sle_rt_peer_init(sle_rt_peer *p, const uint8_t local[6], const uint8_t server[6],
                 uint32_t lid, uint32_t crc, uint32_t slot);
int sle_rt_primary(const sle_rt_peer *p, const sle_found_frame_t *f, int64_t now_sample,
               int64_t lead_samples, int64_t shift_samples, sle_access_plan_t *plan);
int sle_rt_primary_layout(const sle_rt_peer *p, const sle_found_frame_t *f, int64_t now_sample,
                      int64_t lead_samples, int64_t shift_samples,
                      sle_resource_layout_t layout, sle_access_plan_t *plan);
/* Includes both identities, channel/seed, CRC, capability and time checks.
 * A rejected response addressed to us is different from someone else's frame. */
int sle_rt_response(const sle_rt_peer *p, const sle_access_plan_t *plan,
                const sle_found_frame_t *f);

typedef struct { int valid, count; int64_t offset, last_sample; } sle_rt_cal;
int sle_rt_cal_observe(sle_rt_cal *c, int64_t tx_sync, int64_t rx_sync);
int sle_rt_cal_fresh(const sle_rt_cal *c, int64_t now_sample, int64_t ttl_samples);
void sle_rt_cal_clear(sle_rt_cal *c);

typedef struct { size_t n; int16_t iq[2 * SLE_RT_WAVE_MAX]; } sle_rt_wave;
int sle_rt_modulate(sle_rt_wave *w, const uint8_t *bits, size_t n, double cfo_hz);
void sle_rt_rotate(sle_rt_wave *out, const sle_rt_wave *in, double cfo_hz);
int64_t sle_rt_sync_in_wave(void);
int sle_rt_tx_index(const sle_rt_cal *cal, int64_t rx_sync, int64_t tx_head, int64_t *start);

/* One immutable owned waveform at a time. Partial late transmissions are
 * forbidden. Clearing releases ownership, including on shutdown/error. */
typedef struct { int active; int64_t start, next_head; sle_rt_wave wave; } sle_rt_renderer;
int sle_rt_render_arm(sle_rt_renderer *r, int64_t head, int64_t start, const sle_rt_wave *w);
int sle_rt_render_block(sle_rt_renderer *r, int16_t *dst, int64_t base, size_t n);
void sle_rt_render_clear(sle_rt_renderer *r);

int sle_rt_reply_matches(const sle_link_tx_t *tx, const sle_conn_sched_t *s,
                     const sle_found_frame_t *f, int64_t *error_samples);
int sle_rt_expired(int64_t now, int64_t deadline);

/* Cheap continuous-listen energy gate: sample power every fourth sample,
 * compare the hottest 128-sample bin against a quiet-block lower envelope.
 * First eight blocks and a signal without observed contrast fail open.
 * PREVIOUS/CURRENT describe feeds, not power classification; preserve both
 * sides of a burst and never feed a block twice. Caller owns IQ history. */
#define SLE_RT_ENERGY_FACTOR 10u /* 10 dB, streaming receiver's recorded-capture default */
#define SLE_RT_ENERGY_LEARN_BLOCKS 8u
enum { SLE_RT_GATE_CURRENT=1, SLE_RT_GATE_PREVIOUS=2, SLE_RT_GATE_HOT=4,
       SLE_RT_GATE_LEARNING=8, SLE_RT_GATE_OPEN=16, SLE_RT_GATE_POST=32 };
typedef struct {
    uint64_t floor_sum, peak_bin_sum, last_sum, last_bin_sum;
    unsigned learned, clipped, sampled;
    int have_previous, previous_hot, previous_fed;
} sle_rt_energy;
void sle_rt_energy_reset(sle_rt_energy *g, int keep_floor);
unsigned sle_rt_energy_step(sle_rt_energy *g, const int16_t iq[SLE_RT_BLOCK*2]);
#endif
