/* sle_demod.h - streaming GFSK demodulator + SLE frame-sync scanner.
 *
 * Pipeline per channel: NCO downconvert -> FIR lowpass -> FM discriminator
 * (angle of x[n]*conj(x[n-1])) -> hard bit per sample -> per-symbol-phase
 * (0..sps-1) sync correlation and frame state machine.
 *
 * Designed for streaming: sle_demod_channel_process() may be called
 * repeatedly with successive chunks of samples; all filter/NCO/bit-sync
 * state persists in the sle_demod_channel_t across calls, matching how a
 * DMA ring buffer would feed it on target hardware. No dynamic
 * allocation after init.
 */
#ifndef SLE_DEMOD_H
#define SLE_DEMOD_H

#include <stddef.h>
#include <stdint.h>
#include "sle_phy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLE_DEMOD_MAX_SPS     16   /* max samples/symbol supported */
#ifndef SLE_DEMOD_FIR_TAPS
#define SLE_DEMOD_FIR_TAPS    63
#endif
#define SLE_DEMOD_MAX_TARGETS 8

/* Set to 0 for a scalar ARM reference build. Native builds stay scalar. */
#ifndef SLE_DEMOD_NEON_FIR
#define SLE_DEMOD_NEON_FIR 0
#endif
#if SLE_DEMOD_NEON_FIR && !defined(__ARM_NEON)
#error "SLE_DEMOD_NEON_FIR requires ARM NEON"
#endif

typedef enum {
    SLE_TARGET_BROADCAST = 0, /* fixed seed, known from channel number */
    SLE_TARGET_CONNECT   = 1  /* seed brute-forced 0..127 */
} sle_target_kind_t;

typedef struct {
    sle_target_kind_t kind;
    uint8_t sync_bits[32];   /* air order, bit0 transmitted first */
    uint32_t sync_packed;    /* bit0 at MSB(31) .. bit31 at LSB(0), for popcount compare */
    uint8_t seed;            /* SLE_TARGET_BROADCAST only */
    int max_bit_errors;      /* allowed sync correlation errors, 0 = exact */
    const char *label;       /* diagnostic only, may be NULL */
    int has_connect_config; /* 0: header-only analysis with unknown link parameters */
    sle_connect_config_t connect_config;
} sle_sync_target_t;

typedef enum {
    SLE_PHASE_SEARCH = 0,
    SLE_PHASE_HEADER = 1,
    SLE_PHASE_BODY   = 2
} sle_phase_state_t;

typedef struct {
    uint32_t shiftreg;
    sle_phase_state_t state;
    int matched_target;                  /* index into targets[], -1 if none */
    uint64_t sync_start_sample;          /* global sample index of sync bit 0 */
    size_t need_bits;                    /* total bits needed once matched (incl. sync) */
    uint8_t bitbuf[SLE_MAX_FRAME_BITS];  /* raw (still-whitened for body) bits from sync */
    size_t pos;                          /* bits filled in bitbuf so far */
    unsigned search_bits;               /* avoid matching a partially filled shift register */
} sle_phase_ctx_t;

/* Candidate counters count symbol-phase hypotheses, not unique packets or PER.
 * In particular, unmatched search windows are not known missing packets. */
typedef struct {
    uint64_t samples_processed;
    uint64_t warmup_samples_discarded;
    uint64_t search_windows;
    uint64_t sync_candidates;
    uint64_t frames_ok;
    uint64_t crc12_failures;
    uint64_t crc24_failures;
    uint64_t sync_mismatches;
    uint64_t bad_lengths;
    uint64_t configuration_failures;
    uint64_t invalid_headers;
    uint64_t truncated_candidates;
    uint64_t discontinuities;
    uint64_t missing_samples;
    uint64_t rejected_chunks;
    uint64_t rejected_samples;
    uint64_t dedup_suppressed;   /* same frame on other symbol phases (dedup on) */
} sle_demod_stats_t;

typedef enum {
    SLE_STREAM_OK = 0,
    SLE_STREAM_GAP = 1,       /* forward gap: reset DSP state, then accept this block */
    SLE_STREAM_STALE = 2,     /* overlap/duplicate/backwards block: reject it entirely */
    SLE_STREAM_BAD_ARGUMENT = -1
} sle_stream_status_t;

/* One decoded frame, reported via the callback. */
typedef struct {
    uint64_t sample_index;   /* global sample index of the frame's first sync bit */
    int      channel_mhz;    /* configured channel label (e.g. 2424) */
    int      phase;          /* symbol phase 0..sps-1 that found it */
    sle_frame_t frame;       /* decoded fields (kind, crc12_ok, crc24_ok, payload, ...) */
} sle_found_frame_t;

typedef void (*sle_frame_cb_t)(const sle_found_frame_t *found, void *user);

typedef struct {
    /* configuration */
    double fs_hz;
    double offset_hz;        /* channel_center - capture_lo, digital baseband offset */
    int    sps;               /* samples per symbol = fs_hz / 1e6 (1 Msym/s) */
    int    channel_mhz;       /* label only */
    sle_sync_target_t targets[SLE_DEMOD_MAX_TARGETS];
    int    n_targets;
    sle_frame_cb_t cb;
    void  *cb_user;

    /* NCO state (recursive complex rotator, renormalized periodically) */
    double nco_re, nco_im;
    double nco_inc_re, nco_inc_im;
    uint32_t nco_renorm_counter;

    /* FIR lowpass (windowed-sinc, cutoff 700 kHz, Hamming, matches
     * scripts/scan_sle_capture.py lowpass()) */
    float fir_taps[SLE_DEMOD_FIR_TAPS];
    float fir_taps_rev[SLE_DEMOD_FIR_TAPS]; /* fixed layout; NEON reads oldest first */
    /* Fixed public layout across scalar/NEON builds; NEON mirrors the ring. */
    float fir_delay_re[2 * SLE_DEMOD_FIR_TAPS];
    float fir_delay_im[2 * SLE_DEMOD_FIR_TAPS];
    int   fir_pos;

    /* discriminator state */
    float prev_re, prev_im;
    int   have_prev;

    /* 1: skip the software FIR (the AD9361 analog/digital filters band-limit
     * a channel-centred narrowband input); no group delay, no warm-up. */
    int   fir_bypass;
    /* With fir_bypass: optional N-sample moving sum (0 = off, 2..8), a cheap
     * band-edge noise cut; group delay N/2 samples is compensated. */
    int   box_n, box_pos;
    float box_re[8], box_im[8], box_sre, box_sim;

    /* 1: report each frame once (sle_demod_set_dedup); pending group of the
     * same frame found on several symbol phases. */
    int   dedup;
    int   npend;
    uint64_t pend_deadline;
    sle_found_frame_t pend[SLE_DEMOD_MAX_SPS];

    /* Absolute index expected for the next accepted sample. */
    uint64_t sample_counter;
    int have_sample_counter;
    unsigned warmup_samples;
    sle_demod_stats_t stats;

    /* per-phase bit-sync state machines */
    sle_phase_ctx_t phase_ctx[SLE_DEMOD_MAX_SPS];
} sle_demod_channel_t;

/* Initialize a channel. fs_hz must be an integer multiple of 1e6 (1 Msym/s).
 * offset_hz is the digital baseband frequency to mix the channel's carrier
 * down to 0 Hz (channel_center_hz - capture_lo_hz). Returns 0 on success,
 * -1 on invalid sps or too many targets. */
int sle_demod_channel_init(sle_demod_channel_t *ch, double fs_hz, double offset_hz,
                            int channel_mhz, sle_frame_cb_t cb, void *cb_user);

/* Enable/disable the software FIR (default enabled). Call before feeding
 * samples; bypass is for channel-centred input that the radio already
 * band-limits (live E310 reception with LO on the channel). */
void sle_demod_set_fir_bypass(sle_demod_channel_t *ch, int bypass);
/* Moving-sum length used only while the FIR is bypassed (0 disables, 2..8).
 * Call before feeding; default 0 keeps bypass output unchanged. */
int sle_demod_set_boxcar(sle_demod_channel_t *ch, int n);

/* Report each frame once instead of once per symbol phase that decoded it
 * (default off, which keeps the raw per-phase reports the regression tools
 * expect). The kept report prefers a full CRC pass, then the earliest sync
 * start of the group (decodable phases start at the true sync position). Suppressed copies are counted in
 * stats.dedup_suppressed. */
void sle_demod_set_dedup(sle_demod_channel_t *ch, int on);

/* Add a sync target to search for on this channel. Returns 0 on success. */
int sle_demod_add_target(sle_demod_channel_t *ch, const sle_sync_target_t *target);

/* Convenience: add the fixed broadcast target with a given whitening seed. */
int sle_demod_add_broadcast_target(sle_demod_channel_t *ch, uint8_t white_seed,
                                    int max_bit_errors);

/* Convenience: add a connect target from a 24-bit logical link id. */
int sle_demod_add_connect_target(sle_demod_channel_t *ch, uint32_t lid,
                                  int max_bit_errors);

/* Decode non-empty A2 data only with explicit link CRC/whitening parameters.
 * This config is copied: update/recreate the target when the slot/seed changes. */
int sle_demod_add_connect_config_target(sle_demod_channel_t *ch,
                                        const sle_connect_config_t *config,
                                        int max_bit_errors);

/* Feed `n_samples` of interleaved int16 I/Q (I,Q,I,Q,...) starting at
 * absolute sample index `sample_index_base` (i.e. iq[0],iq[1] is sample
 * number sample_index_base). State (NCO phase, FIR delay line,
 * discriminator memory, per-phase sync search) persists across calls, so
 * chunk boundaries do not lose or duplicate frames as long as
 * sample_index_base advances by exactly n_samples from call to call.
 * The first nonempty block establishes the index origin. A forward gap
 * invalidates pending frames and filter history, counts missing samples,
 * and processes the new block after reset. Any backwards/overlapping block
 * is rejected without consuming samples or disturbing the expected index.
 * A zero-length block is a no-op. Index/count overflow is an error. */
sle_stream_status_t sle_demod_channel_process(sle_demod_channel_t *ch,
                                const int16_t *iq_interleaved,
                                size_t n_samples, uint64_t sample_index_base);

/* End an input segment: count incomplete candidates, reset DSP state, retain
 * targets and cumulative statistics. Returns the number of truncated phase
 * candidates. The next block may establish a new index origin. */
uint64_t sle_demod_channel_finish(sle_demod_channel_t *ch);

#ifdef __cplusplus
}
#endif
#endif /* SLE_DEMOD_H */
