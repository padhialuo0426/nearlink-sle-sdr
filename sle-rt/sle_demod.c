/* sle_demod.c - see sle_demod.h. The FIR MAC has an optional ARM NEON path;
 * NCO/mixing, discriminator and bit synchronization retain scalar behavior. */
#include "sle_demod.h"
#include <math.h>
#include <string.h>
#if SLE_DEMOD_NEON_FIR
#include <arm_neon.h>
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define SLE_FIR_DELAY ((SLE_DEMOD_FIR_TAPS - 1) / 2) /* 31 for 63 taps */

static void sle_demod_fir_push_mac(sle_demod_channel_t *ch, float mre, float mim,
                                   float *yre, float *yim)
{
    const int pos = ch->fir_pos;
    ch->fir_delay_re[pos] = mre;
    ch->fir_delay_im[pos] = mim;
#if SLE_DEMOD_NEON_FIR
    ch->fir_delay_re[pos + SLE_DEMOD_FIR_TAPS] = mre;
    ch->fir_delay_im[pos + SLE_DEMOD_FIR_TAPS] = mim;
    const float *re = ch->fir_delay_re + pos + 1;
    const float *im = ch->fir_delay_im + pos + 1;
    float32x4_t acc_re = vdupq_n_f32(0.0f), acc_im = vdupq_n_f32(0.0f);
    int k = 0;
    for (; k + 4 <= SLE_DEMOD_FIR_TAPS; k += 4) {
        const float32x4_t tap = vld1q_f32(ch->fir_taps_rev + k);
        acc_re = vmlaq_f32(acc_re, tap, vld1q_f32(re + k));
        acc_im = vmlaq_f32(acc_im, tap, vld1q_f32(im + k));
    }
    /* Each lane preserves tap order; cross-lane reduction changes rounding. */
    float sum_re = vgetq_lane_f32(acc_re, 0) + vgetq_lane_f32(acc_re, 1);
    float sum_im = vgetq_lane_f32(acc_im, 0) + vgetq_lane_f32(acc_im, 1);
    sum_re += vgetq_lane_f32(acc_re, 2) + vgetq_lane_f32(acc_re, 3);
    sum_im += vgetq_lane_f32(acc_im, 2) + vgetq_lane_f32(acc_im, 3);
    for (; k < SLE_DEMOD_FIR_TAPS; k++) {
        sum_re += ch->fir_taps_rev[k] * re[k];
        sum_im += ch->fir_taps_rev[k] * im[k];
    }
    *yre = sum_re;
    *yim = sum_im;
#else
    float sum_re = 0.0f, sum_im = 0.0f;
    int idx = pos;
    for (int k = 0; k < SLE_DEMOD_FIR_TAPS; k++) {
        sum_re += ch->fir_taps[k] * ch->fir_delay_re[idx];
        sum_im += ch->fir_taps[k] * ch->fir_delay_im[idx];
        idx = (idx == 0) ? SLE_DEMOD_FIR_TAPS - 1 : idx - 1;
    }
    *yre = sum_re;
    *yim = sum_im;
#endif
    ch->fir_pos = (pos + 1 == SLE_DEMOD_FIR_TAPS) ? 0 : pos + 1;
}

static void design_lowpass(float *taps, int n, double fs, double cutoff)
{
    double sum = 0.0;
    double h[SLE_DEMOD_FIR_TAPS];
    for (int i = 0; i < n; i++) {
        double x = (double)i - (double)(n - 1) / 2.0;
        double arg = 2.0 * cutoff / fs * x;
        double sinc = (fabs(arg) < 1e-12) ? 1.0 : sin(M_PI * arg) / (M_PI * arg);
        double w = 0.54 - 0.46 * cos(2.0 * M_PI * (double)i / (double)(n - 1));
        h[i] = sinc * w;
        sum += h[i];
    }
    for (int i = 0; i < n; i++) taps[i] = (float)(h[i] / sum);
}

static unsigned popcount32(uint32_t v)
{
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned)__builtin_popcount(v);
#else
    unsigned c = 0;
    while (v) { c += v & 1u; v >>= 1; }
    return c;
#endif
}

int sle_demod_channel_init(sle_demod_channel_t *ch, double fs_hz, double offset_hz,
                            int channel_mhz, sle_frame_cb_t cb, void *cb_user)
{
    if (!ch) return -1;
    memset(ch, 0, sizeof(*ch));
    if (!isfinite(fs_hz) || !isfinite(offset_hz) ||
        fs_hz < 1.0e6 || fs_hz > SLE_DEMOD_MAX_SPS * 1.0e6)
        return -1;
    double sps_f = fs_hz / 1.0e6;
    int sps = (int)(sps_f + 0.5);
    if (fabs(sps_f - (double)sps) > 1e-6 || sps < 1 || sps > SLE_DEMOD_MAX_SPS)
        return -1;

    ch->fs_hz = fs_hz;
    ch->offset_hz = offset_hz;
    ch->sps = sps;
    ch->channel_mhz = channel_mhz;
    ch->cb = cb;
    ch->cb_user = cb_user;
    ch->n_targets = 0;

    ch->nco_re = 1.0; ch->nco_im = 0.0;
    double w = -2.0 * M_PI * offset_hz / fs_hz; /* down-convert: multiply by exp(-j w n) */
    ch->nco_inc_re = cos(w);
    ch->nco_inc_im = sin(w);
    ch->nco_renorm_counter = 0;

    design_lowpass(ch->fir_taps, SLE_DEMOD_FIR_TAPS, fs_hz, 700e3);
    for (int k = 0; k < SLE_DEMOD_FIR_TAPS; k++)
        ch->fir_taps_rev[k] = ch->fir_taps[SLE_DEMOD_FIR_TAPS - 1 - k];
    ch->fir_pos = 0;

    ch->have_prev = 0;
    ch->sample_counter = 0;

    for (int p = 0; p < SLE_DEMOD_MAX_SPS; p++) {
        ch->phase_ctx[p].state = SLE_PHASE_SEARCH;
        ch->phase_ctx[p].matched_target = -1;
        ch->phase_ctx[p].shiftreg = 0;
        ch->phase_ctx[p].pos = 0;
    }
    return 0;
}

int sle_demod_set_boxcar(sle_demod_channel_t *ch, int n)
{
    if (!ch || n < 0 || n == 1 || n > 8) return -1;
    ch->box_n = n; ch->box_pos = 0; ch->box_sre = ch->box_sim = 0.0f;
    memset(ch->box_re, 0, sizeof ch->box_re); memset(ch->box_im, 0, sizeof ch->box_im);
    return 0;
}
void sle_demod_set_fir_bypass(sle_demod_channel_t *ch, int bypass)
{
    ch->fir_bypass = bypass ? 1 : 0;
}

static uint32_t pack_sync(const uint8_t bits[32])
{
    uint32_t v = 0;
    for (int i = 0; i < 32; i++)
        v |= ((uint32_t)(bits[i] & 1u)) << (31 - i);
    return v;
}

int sle_demod_add_target(sle_demod_channel_t *ch, const sle_sync_target_t *target)
{
    if (!ch || !target || ch->sps < 1 || ch->n_targets >= SLE_DEMOD_MAX_TARGETS ||
        target->max_bit_errors < 0 || target->max_bit_errors > 32 ||
        (target->kind != SLE_TARGET_BROADCAST && target->kind != SLE_TARGET_CONNECT) ||
        (target->kind == SLE_TARGET_BROADCAST && target->seed > 127)) return -1;
    ch->targets[ch->n_targets] = *target;
    ch->targets[ch->n_targets].sync_packed = pack_sync(target->sync_bits);
    ch->n_targets++;
    return 0;
}

int sle_demod_add_broadcast_target(sle_demod_channel_t *ch, uint8_t white_seed,
                                    int max_bit_errors)
{
    sle_sync_target_t t;
    memset(&t, 0, sizeof(t));
    t.kind = SLE_TARGET_BROADCAST;
    for (int i = 0; i < 32; i++)
        t.sync_bits[i] = (uint8_t)((SLE_BROADCAST_SYNC_WORD >> i) & 1u);
    t.seed = white_seed;
    t.max_bit_errors = max_bit_errors;
    t.label = "broadcast";
    return sle_demod_add_target(ch, &t);
}

int sle_demod_add_connect_target(sle_demod_channel_t *ch, uint32_t lid,
                                  int max_bit_errors)
{
    if (lid > 0xFFFFFFu) return -1;
    sle_sync_target_t t;
    memset(&t, 0, sizeof(t));
    t.kind = SLE_TARGET_CONNECT;
    sle_sync_from_lid(lid, t.sync_bits);
    t.seed = 0; /* unused; brute-forced at decode time */
    t.max_bit_errors = max_bit_errors;
    t.label = "connect";
    return sle_demod_add_target(ch, &t);
}

int sle_demod_add_connect_config_target(sle_demod_channel_t *ch,
                                        const sle_connect_config_t *config,
                                        int max_bit_errors)
{
    if (sle_connect_config_validate(config) != SLE_DECODE_OK) return -1;
    sle_sync_target_t t;
    memset(&t, 0, sizeof(t));
    t.kind = SLE_TARGET_CONNECT;
    sle_sync_from_lid(config->lid, t.sync_bits);
    t.max_bit_errors = max_bit_errors;
    t.label = "connect-configured";
    t.has_connect_config = 1;
    t.connect_config = *config;
    return sle_demod_add_target(ch, &t);
}

static void phase_reset(sle_phase_ctx_t *pc)
{
    pc->state = SLE_PHASE_SEARCH;
    pc->matched_target = -1;
    pc->pos = 0;
    pc->shiftreg = 0;
    pc->search_bits = 0;
}

static void dedup_flush(sle_demod_channel_t *ch);

static uint64_t reset_stream(sle_demod_channel_t *ch)
{
    uint64_t truncated = 0;
    dedup_flush(ch);                 /* completed frames are still valid */
    for (int p = 0; p < ch->sps; p++) {
        if (ch->phase_ctx[p].state != SLE_PHASE_SEARCH) truncated++;
        phase_reset(&ch->phase_ctx[p]);
    }
    ch->stats.truncated_candidates += truncated;
    memset(ch->fir_delay_re, 0, sizeof(ch->fir_delay_re));
    memset(ch->fir_delay_im, 0, sizeof(ch->fir_delay_im));
    ch->fir_pos = 0;
    /* integer IQ keeps the float moving sum exact; clear it with the FIR */
    memset(ch->box_re, 0, sizeof ch->box_re); memset(ch->box_im, 0, sizeof ch->box_im);
    ch->box_sre = ch->box_sim = 0.0f; ch->box_pos = 0;
    ch->prev_re = ch->prev_im = 0;
    ch->have_prev = 0;
    ch->warmup_samples = 0;
    ch->nco_re = 1.0;
    ch->nco_im = 0.0;
    ch->nco_renorm_counter = 0;
    return truncated;
}

uint64_t sle_demod_channel_finish(sle_demod_channel_t *ch)
{
    if (!ch || ch->sps < 1 || ch->sps > SLE_DEMOD_MAX_SPS) return 0;
    uint64_t truncated = reset_stream(ch);
    ch->have_sample_counter = 0;
    return truncated;
}

static sle_decode_status_t decode_candidate(const sle_sync_target_t *tg,
                                             const sle_phase_ctx_t *pc,
                                             sle_frame_t *fr)
{
    if (tg->kind == SLE_TARGET_BROADCAST)
        return sle_decode_broadcast(pc->bitbuf, pc->pos, tg->seed, tg->sync_bits, fr);
    if (tg->has_connect_config)
        return sle_decode_connect_config(pc->bitbuf, pc->pos, &tg->connect_config, fr);
    return sle_decode_connect(pc->bitbuf, pc->pos, tg->sync_bits, fr);
}

static void count_result(sle_demod_channel_t *ch, sle_decode_status_t st)
{
    switch (st) {
    case SLE_DECODE_OK: ch->stats.frames_ok++; break;
    case SLE_DECODE_CRC12_FAIL: ch->stats.crc12_failures++; break;
    case SLE_DECODE_CRC24_FAIL: ch->stats.crc24_failures++; break;
    case SLE_DECODE_SYNC_MISMATCH: ch->stats.sync_mismatches++; break;
    case SLE_DECODE_BAD_LENGTH: ch->stats.bad_lengths++; break;
    case SLE_DECODE_NEED_CONFIG:
    case SLE_DECODE_BAD_CONFIG:
    case SLE_DECODE_UNSUPPORTED_CRC: ch->stats.configuration_failures++; break;
    case SLE_DECODE_NEED_MORE: break;
    default: ch->stats.invalid_headers++; break;
    }
}


/* ---- per-frame de-duplication across symbol phases ------------------- */
void sle_demod_set_dedup(sle_demod_channel_t *ch, int on)
{
    ch->dedup = on ? 1 : 0;
}

static int frame_crc_ok(const sle_frame_t *f)
{
    return f->crc12_ok && (!f->has_crc24 || f->crc24_ok);
}

static void dedup_flush(sle_demod_channel_t *ch)
{
    if (ch->npend <= 0) return;
    /* prefer full CRC passes; among them the earliest sync start (the run of
     * decodable phases starts at the true sync position and extends later) */
    int idx[SLE_DEMOD_MAX_SPS], n = 0, want_ok = 0;
    for (int i = 0; i < ch->npend; i++) if (frame_crc_ok(&ch->pend[i].frame)) want_ok = 1;
    for (int i = 0; i < ch->npend; i++)
        if (!want_ok || frame_crc_ok(&ch->pend[i].frame)) idx[n++] = i;
    for (int i = 1; i < n; i++)            /* insertion sort by sync start */
        for (int j = i; j > 0 && ch->pend[idx[j]].sample_index < ch->pend[idx[j - 1]].sample_index; j--) {
            int t = idx[j]; idx[j] = idx[j - 1]; idx[j - 1] = t;
        }
    const sle_found_frame_t *best = &ch->pend[idx[0]];
    ch->stats.dedup_suppressed += (uint64_t)(ch->npend - 1);
    ch->npend = 0;
    if (ch->cb) ch->cb(best, ch->cb_user);
}

static void report_frame(sle_demod_channel_t *ch, const sle_found_frame_t *found,
                         uint64_t aligned_index)
{
    if (!ch->dedup) {
        if (ch->cb) ch->cb(found, ch->cb_user);
        return;
    }
    if (ch->npend > 0) {
        uint64_t a = found->sample_index, b = ch->pend[0].sample_index;
        uint64_t d = a > b ? a - b : b - a;
        if (d > (uint64_t)ch->sps || ch->npend >= SLE_DEMOD_MAX_SPS) dedup_flush(ch);
    }
    ch->pend[ch->npend++] = *found;
    /* no other phase can complete the same frame later than sps samples on */
    ch->pend_deadline = aligned_index + (uint64_t)ch->sps + 1;
}

static void phase_feed_bit(sle_demod_channel_t *ch, int phase, uint8_t bit,
                            uint64_t aligned_index)
{
    sle_phase_ctx_t *pc = &ch->phase_ctx[phase];

    if (pc->state == SLE_PHASE_SEARCH) {
        pc->shiftreg = (pc->shiftreg << 1) | bit;
        if (pc->search_bits < 32) pc->search_bits++;
        if (pc->search_bits < 32) return;
        ch->stats.search_windows++;
        for (int t = 0; t < ch->n_targets; t++) {
            unsigned errs = popcount32(pc->shiftreg ^ ch->targets[t].sync_packed);
            if ((int)errs <= ch->targets[t].max_bit_errors) {
                ch->stats.sync_candidates++;
                pc->matched_target = t;
                pc->state = SLE_PHASE_HEADER;
                pc->pos = 32;
                memcpy(pc->bitbuf, ch->targets[t].sync_bits, 32);
                uint64_t stride = (uint64_t)ch->sps * 31;
                pc->sync_start_sample = (aligned_index >= stride) ? aligned_index - stride : 0;
                pc->need_bits = SLE_SYNC_BITS + SLE_HEADER_BITS;
                break;
            }
        }
        return;
    }

    /* HEADER or BODY: accumulate raw bits */
    pc->bitbuf[pc->pos++] = bit;

    if (pc->state == SLE_PHASE_HEADER && pc->pos == SLE_SYNC_BITS + SLE_HEADER_BITS) {
        const sle_sync_target_t *tg = &ch->targets[pc->matched_target];
        sle_frame_t fr;
        sle_decode_status_t st = decode_candidate(tg, pc, &fr);
        count_result(ch, st);

        if (st == SLE_DECODE_OK) {
            sle_found_frame_t found;
            found.sample_index = pc->sync_start_sample;
            found.channel_mhz = ch->channel_mhz;
            found.phase = phase;
            found.frame = fr;
            report_frame(ch, &found, aligned_index);
            phase_reset(pc);
        } else if (st == SLE_DECODE_NEED_MORE) {
            pc->state = SLE_PHASE_BODY;
            pc->need_bits = fr.total_bits_from_sync;
            if (pc->need_bits > SLE_MAX_FRAME_BITS || pc->need_bits <= pc->pos) {
                ch->stats.bad_lengths++;
                phase_reset(pc);
            }
        } else {
            /* CRC12_FAIL, BAD_LENGTH, SYNC_MISMATCH (shouldn't happen) */
            phase_reset(pc);
        }
        return;
    }

    if (pc->state == SLE_PHASE_BODY && pc->pos == pc->need_bits) {
        const sle_sync_target_t *tg = &ch->targets[pc->matched_target];
        sle_frame_t fr;
        sle_decode_status_t st = decode_candidate(tg, pc, &fr);
        count_result(ch, st);

        /* Report both full-CRC-pass and CRC24-fail frames (header already
         * passed CRC12, so this is a real sync hit worth telling the
         * caller about); drop anything else as a spurious match. */
        if (st == SLE_DECODE_OK || st == SLE_DECODE_CRC24_FAIL) {
            sle_found_frame_t found;
            found.sample_index = pc->sync_start_sample;
            found.channel_mhz = ch->channel_mhz;
            found.phase = phase;
            found.frame = fr;
            report_frame(ch, &found, aligned_index);
        }
        phase_reset(pc);
    }
}

sle_stream_status_t sle_demod_channel_process(sle_demod_channel_t *ch, const int16_t *iq_interleaved,
                                size_t n_samples, uint64_t sample_index_base)
{
    if (!ch || ch->sps < 1 || ch->sps > SLE_DEMOD_MAX_SPS ||
        (n_samples && !iq_interleaved) || n_samples > SIZE_MAX / 2 ||
        n_samples > UINT64_MAX - sample_index_base)
        return SLE_STREAM_BAD_ARGUMENT;
    if (n_samples == 0) return SLE_STREAM_OK;
    sle_stream_status_t result = SLE_STREAM_OK;
    if (ch->have_sample_counter) {
        if (sample_index_base < ch->sample_counter) {
            ch->stats.rejected_chunks++;
            ch->stats.rejected_samples += n_samples;
            return SLE_STREAM_STALE;
        }
        if (sample_index_base > ch->sample_counter) {
            ch->stats.discontinuities++;
            ch->stats.missing_samples += sample_index_base - ch->sample_counter;
            reset_stream(ch);
            result = SLE_STREAM_GAP;
        }
    }
    ch->have_sample_counter = 1;
    const int sps = ch->sps;
    /* offset 0: the rotator stays exactly (1, 0), so skipping it is bit-exact */
    const int use_nco = ch->offset_hz != 0.0;
    const int fir_bypass = ch->fir_bypass;
    const int box_n = fir_bypass ? ch->box_n : 0;
    const unsigned warmup = fir_bypass ? (unsigned)box_n : (unsigned)SLE_DEMOD_FIR_TAPS;
    const uint64_t fir_delay = fir_bypass ? (uint64_t)(box_n / 2) : (uint64_t)SLE_FIR_DELAY;
    /* symbol phase of the FIR-aligned index, advanced incrementally (a 64-bit
     * modulo per sample is a library call on ARM32) */
    int phase = -1;
    for (size_t i = 0; i < n_samples; i++) {
        uint64_t gidx = sample_index_base + i;
        float I = (float)iq_interleaved[2 * i + 0];
        float Q = (float)iq_interleaved[2 * i + 1];

        /* --- hot: NCO mix (1 complex multiply) --- */
        float mre = I, mim = Q;
        if (use_nco) {
            mre = (float)(I * ch->nco_re - Q * ch->nco_im);
            mim = (float)(I * ch->nco_im + Q * ch->nco_re);
            double nre = ch->nco_re * ch->nco_inc_re - ch->nco_im * ch->nco_inc_im;
            double nim = ch->nco_re * ch->nco_inc_im + ch->nco_im * ch->nco_inc_re;
            ch->nco_re = nre; ch->nco_im = nim;
            if (++ch->nco_renorm_counter >= 4096) {
                double mag = sqrt(ch->nco_re * ch->nco_re + ch->nco_im * ch->nco_im);
                if (mag > 1e-12) { ch->nco_re /= mag; ch->nco_im /= mag; }
                ch->nco_renorm_counter = 0;
            }
        }

        /* --- hot: FIR (dot product over SLE_DEMOD_FIR_TAPS taps) --- */
        float yre, yim;
        if (fir_bypass && box_n) {
            int p = ch->box_pos;
            ch->box_sre += mre - ch->box_re[p]; ch->box_sim += mim - ch->box_im[p];
            ch->box_re[p] = mre; ch->box_im[p] = mim;
            ch->box_pos = p + 1 == box_n ? 0 : p + 1;
            yre = ch->box_sre; yim = ch->box_sim;
        } else if (fir_bypass) {
            yre = mre; yim = mim;
        } else {
            sle_demod_fir_push_mac(ch, mre, mim, &yre, &yim);
        }

        /* Warm up per segment, not relative to absolute capture index. */
        if (ch->warmup_samples < warmup) {
            ch->warmup_samples++;
            ch->stats.warmup_samples_discarded++;
            continue;
        }
        if (gidx < fir_delay) continue;
        uint64_t aligned_index = gidx - fir_delay;

        if (!ch->have_prev) {
            ch->prev_re = yre; ch->prev_im = yim; ch->have_prev = 1;
            continue;
        }

        /* FM discriminator: angle(y * conj(prev)) > 0. atan2f(im, re) > 0
         * exactly when im > 0, or im == +0 with re < 0 (angle +pi); the sign
         * test reproduces the former atan2f decision bit for bit. */
        float re = yre * ch->prev_re + yim * ch->prev_im;
        float im = yim * ch->prev_re - yre * ch->prev_im;
        ch->prev_re = yre; ch->prev_im = yim;

        uint8_t bit = (im > 0.0f || (im == 0.0f && !signbit(im) && re < 0.0f)) ? 1u : 0u;
        if (phase < 0) phase = (int)(aligned_index % (uint64_t)sps);
        phase_feed_bit(ch, phase, bit, aligned_index);
        if (++phase == sps) phase = 0;
        if (ch->npend > 0 && aligned_index > ch->pend_deadline) dedup_flush(ch);
    }
    ch->sample_counter = sample_index_base + n_samples;
    ch->stats.samples_processed += n_samples;
    return result;
}
