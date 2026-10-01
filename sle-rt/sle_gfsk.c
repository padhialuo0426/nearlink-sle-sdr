/* sle_gfsk.c - see sle_gfsk.h. */
#include "sle_gfsk.h"

#include <math.h>
#include <string.h>

#define MAX_HALF 64   /* half kernel length in samples: 2 symbols * sps <= 64 */
#define SLE_PI 3.14159265358979323846

void sle_gfsk_default(sle_gfsk_cfg_t *c, int fs_hz)
{
    c->fs_hz = fs_hz;
    c->deviation_hz = 250e3;
    c->bt = 0.5;
    c->lead = (int)lround(2e-6 * fs_hz);   /* 2 us ramps */
    c->tail = (int)lround(2e-6 * fs_hz);
    c->amplitude = 8000.0;
}

size_t sle_gfsk_len(const sle_gfsk_cfg_t *c, size_t nbits)
{
    return (size_t)c->lead + nbits * (size_t)(c->fs_hz / 1000000) + (size_t)c->tail;
}

size_t sle_gfsk_with_preamble(const uint8_t *frame_bits, size_t n, uint8_t *out, size_t cap)
{
    if (cap < n + SLE_GFSK_PREAMBLE_BITS) return 0;
    for (int i = 0; i < SLE_GFSK_PREAMBLE_BITS; i++) out[i] = (uint8_t)(i & 1);
    memcpy(out + SLE_GFSK_PREAMBLE_BITS, frame_bits, n);
    return n + SLE_GFSK_PREAMBLE_BITS;
}

size_t sle_gfsk_mod(const sle_gfsk_cfg_t *c, const uint8_t *bits, size_t nbits,
                    double offset_hz, int16_t *iq, size_t cap_samples)
{
    if (!c || !bits || !iq || c->fs_hz <= 0 || c->fs_hz % 1000000 || c->bt <= 0 ||
        c->lead < 2 || c->tail < 2 || nbits == 0)
        return 0;
    int sps = c->fs_hz / 1000000;
    int half = (int)ceil(4.0 * sps / 2.0);
    if (half < 1) half = 1;
    if (half > MAX_HALF) return 0;
    size_t nsym = nbits * (size_t)sps, total = sle_gfsk_len(c, nbits);
    if (total > cap_samples) return 0;

    double taps[2 * MAX_HALF + 1], sum = 0;
    double sigma = sqrt(log(2.0)) * sps / (2 * SLE_PI * c->bt);
    for (int k = -half; k <= half; k++) {
        taps[k + half] = exp(-0.5 * (k / sigma) * (k / sigma));
        sum += taps[k + half];
    }
    for (int k = 0; k <= 2 * half; k++) taps[k] /= sum;

    double phase = 0, w_off = 2 * SLE_PI * offset_hz / c->fs_hz;
    for (size_t n = 0; n < total; n++) {
        double f = 0;
        if (n >= (size_t)c->lead && n < (size_t)c->lead + nsym) {
            /* "same" convolution: y[m] = sum_k taps[k] * nrz[m + half - k] */
            long m = (long)(n - (size_t)c->lead);
            double y = 0;
            for (int k = 0; k <= 2 * half; k++) {
                long idx = m + half - k;
                if (idx < 0 || idx >= (long)nsym) continue;
                y += taps[k] * (bits[idx / sps] ? 1.0 : -1.0);
            }
            f = c->deviation_hz * y;
        }
        phase += 2 * SLE_PI * f / c->fs_hz;        /* cumsum, as in the reference */
        double env = 1.0;
        if (n < (size_t)c->lead)
            env = 0.5 - 0.5 * cos(SLE_PI * (double)n / (c->lead - 1));
        else if (n >= total - (size_t)c->tail)
            env = 0.5 + 0.5 * cos(SLE_PI * (double)(n - (total - c->tail)) / (c->tail - 1));
        double ph = phase + w_off * (double)n;
        iq[2 * n] = (int16_t)lround(c->amplitude * env * cos(ph));
        iq[2 * n + 1] = (int16_t)lround(c->amplitude * env * sin(ph));
    }
    return total;
}
