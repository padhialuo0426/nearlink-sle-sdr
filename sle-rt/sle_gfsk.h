/* sle_gfsk.h - GFSK burst modulator for SLE 1 Msym/s frames.
 *
 * C port of the project's own Python reference
 * scripts/sle_waveform_reference.py (gaussian_nrz, frame_iq), whose output was
 * accepted by the WS63 in M1 (docs/experiments/sle-sdr-first-discovery-2026-09-25.md):
 * NRZ symbols repeated sps times, Gaussian taps with sigma =
 * sqrt(ln 2) * sps / (2 pi BT) over +-2 symbols (normalised, "same"
 * convolution), frequency = deviation * filtered NRZ with `lead` and `tail`
 * zero-frequency samples, phase = 2 pi cumsum(f) / fs, raised-cosine
 * envelope over lead and tail. BT 0.5 and 250 kHz deviation are the M1
 * candidates, not RF-validated values.
 */
#ifndef SLE_GFSK_H
#define SLE_GFSK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLE_GFSK_PREAMBLE_BITS 10   /* "0101010101", as in M1 */

typedef struct {
    int fs_hz;            /* integer multiple of 1 MHz */
    double deviation_hz;  /* 250e3 */
    double bt;            /* 0.5 */
    int lead, tail;       /* ramp samples before/after the bits, >= 2 */
    double amplitude;     /* int16 full-scale units, e.g. 8000 */
} sle_gfsk_cfg_t;

void sle_gfsk_default(sle_gfsk_cfg_t *c, int fs_hz);

/* Samples produced for nbits channel bits (preamble included by the caller). */
size_t sle_gfsk_len(const sle_gfsk_cfg_t *c, size_t nbits);

/* Prepend the 10-bit preamble to frame bits (from the sync word). Returns
 * the total bit count or 0 if cap is too small. */
size_t sle_gfsk_with_preamble(const uint8_t *frame_bits, size_t n, uint8_t *out, size_t cap);

/* Modulate bits (0/1 per byte) into interleaved int16 I/Q. offset_hz shifts
 * the burst away from 0 Hz (0 for a channel-centred LO). Returns the number
 * of samples written, or 0 on bad arguments/capacity. The preamble starts at
 * output sample `lead`. */
size_t sle_gfsk_mod(const sle_gfsk_cfg_t *c, const uint8_t *bits, size_t nbits,
                    double offset_hz, int16_t *iq, size_t cap_samples);

#ifdef __cplusplus
}
#endif
#endif /* SLE_GFSK_H */
