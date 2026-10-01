#ifndef SLE_T_WAVE_H
#define SLE_T_WAVE_H
#include "sle_radio_core.h"
/* Zero-CFO 4 MS/s radio waveform: BT=.5, deviation=250kHz, amplitude=8000,
 * 10-bit preamble and 8-sample raised-cosine ramps. Call init once before
 * starting radio threads; initialization is deliberately not concurrent.
 * After initialization modulation is reentrant. No hardware access. */
void sle_t_wave_init(void);
int sle_t_modulate(sle_rt_wave *wave, const uint8_t *bits, size_t n);
#endif
