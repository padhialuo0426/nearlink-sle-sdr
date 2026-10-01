/* Measurement-only poller of AD9361 HDL core sticky status bits on the E310.
 *
 * DAC core 0x79024000 (version 0x00090162): reg 0x88 bit0 = DAC underflow.
 * ADC core 0x79020000 (version 0x000a0300): reg 0x88 bit2 = ADC overflow.
 * Both are sticky and write-1-to-clear. A dedicated thread polls them through
 * /dev/mem, records every set observation with CLOCK_MONOTONIC time and the
 * radio's RX/TX sample heads, then clears the observed bits. The radio path
 * is not changed. Events are kept in memory and written after stop. */
#ifndef SLE_RT_HWSTAT_H
#define SLE_RT_HWSTAT_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include "sle_radio.h"

#define SLE_RT_HW_ADC_BASE 0x79020000u
#define SLE_RT_HW_DAC_BASE 0x79024000u
#define SLE_RT_HW_STATUS_REG 0x88u
#define SLE_RT_HW_DAC_UNF 0x1u
#define SLE_RT_HW_ADC_OVF 0x4u
#define SLE_RT_HW_EVENTS 8192u
/* Optional AXI-DMAC interrupt-latency tracking (2026-09-29 sw-opt), off by
 * default. IRQ_PENDING (0x84; bit0 SOT, bit1 EOT) of the RX (0x7c400000) and
 * TX (0x7c420000) DMACs is read side-effect free; the Linux handler clears it
 * with W1C. A bit seen set at polls t1..t2 proves a service delay >= t2-t1.
 * Only meaningful when the poller does not share the CPU that services the
 * interrupt (use cpu 1, below the radio priority). */
#define SLE_RT_HW_RX_DMAC 0x7c400000u
#define SLE_RT_HW_TX_DMAC 0x7c420000u
#define SLE_RT_HW_DMAC_VERSION 0x00040461u
#define SLE_RT_HW_DMAC_PENDING 0x84u
#define SLE_RT_HW_DMA_LONG 256u
#define SLE_RT_HW_DMA_BINS 64u /* 10 us bins of the lower bound, last = overflow */
typedef struct {
    uint32_t prev; int64_t first_ns, last_ns;
    uint64_t episodes, multi, hist[SLE_RT_HW_DMA_BINS];
    int64_t max_lo_ns, max_at_ns;
    uint64_t n_long; int64_t long_at_ns[SLE_RT_HW_DMA_LONG], long_lo_ns[SLE_RT_HW_DMA_LONG];
    int64_t long_rx[SLE_RT_HW_DMA_LONG], long_tx[SLE_RT_HW_DMA_LONG];
} sle_rt_hw_dma;

typedef struct {
    int64_t mono_ns, prev_poll_ns, rx_head, tx_head;
    uint32_t dac, adc, dac_after, adc_after;
} sle_rt_hw_event;

typedef struct {
    int fd;
    volatile uint32_t *adc, *dac;
    void *adc_map, *dac_map;
    uint32_t adc_version, dac_version, dac_initial, adc_initial;
    pthread_t thread;
    int started, cpu, prio;
    int64_t period_ns;
    atomic_int stop, ready;
    sle_rt_radio *radio;
    int64_t start_ns, end_ns, max_gap_ns, max_gap_at_ns, last_poll_ns;
    uint64_t polls, dac_hits, adc_hits, n_events, dropped;
    sle_rt_hw_event *event; /* SLE_RT_HW_EVENTS entries, allocated at open */
    int dma_track; volatile uint32_t *dmac[2]; void *dmac_map[2]; uint32_t dmac_version[2];
    sle_rt_hw_dma dma[2]; /* 0 = RX DMAC, 1 = TX DMAC */
} sle_rt_hwstat;

/* Map both cores and verify their version registers. 0 on success. */
int sle_rt_hwstat_open(sle_rt_hwstat *h);
/* After open, before start: also map both DMACs read-only and track how long
 * their IRQ_PENDING stays set. 0 on success (versions verified). */
int sle_rt_hwstat_track_dma(sle_rt_hwstat *h);
/* Start polling on cpu at SCHED_FIFO prio (0 = SCHED_OTHER). */
int sle_rt_hwstat_start(sle_rt_hwstat *h, sle_rt_radio *r, int cpu, int prio, int64_t period_ns);
int sle_rt_hwstat_stop(sle_rt_hwstat *h);
void sle_rt_hwstat_close(sle_rt_hwstat *h);
/* One summary line plus one line per event; call only after stop. */
int sle_rt_hwstat_write(const sle_rt_hwstat *h, FILE *out, int attempt);

#endif
