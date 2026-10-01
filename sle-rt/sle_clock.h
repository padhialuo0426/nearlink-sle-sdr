/* sle_clock.h - SLE access timing and connection clock/hop model.
 *
 * Time is a caller-defined monotonic int64 in nanoseconds ("local time"),
 * e.g. an E310 sample counter converted with sle_samples_to_ns(). All frame
 * times refer to the START OF THE SYNC WORD; the 10-symbol preamble starts
 * SLE_PREAMBLE_NS earlier. All attempt-8 frames use the same preamble, so
 * sync-to-sync equals frame-start-to-frame-start.
 *
 * Validated on logs/e310/local-connect-attempt8-20260926 (see
 * docs/research/sle-access-framing-2026-09-26.md):
 *  - request at aux + 2500 us (WS63 client: 2497.2 us; server response at
 *    aux + 6250.2 us);
 *  - event 0 at request + start_offset_us (9534 us, recorded 9534.2 us);
 *  - event k at t0 + k*group_period*slot, slot = base_slot + k*period,
 *    whitening seed 0x40 | (slot & 63), hop PRNG of GB/T 46803.1 6.7.3.2 with
 *    parameter 2 from the 32-bit connection sync word and 3 rounds:
 *    51/51 recorded events match channel and seed.
 * Not validated: the remapping branch for disabled channels (the recorded
 * map disables only the three broadcast RF channels, so it never ran).
 */
#ifndef SLE_CLOCK_H
#define SLE_CLOCK_H

#include <stdint.h>

#include "sle_access.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int64_t sle_time_ns_t;

#define SLE_BASE_SLOT_NS  125000LL
#define SLE_PREAMBLE_NS    10000LL  /* 10 x 1 us symbols, measured before sync */
#define SLE_SLOT_MASK     0x3FFFFFFFu /* 30-bit slot counters (Part 1 6.2.1) */

/* Physical channel (Part 1 Table 25, 2.4 GHz 1 MHz) <-> RF channel/frequency.
 * Return -1 when out of range. */
int sle_phys_to_rf(int phys);
int sle_rf_to_phys(int rf);
int sle_phys_to_mhz(int phys);

/* Conversions for a sample-counter time base (fs in Hz). */
sle_time_ns_t sle_samples_to_ns(int64_t samples, uint32_t fs_hz);
int64_t sle_ns_to_samples(sle_time_ns_t t, uint32_t fs_hz);

/* Air time in ns of a 1 Msym/s GFSK frame, including the preamble.
 * connect_empty: A2 empty frame (no body CRC). */
int64_t sle_frame_air_ns(uint32_t payload_len, int connect_empty);

/* ---- Access (G node answering a connectable advertisement) ------------- */
typedef enum {
    SLE_PLAN_OK = 0,
    SLE_PLAN_LATE = 1,     /* all request windows missed: skip this adv event */
    SLE_PLAN_BAD = 2,      /* inconsistent inputs */
    SLE_PLAN_TOO_LONG = 3  /* request longer than window or max length */
} sle_plan_status_t;

typedef struct {
    sle_time_ns_t aux_sync_ns;     /* measured, or predicted from the primary */
    uint8_t aux_channel;           /* physical channel = whitening seed */
    int aux_mhz;
    uint8_t window;                /* chosen request window index */
    sle_time_ns_t req_sync_ns;     /* request sync start */
    sle_time_ns_t req_tx_start_ns; /* preamble start = req_sync_ns - preamble */
    sle_time_ns_t rsp_sync_ns;     /* expected response sync start */
    uint32_t window_len_us;
    sle_plan_status_t status;
} sle_access_plan_t;

typedef struct {
    int have_aux;                  /* 1: aux_sync_ns measured */
    sle_time_ns_t aux_sync_ns;
    sle_time_ns_t primary_sync_ns; /* used when have_aux == 0 */
    uint32_t resource_word;        /* from the primary (WS63 layout) */
    int64_t aux_correction_ns;     /* added to a predicted aux: WS63 truncates the
                                    * offset to 125 us; +25000 for its 2424 MHz
                                    * primary (descriptor 1). Ignored if have_aux. */
    sle_time_ns_t now_ns;          /* current local time */
    int64_t tx_lead_ns;            /* host/PL pipeline lead needed before preamble */
    int allow_later_window;        /* use window n>0 when N>1 and window 0 missed */
    uint32_t request_len;          /* request payload bytes (checked vs window) */
} sle_access_plan_in_t;

sle_plan_status_t sle_access_plan(const sle_access_plan_in_t *in,
                                  const sle_access_resource_t *unit,
                                  sle_access_plan_t *out);

/* ---- Connection schedule ---------------------------------------------- */
typedef struct {
    sle_time_ns_t t0_ns;       /* sync start of the first sender in event 0 */
    uint32_t base_slot;        /* scheduling slot number of event 0 */
    uint32_t period_slots;     /* event-group period */
    int64_t slot_ns;           /* scheduling slot length */
    uint32_t sync32;           /* connection sync word, bit i = i-th air bit */
    uint32_t lid;
    uint8_t used[76];          /* usable physical channels, ascending */
    uint8_t n_used;
    int64_t intra_gap_ns;      /* intra-event gap (first end -> second start) */
    uint32_t timeout_ms;
} sle_conn_sched_t;

typedef struct {
    uint32_t k;
    sle_time_ns_t t_ns;        /* first-sender sync start */
    uint32_t slot;
    uint8_t phys;
    int mhz;
    uint8_t white_seed;        /* 0x40 | (slot & 63) */
} sle_conn_event_t;

uint32_t sle_sync32_from_lid(uint32_t lid);
uint16_t sle_hop_prng(uint32_t slot, uint32_t sync32);
/* Returns the physical channel, or -1 if no channel is usable. */
int sle_hop_channel(uint16_t r, const uint8_t *used, uint8_t n_used);
/* Usable physical channels from a hop map whose bit n is RF channel n. */
uint8_t sle_hop_map_used(const uint8_t *hop_map, uint8_t map_len, uint8_t used[76]);

/* Anchor = sync start of the frame that carried the transmission indication
 * (the access request when the initiator becomes G). Returns 0 or -1. */
int sle_conn_sched_init(sle_conn_sched_t *s, sle_time_ns_t anchor_sync_ns,
                        const sle_tx_indication_t *txi);
void sle_conn_event(const sle_conn_sched_t *s, uint32_t k, sle_conn_event_t *ev);
/* First event index whose first-sender preamble starts at or after
 * not_before_ns (use now + pipeline lead: late events are skipped, never
 * sent late inside the event). */
uint32_t sle_conn_next_event(const sle_conn_sched_t *s, sle_time_ns_t not_before_ns);
/* Second-sender sync start relative to the first-sender sync start
 * (INFERENCE, Part 1 6.2.1: next slot boundary after end + intra gap;
 * measured WS63 T replies are 2.2..3.5 us earlier than this). */
int64_t sle_second_sender_offset_ns(const sle_conn_sched_t *s, uint32_t first_payload_len,
                                    int first_empty);
/* 1 when no valid frame was received for longer than the link timeout. */
int sle_conn_timed_out(const sle_conn_sched_t *s, sle_time_ns_t last_rx_ns, sle_time_ns_t now_ns);

#ifdef __cplusplus
}
#endif
#endif /* SLE_CLOCK_H */
