/* sle_link.h - SLE connection-state link model (O5): event loop, hop map,
 * SN/NESN ARQ, supervision timeout, control-plane updates at an instant.
 *
 * Pure protocol logic: no I/O, no clock reads, no allocation. The caller
 * supplies local time (ns, see sle_clock.h), encodes/decodes air frames with
 * sle_link_encode()/sle_link_decode(), and keeps pushed payload buffers alive
 * until the PDU is acknowledged (control PDUs built here are stored inline).
 *
 * Rules and their sources:
 *  - ARQ, frame type 1 (1-bit SN/NESN): GB/T 46803.1-2025 6.4.1.1 a-e. One
 *    outstanding PDU; a new PDU toggles SN, a retransmission repeats it;
 *    NESN = SN expected in the next peer data PDU.
 *  - Empty frames carry SN = 0 and their SN is ignored on receipt; only
 *    data PDUs consume a sequence number. Not stated in the standard;
 *    FACT from the attempt-8 WS63 recording (every empty frame of both
 *    sides has SN 0 while NESN toggles), see test_sle_link.c.
 *  - One event per event group (the WS63 value, event count 1). A missing or
 *    header-CRC-failed first-sender frame means the second sender stays
 *    silent (6.4.1.1 f); a missing reply means the next event retransmits
 *    (6.4.1.1 e/g). Multi-event groups and flow-controlled extra events are
 *    not modelled.
 *  - G is always the first sender (recorded; the WS63 access request says
 *    first/second = 0 nevertheless, see docs/research/sle-access-framing).
 *  - Hop map update 0x0013 (Part 2 Table 49, 6.9): new map from the event
 *    whose slot is at or after the instant (inclusive).
 *  - Asynchronous link parameter update indication 0x003A (Part 2 Table
 *    75/76): ref slot = start slot of the last event group with the old
 *    parameters; the first new event starts offset old slots later. When the
 *    new scheduling slot is not 125 us the slot numbering restarts at 0 there
 *    (Table 76 text; HYPOTHESIS for hop/whitening use).
 *  - Link disconnect indication 0x001E (Part 2 Table 71/72).
 *  - Control PDUs generated here (0x0013/0x003A/0x001E) are sent before any
 *    queued upper-layer PDU (FIFO among themselves), so an instant is not
 *    overtaken by queued data (design choice).
 *  - Supervision: DOWN(reason 7, "connection timeout") when an event would
 *    start more than timeout after the last reply with a valid header.
 *    Starting the timer at event 0 is an INFERENCE.
 *  - A T-role receiver that gets an update whose instant has already passed
 *    goes DOWN with SLE_LINK_REASON_INSTANT_PASSED (policy; the standard
 *    does not say).
 *  - A T that receives a disconnect indication still sends the reply of that
 *    event (carrying the acknowledgement) and then stops (design choice;
 *    otherwise G can only end by supervision timeout).
 * docs/research/sle-link-model-2026-09-26.md has the full derivation.
 */
#ifndef SLE_LINK_H
#define SLE_LINK_H

#include <stddef.h>
#include <stdint.h>

#include "sle_clock.h"
#include "sle_phy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLE_LINK_QUEUE_MAX 1024
#define SLE_LINK_CTRL_MAX  20      /* largest control PDU built here: 3 + 17 */
#define SLE_LINK_CQ_MAX    32      /* link-generated control PDUs waiting */

enum { SLE_CTRL_HOPMAP_UPDATE = 0x0013, SLE_CTRL_DISCONNECT = 0x001E,
       SLE_CTRL_PARAM_UPDATE = 0x003A };
enum { SLE_PTYPE_DATA = 0, SLE_PTYPE_CTRL = 3 };
enum { SLE_LINK_REASON_TIMEOUT = 7, SLE_LINK_REASON_INSTANT_PASSED = 0xF0,
       SLE_LINK_REASON_BAD_UPDATE = 0xF1 };

typedef enum { SLE_LINK_ROLE_G = 0, SLE_LINK_ROLE_T = 1 } sle_link_role_t;

/* ---- ARQ core (also used directly by the recorded-trace regression) ---- */
typedef struct {
    uint8_t tx_sn;     /* SN of the outstanding / next data PDU */
    uint8_t rx_nesn;   /* SN expected in the next peer data PDU */
    uint8_t has_cur;   /* a data PDU is outstanding */
} sle_arq_t;

typedef struct {
    uint8_t acked;     /* outstanding PDU acknowledged (tx_sn toggled) */
    uint8_t deliver;   /* new peer data PDU: hand to upper layer */
    uint8_t dup;       /* peer data PDU with a repeated SN: drop */
} sle_arq_out_t;

/* Header fields of a received frame whose CRC12 passed; body_ok = CRC24
 * passed (ignored for empty frames). */
void sle_arq_rx(sle_arq_t *a, uint8_t empty, uint8_t sn, uint8_t nesn, int body_ok,
                sle_arq_out_t *out);

/* ---- Control-plane codecs (2 B type LE, 1 B length, data) ----
 * 0x003A: Table 75 lists fields totalling 136 bits (17 B) but states 120 bits
 * (15 B). The field list is encoded; the WS63 length is unverified. */
typedef struct {
    uint32_t ref_slot;      /* 32-bit field, 30-bit value */
    uint16_t offset_slots;
    uint16_t period_slots;
    uint16_t intra_gap_us;
    uint16_t inter_gap_us;  /* inter-event and inter-group gap */
    uint16_t latency_groups;
    uint16_t timeout_10ms;
    uint8_t sched_slot;     /* 3 bits, 0..4 = 25..125 us */
    uint8_t first_second;   /* 1 bit */
} sle_param_update_t;

size_t sle_ctrl_param_update_build(const sle_param_update_t *p, uint8_t *out, size_t cap);
int sle_ctrl_param_update_parse(const uint8_t *pdu, size_t n, sle_param_update_t *p);
size_t sle_ctrl_hopmap_build(const uint8_t map[10], uint32_t instant, uint8_t *out, size_t cap);
int sle_ctrl_hopmap_parse(const uint8_t *pdu, size_t n, uint8_t map[10], uint32_t *instant);
size_t sle_ctrl_disconnect_build(uint32_t lid, uint8_t reason, uint8_t *out, size_t cap);
int sle_ctrl_disconnect_parse(const uint8_t *pdu, size_t n, uint32_t *lid, uint8_t *reason);

/* ---- Link ---- */
typedef struct {
    const uint8_t *data;   /* caller buffer, or NULL: use inl */
    uint16_t len;
    uint8_t ptype;
    uint8_t is_disc;
    uint8_t reason;
    uint8_t inl[SLE_LINK_CTRL_MAX];
} sle_link_pdu_t;

typedef struct {
    int active;
    int64_t k_ref;
    sle_param_update_t p;
} sle_link_pend_param_t;

typedef struct {
    int active;
    uint32_t instant;
    uint8_t map[10];
} sle_link_pend_map_t;

typedef struct {
    sle_link_role_t role;
    sle_conn_sched_t s;        /* current schedule segment */
    int64_t k_first;           /* global index of s's local event 0 */
    uint32_t crc_init;
    int64_t last_k;            /* last event used (-1 before the first) */
    sle_time_ns_t last_t_ns;
    int have_event;            /* last_k is valid for rx */
    int rx_hdr_ok;             /* T role: header of the G frame passed */
    int reply_once;            /* T role: acknowledge a received disconnect */
    sle_arq_t arq;
    sle_link_pdu_t cur;
    uint32_t cur_sent;         /* transmissions of cur so far */
    sle_link_pdu_t q[SLE_LINK_QUEUE_MAX];
    uint32_t q_head, q_len;
    sle_link_pdu_t cq[SLE_LINK_CQ_MAX]; /* sent before q (control has priority) */
    uint32_t cq_head, cq_len;
    sle_time_ns_t last_valid_ns;
    int down;
    uint8_t down_reason;
    sle_link_pend_param_t pend_param;
    sle_link_pend_map_t pend_map;
    /* statistics */
    uint32_t n_tx, n_retx, n_ack, n_deliver, n_dup, n_badbody, n_miss;
} sle_link_t;

typedef struct { uint8_t what; int64_t k; } sle_link_apply_t; /* what: 1 param, 2 hopmap */

typedef struct {
    sle_conn_event_t ev;       /* ev.k is the global event index */
    int64_t k;
    uint8_t ptype, empty, sn, nesn, flow;
    const uint8_t *data;       /* valid until the next call on the link */
    uint16_t len;
    int retx;                  /* this data PDU was sent before */
    sle_link_apply_t apply[4];
    int n_apply;
    int down;                  /* 1: no frame; link is (now) down */
} sle_link_tx_t;

typedef enum { SLE_RX_NONE = 0, SLE_RX_HDRFAIL = 1, SLE_RX_BODYFAIL = 2, SLE_RX_OK = 3 } sle_rx_kind_t;

typedef struct {
    sle_rx_kind_t kind;
    uint8_t empty, sn, nesn, flow, ptype;
    const uint8_t *data;
    uint16_t len;
} sle_link_rx_t;

typedef struct {
    uint8_t acked, acked_sn, deliver, dup, badbody;
    int went_down;             /* link went down while handling this frame */
    const uint8_t *data;       /* delivered payload (points into rx->data) */
    uint16_t len;
    uint8_t ptype;
} sle_link_rx_out_t;

/* sched: from sle_conn_sched_init(); crc_init: negotiated 32-bit value. */
void sle_link_init(sle_link_t *l, sle_link_role_t role, const sle_conn_sched_t *s,
                   uint32_t crc_init);
/* Returns 0, or -1 (queue full / bad length / ptype). */
int sle_link_push(sle_link_t *l, uint8_t ptype, const uint8_t *data, uint16_t len);
/* G only. Return 0 when queued, -1 when rejected (see sle_link.c). */
int sle_link_hopmap_update(sle_link_t *l, const uint8_t map[10], uint32_t instant);
int sle_link_param_update(sle_link_t *l, const sle_param_update_t *p);
int sle_link_disconnect(sle_link_t *l, uint8_t reason);

/* G: choose the first event after the last one whose preamble starts at or
 * after now+lead, apply updates that became due, check supervision and build
 * the frame. Returns 0 with a frame, 1 when the link is down. */
int sle_link_g_prepare(sle_link_t *l, sle_time_ns_t now_ns, int64_t lead_ns, sle_link_tx_t *tx);
/* T: choose the event to listen to (same selection rule; tx->ev only). */
int sle_link_t_listen(sle_link_t *l, sle_time_ns_t now_ns, int64_t lead_ns, sle_link_tx_t *tx);
/* Both roles: the peer frame of the current event. */
void sle_link_on_rx(sle_link_t *l, const sle_link_rx_t *rx, sle_link_rx_out_t *out);
/* T: build the reply for the current event. Returns 0 with a frame, 1 when
 * no reply may be sent (G frame not received, or link down). */
int sle_link_t_reply(sle_link_t *l, sle_link_tx_t *tx);

/* Event k (global index) under the current schedule and map. */
void sle_link_event(const sle_link_t *l, int64_t k, sle_conn_event_t *ev);

/* Air bits (from the sync word) for a prepared frame. Returns bit count or 0. */
size_t sle_link_encode(const sle_link_t *l, const sle_link_tx_t *tx, uint8_t *out_bits,
                       size_t cap_bits);
/* Decode sync-aligned bits of the peer frame in event ev; fills rx and keeps
 * its payload in frame->payload. */
void sle_link_decode(const sle_link_t *l, const sle_conn_event_t *ev, const uint8_t *bits,
                     size_t avail, sle_frame_t *frame, sle_link_rx_t *rx);

#ifdef __cplusplus
}
#endif
#endif /* SLE_LINK_H */
