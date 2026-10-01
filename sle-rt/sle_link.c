/* sle_link.c - see sle_link.h. */
#include "sle_link.h"

#include <string.h>

#define HALF_RANGE 0x20000000u   /* 2^29: half of the 30-bit slot space */

/* a at or after b in the 30-bit slot space. */
static int after_eq(uint32_t a, uint32_t b)
{
    return ((a - b) & SLE_SLOT_MASK) < HALF_RANGE;
}

/* ---- ARQ core ---------------------------------------------------------- */

void sle_arq_rx(sle_arq_t *a, uint8_t empty, uint8_t sn, uint8_t nesn, int body_ok,
                sle_arq_out_t *out)
{
    memset(out, 0, sizeof(*out));
    /* 6.4.1.1 a/b: the peer asks for the other SN -> our PDU arrived. */
    if (a->has_cur && (nesn & 1u) != a->tx_sn) {
        out->acked = 1;
        a->tx_sn ^= 1u;
        a->has_cur = 0;
    }
    if (empty || !body_ok) return;     /* empty SN is ignored; bad body: NESN kept (c/d) */
    if ((sn & 1u) == a->rx_nesn) {
        out->deliver = 1;
        a->rx_nesn ^= 1u;
    } else {
        out->dup = 1;                  /* b: retransmission of a delivered PDU */
    }
}

/* ---- Control-plane codecs --------------------------------------------- */

typedef struct { uint8_t *p; size_t bit; } bw_t;

static void bw_put(bw_t *w, uint32_t v, unsigned width)
{
    for (unsigned i = 0; i < width; i++, w->bit++)
        if (v >> i & 1u) w->p[w->bit / 8] |= (uint8_t)(1u << (w->bit % 8));
}

static uint32_t br_get(const uint8_t *p, size_t *bit, unsigned width)
{
    uint32_t v = 0;
    for (unsigned i = 0; i < width; i++, (*bit)++)
        if (p[*bit / 8] >> (*bit % 8) & 1u) v |= 1u << i;
    return v;
}

static size_t ctrl_head(uint16_t type, uint8_t len, uint8_t *out, size_t cap)
{
    if (cap < 3u + len) return 0;
    out[0] = (uint8_t)type;
    out[1] = (uint8_t)(type >> 8);
    out[2] = len;
    memset(out + 3, 0, len);
    return 3u + len;
}

static int ctrl_check(const uint8_t *pdu, size_t n, uint16_t type, uint8_t len)
{
    return n == 3u + len && pdu[0] == (uint8_t)type && pdu[1] == (uint8_t)(type >> 8) &&
           pdu[2] == len;
}

size_t sle_ctrl_param_update_build(const sle_param_update_t *p, uint8_t *out, size_t cap)
{
    if (p->sched_slot > 7 || p->first_second > 1 || p->ref_slot > SLE_SLOT_MASK) return 0;
    size_t n = ctrl_head(SLE_CTRL_PARAM_UPDATE, 17, out, cap);
    if (!n) return 0;
    bw_t w = { out + 3, 0 };
    bw_put(&w, p->ref_slot, 32);
    bw_put(&w, p->offset_slots, 16);
    bw_put(&w, p->period_slots, 16);
    bw_put(&w, p->intra_gap_us, 16);
    bw_put(&w, p->inter_gap_us, 16);
    bw_put(&w, p->latency_groups, 16);
    bw_put(&w, p->timeout_10ms, 16);
    bw_put(&w, p->sched_slot, 3);
    bw_put(&w, p->first_second, 1);
    bw_put(&w, 0, 4);
    return n;
}

int sle_ctrl_param_update_parse(const uint8_t *pdu, size_t n, sle_param_update_t *p)
{
    if (!ctrl_check(pdu, n, SLE_CTRL_PARAM_UPDATE, 17)) return -1;
    size_t b = 0;
    const uint8_t *d = pdu + 3;
    p->ref_slot = br_get(d, &b, 32);
    p->offset_slots = (uint16_t)br_get(d, &b, 16);
    p->period_slots = (uint16_t)br_get(d, &b, 16);
    p->intra_gap_us = (uint16_t)br_get(d, &b, 16);
    p->inter_gap_us = (uint16_t)br_get(d, &b, 16);
    p->latency_groups = (uint16_t)br_get(d, &b, 16);
    p->timeout_10ms = (uint16_t)br_get(d, &b, 16);
    p->sched_slot = (uint8_t)br_get(d, &b, 3);
    p->first_second = (uint8_t)br_get(d, &b, 1);
    return br_get(d, &b, 4) == 0 ? 0 : -1;
}

size_t sle_ctrl_hopmap_build(const uint8_t map[10], uint32_t instant, uint8_t *out, size_t cap)
{
    size_t n = ctrl_head(SLE_CTRL_HOPMAP_UPDATE, 14, out, cap);
    if (!n) return 0;
    memcpy(out + 3, map, 10);
    for (int i = 0; i < 4; i++) out[13 + i] = (uint8_t)(instant >> (8 * i));
    return n;
}

int sle_ctrl_hopmap_parse(const uint8_t *pdu, size_t n, uint8_t map[10], uint32_t *instant)
{
    if (!ctrl_check(pdu, n, SLE_CTRL_HOPMAP_UPDATE, 14)) return -1;
    memcpy(map, pdu + 3, 10);
    *instant = 0;
    for (int i = 0; i < 4; i++) *instant |= (uint32_t)pdu[13 + i] << (8 * i);
    return 0;
}

size_t sle_ctrl_disconnect_build(uint32_t lid, uint8_t reason, uint8_t *out, size_t cap)
{
    size_t n = ctrl_head(SLE_CTRL_DISCONNECT, 4, out, cap);
    if (!n) return 0;
    for (int i = 0; i < 3; i++) out[3 + i] = (uint8_t)(lid >> (8 * i));
    out[6] = reason;
    return n;
}

int sle_ctrl_disconnect_parse(const uint8_t *pdu, size_t n, uint32_t *lid, uint8_t *reason)
{
    if (!ctrl_check(pdu, n, SLE_CTRL_DISCONNECT, 4)) return -1;
    *lid = (uint32_t)pdu[3] | (uint32_t)pdu[4] << 8 | (uint32_t)pdu[5] << 16;
    *reason = pdu[6];
    return 0;
}

/* ---- Link --------------------------------------------------------------- */

void sle_link_init(sle_link_t *l, sle_link_role_t role, const sle_conn_sched_t *s,
                   uint32_t crc_init)
{
    memset(l, 0, sizeof(*l));
    l->role = role;
    l->s = *s;
    l->k_first = 0;
    l->crc_init = crc_init;
    l->last_k = -1;
    l->last_valid_ns = s->t0_ns;
}

void sle_link_event(const sle_link_t *l, int64_t k, sle_conn_event_t *ev)
{
    int64_t j = k - l->k_first;
    ev->k = (uint32_t)k;
    ev->t_ns = l->s.t0_ns + j * (int64_t)l->s.period_slots * l->s.slot_ns;
    ev->slot = (l->s.base_slot + (uint32_t)(j * (int64_t)l->s.period_slots)) & SLE_SLOT_MASK;
    ev->phys = (uint8_t)sle_hop_channel(sle_hop_prng(ev->slot, l->s.sync32), l->s.used, l->s.n_used);
    ev->mhz = sle_phys_to_mhz(ev->phys);
    ev->white_seed = (uint8_t)(0x40u | (ev->slot & 0x3Fu));
}

static int enqueue(sle_link_t *l, const sle_link_pdu_t *p)
{
    if (l->q_len >= SLE_LINK_QUEUE_MAX) return -1;
    l->q[(l->q_head + l->q_len) % SLE_LINK_QUEUE_MAX] = *p;
    l->q_len++;
    return 0;
}

int sle_link_push(sle_link_t *l, uint8_t ptype, const uint8_t *data, uint16_t len)
{
    if (ptype > 3 || len == 0 || len > SLE_MAX_CONNECT_PAYLOAD_BYTES || !data) return -1;
    sle_link_pdu_t p;
    memset(&p, 0, sizeof(p));
    p.data = data;
    p.len = len;
    p.ptype = ptype;
    return enqueue(l, &p);
}

static int enqueue_ctrl(sle_link_t *l, const uint8_t *pdu, size_t n, int is_disc, uint8_t reason)
{
    sle_link_pdu_t p;
    memset(&p, 0, sizeof(p));
    memcpy(p.inl, pdu, n);
    p.len = (uint16_t)n;
    p.ptype = SLE_PTYPE_CTRL;
    p.is_disc = (uint8_t)is_disc;
    p.reason = reason;
    if (l->cq_len >= SLE_LINK_CQ_MAX) return -1;
    l->cq[(l->cq_head + l->cq_len) % SLE_LINK_CQ_MAX] = p;
    l->cq_len++;
    return 0;
}

int sle_link_hopmap_update(sle_link_t *l, const uint8_t map[10], uint32_t instant)
{
    uint8_t used[76], pdu[SLE_LINK_CTRL_MAX];
    sle_conn_event_t next;
    if (l->role != SLE_LINK_ROLE_G || l->pend_map.active || instant > SLE_SLOT_MASK) return -1;
    if (sle_hop_map_used(map, 10, used) < 2) return -1;
    sle_link_event(l, l->last_k + 1, &next);
    if (!after_eq(instant, next.slot)) return -1;
    size_t n = sle_ctrl_hopmap_build(map, instant, pdu, sizeof(pdu));
    if (!n || enqueue_ctrl(l, pdu, n, 0, 0)) return -1;
    l->pend_map.active = 1;
    l->pend_map.instant = instant;
    memcpy(l->pend_map.map, map, 10);
    return 0;
}

/* k_ref for a ref slot of the current schedule, or -1 if not an event slot. */
static int64_t ref_event(const sle_link_t *l, uint32_t ref_slot)
{
    uint32_t d = (ref_slot - l->s.base_slot) & SLE_SLOT_MASK;
    if (l->s.period_slots == 0 || d % l->s.period_slots) return -1;
    return l->k_first + (int64_t)(d / l->s.period_slots);
}

int sle_link_param_update(sle_link_t *l, const sle_param_update_t *p)
{
    uint8_t pdu[SLE_LINK_CTRL_MAX];
    if (l->role != SLE_LINK_ROLE_G || l->pend_param.active || p->offset_slots < 1 ||
        p->period_slots < 1 || p->sched_slot > 4 || p->ref_slot > SLE_SLOT_MASK) return -1;
    int64_t k_ref = ref_event(l, p->ref_slot);
    if (k_ref < 0 || k_ref <= l->last_k) return -1;
    size_t n = sle_ctrl_param_update_build(p, pdu, sizeof(pdu));
    if (!n || enqueue_ctrl(l, pdu, n, 0, 0)) return -1;
    l->pend_param.active = 1;
    l->pend_param.k_ref = k_ref;
    l->pend_param.p = *p;
    return 0;
}

int sle_link_disconnect(sle_link_t *l, uint8_t reason)
{
    uint8_t pdu[SLE_LINK_CTRL_MAX];
    size_t n = sle_ctrl_disconnect_build(l->s.lid, reason, pdu, sizeof(pdu));
    return enqueue_ctrl(l, pdu, n, 1, reason);
}

static void go_down(sle_link_t *l, uint8_t reason)
{
    l->down = 1;
    l->down_reason = reason;
}

static void apply_param(sle_link_t *l, sle_link_tx_t *tx)
{
    const sle_param_update_t *p = &l->pend_param.p;
    sle_conn_event_t ref;
    sle_link_event(l, l->pend_param.k_ref, &ref);
    uint32_t slot_us = sle_sched_slot_us(p->sched_slot);
    l->s.t0_ns = ref.t_ns + (int64_t)p->offset_slots * l->s.slot_ns;
    l->s.base_slot = slot_us == 125 ? (p->ref_slot + p->offset_slots) & SLE_SLOT_MASK : 0;
    l->s.period_slots = p->period_slots;
    l->s.slot_ns = (int64_t)slot_us * 1000;
    l->s.intra_gap_ns = (int64_t)p->intra_gap_us * 1000;
    l->s.timeout_ms = (uint32_t)p->timeout_10ms * 10u;
    l->k_first = l->pend_param.k_ref + 1;
    l->pend_param.active = 0;
    if (tx->n_apply < 4) tx->apply[tx->n_apply++] = (sle_link_apply_t){ 1, l->k_first };
}

/* Spec 3 "tx" step 2: first k > last_k whose preamble starts at or after
 * not_before, applying updates as candidates pass their instants. */
static void select_event(sle_link_t *l, sle_time_ns_t not_before, sle_link_tx_t *tx)
{
    int64_t k = l->last_k + 1;
    for (;;) {
        if (l->pend_param.active && k > l->pend_param.k_ref) apply_param(l, tx);
        if (!l->pend_param.active && !l->pend_map.active && k >= l->k_first) {
            int64_t span = (int64_t)l->s.period_slots * l->s.slot_ns;
            int64_t d = not_before - (l->s.t0_ns - SLE_PREAMBLE_NS);
            if (d > 0) {
                int64_t kj = l->k_first + (d + span - 1) / span;
                if (kj > k) k = kj;
            }
        }
        sle_link_event(l, k, &tx->ev);
        if (l->pend_map.active && after_eq(tx->ev.slot, l->pend_map.instant)) {
            l->s.n_used = sle_hop_map_used(l->pend_map.map, 10, l->s.used);
            l->pend_map.active = 0;
            if (tx->n_apply < 4) tx->apply[tx->n_apply++] = (sle_link_apply_t){ 2, k };
            sle_link_event(l, k, &tx->ev);
        }
        if (tx->ev.t_ns - SLE_PREAMBLE_NS >= not_before) break;
        k++;
    }
    tx->k = k;
}

static int supervise(sle_link_t *l, sle_link_tx_t *tx)
{
    if (tx->ev.t_ns - l->last_valid_ns > (int64_t)l->s.timeout_ms * 1000000LL) {
        go_down(l, SLE_LINK_REASON_TIMEOUT);
        tx->down = 1;
        return 1;
    }
    return 0;
}

static void build_frame(sle_link_t *l, sle_link_tx_t *tx)
{
    if (!l->arq.has_cur && l->cq_len) {
        l->cur = l->cq[l->cq_head];
        l->cq_head = (l->cq_head + 1) % SLE_LINK_CQ_MAX;
        l->cq_len--;
        l->arq.has_cur = 1;
        l->cur_sent = 0;
    } else if (!l->arq.has_cur && l->q_len) {
        l->cur = l->q[l->q_head];
        l->q_head = (l->q_head + 1) % SLE_LINK_QUEUE_MAX;
        l->q_len--;
        l->arq.has_cur = 1;
        l->cur_sent = 0;
    }
    if (l->arq.has_cur) {
        tx->ptype = l->cur.ptype;
        tx->empty = 0;
        tx->sn = l->arq.tx_sn;
        tx->data = l->cur.data ? l->cur.data : l->cur.inl;
        tx->len = l->cur.len;
        tx->retx = l->cur_sent > 0;
        if (tx->retx) l->n_retx++;
        l->cur_sent++;
    } else {
        tx->ptype = SLE_PTYPE_DATA;
        tx->empty = 1;
        tx->sn = 0;              /* recorded WS63 convention */
        tx->data = NULL;
        tx->len = 0;
    }
    tx->nesn = l->arq.rx_nesn;
    tx->flow = (l->q_len + l->cq_len) > 0;
    l->n_tx++;
}

int sle_link_g_prepare(sle_link_t *l, sle_time_ns_t now_ns, int64_t lead_ns, sle_link_tx_t *tx)
{
    memset(tx, 0, sizeof(*tx));
    if (l->down) { tx->down = 1; return 1; }
    select_event(l, now_ns + lead_ns, tx);
    if (supervise(l, tx)) return 1;
    build_frame(l, tx);
    l->last_k = tx->k;
    l->last_t_ns = tx->ev.t_ns;
    l->have_event = 1;
    return 0;
}

int sle_link_t_listen(sle_link_t *l, sle_time_ns_t now_ns, int64_t lead_ns, sle_link_tx_t *tx)
{
    memset(tx, 0, sizeof(*tx));
    if (l->down) { tx->down = 1; return 1; }
    select_event(l, now_ns + lead_ns, tx);
    if (supervise(l, tx)) return 1;
    l->last_k = tx->k;
    l->last_t_ns = tx->ev.t_ns;
    l->have_event = 1;
    l->rx_hdr_ok = 0;
    return 0;
}

int sle_link_t_reply(sle_link_t *l, sle_link_tx_t *tx)
{
    memset(tx, 0, sizeof(*tx));
    if (l->down && !l->reply_once) { tx->down = 1; return 1; }
    l->reply_once = 0;
    if (!l->have_event || !l->rx_hdr_ok) return 1;   /* 6.4.1.1 f */
    tx->k = l->last_k;
    sle_link_event(l, l->last_k, &tx->ev);
    build_frame(l, tx);
    return 0;
}

/* T role: receiver side of the G-initiated updates. */
static void t_take_ctrl(sle_link_t *l, const uint8_t *d, uint16_t n)
{
    uint8_t map[10];
    uint32_t instant;
    sle_param_update_t p;
    if (sle_ctrl_hopmap_parse(d, n, map, &instant) == 0) {
        sle_conn_event_t next;
        uint8_t used[76];
        sle_link_event(l, l->last_k + 1, &next);
        if (sle_hop_map_used(map, 10, used) < 2) go_down(l, SLE_LINK_REASON_BAD_UPDATE);
        else if (!after_eq(instant, next.slot)) go_down(l, SLE_LINK_REASON_INSTANT_PASSED);
        else {
            l->pend_map.active = 1;
            l->pend_map.instant = instant;
            memcpy(l->pend_map.map, map, 10);
        }
    } else if (sle_ctrl_param_update_parse(d, n, &p) == 0) {
        int64_t k_ref = ref_event(l, p.ref_slot);
        if (k_ref < 0 || p.offset_slots < 1 || p.period_slots < 1 || p.sched_slot > 4)
            go_down(l, SLE_LINK_REASON_BAD_UPDATE);
        else if (k_ref < l->last_k) go_down(l, SLE_LINK_REASON_INSTANT_PASSED);
        else {
            l->pend_param.active = 1;
            l->pend_param.k_ref = k_ref;
            l->pend_param.p = p;
        }
    }
}

void sle_link_on_rx(sle_link_t *l, const sle_link_rx_t *rx, sle_link_rx_out_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!l->have_event || l->down) return;
    if (rx->kind == SLE_RX_NONE || rx->kind == SLE_RX_HDRFAIL) {
        l->n_miss++;
        if (l->role == SLE_LINK_ROLE_T) l->rx_hdr_ok = 0;
        return;
    }
    l->last_valid_ns = l->last_t_ns;
    if (l->role == SLE_LINK_ROLE_T) l->rx_hdr_ok = 1;
    int was_disc = l->arq.has_cur && l->cur.is_disc;
    uint8_t disc_reason = l->cur.reason, old_sn = l->arq.tx_sn;
    sle_arq_out_t a;
    sle_arq_rx(&l->arq, rx->empty, rx->sn, rx->nesn, rx->kind == SLE_RX_OK, &a);
    if (a.acked) {
        out->acked = 1;
        out->acked_sn = old_sn;
        l->n_ack++;
        if (was_disc) {
            go_down(l, disc_reason);
            out->went_down = 1;
            return;
        }
    }
    if (rx->empty) return;
    if (rx->kind == SLE_RX_BODYFAIL) {
        out->badbody = 1;
        l->n_badbody++;
        return;
    }
    if (a.dup) {
        out->dup = 1;
        l->n_dup++;
        return;
    }
    out->deliver = 1;
    out->data = rx->data;
    out->len = rx->len;
    out->ptype = rx->ptype;
    l->n_deliver++;
    if (rx->ptype != SLE_PTYPE_CTRL) return;
    uint32_t lid;
    uint8_t reason;
    if (sle_ctrl_disconnect_parse(rx->data, rx->len, &lid, &reason) == 0) {
        go_down(l, reason);
        out->went_down = 1;
        l->reply_once = l->role == SLE_LINK_ROLE_T;
    } else if (l->role == SLE_LINK_ROLE_T) {
        t_take_ctrl(l, rx->data, rx->len);
        out->went_down = l->down;
    }
}

size_t sle_link_encode(const sle_link_t *l, const sle_link_tx_t *tx, uint8_t *out_bits,
                       size_t cap_bits)
{
    sle_connect_config_t cfg = { l->s.lid, tx->ev.white_seed, SLE_CRC_TYPE_24, l->crc_init, 0 };
    return sle_encode_connect_config(out_bits, cap_bits, tx->data, tx->len, &cfg, tx->ptype,
                                     tx->empty, tx->sn, tx->nesn, tx->flow, 0, 0);
}

void sle_link_decode(const sle_link_t *l, const sle_conn_event_t *ev, const uint8_t *bits,
                     size_t avail, sle_frame_t *frame, sle_link_rx_t *rx)
{
    sle_connect_config_t cfg = { l->s.lid, ev->white_seed, SLE_CRC_TYPE_24, l->crc_init, 0 };
    memset(rx, 0, sizeof(*rx));
    sle_decode_status_t st = sle_decode_connect_config(bits, avail, &cfg, frame);
    if (st == SLE_DECODE_SYNC_MISMATCH || st == SLE_DECODE_BAD_CONFIG ||
        st == SLE_DECODE_UNSUPPORTED_CRC || (st == SLE_DECODE_NEED_MORE && !frame->crc12_ok)) {
        rx->kind = SLE_RX_NONE;
        return;
    }
    if (st == SLE_DECODE_CRC12_FAIL || st == SLE_DECODE_BAD_LENGTH) {
        rx->kind = SLE_RX_HDRFAIL;
        return;
    }
    rx->empty = frame->conn_empty;
    rx->sn = frame->conn_sn;
    rx->nesn = frame->conn_nesn;
    rx->flow = frame->conn_flow;
    rx->ptype = frame->conn_pkt_type;
    if (st == SLE_DECODE_OK) {
        rx->kind = SLE_RX_OK;
        rx->data = frame->payload;
        rx->len = frame->payload_len;
    } else {
        rx->kind = SLE_RX_BODYFAIL;
        rx->len = frame->length;
    }
}
