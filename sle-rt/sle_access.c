/* sle_access.c - see sle_access.h. */
#include "sle_access.h"

#include <string.h>

/* ---- LSB-first continuous bit packing ---------------------------------- */
typedef struct {
    uint8_t *buf;
    size_t cap_bits;
    size_t pos;
    int err;
} bw_t;

static void bw_put(bw_t *w, uint32_t v, unsigned n)
{
    if (n < 32 && (v >> n) != 0) { w->err = 1; return; }
    if (w->pos + n > w->cap_bits) { w->err = 1; return; }
    for (unsigned i = 0; i < n; i++, w->pos++) {
        uint8_t *b = &w->buf[w->pos >> 3];
        uint8_t m = (uint8_t)(1u << (w->pos & 7));
        if ((v >> i) & 1u) *b |= m; else *b &= (uint8_t)~m;
    }
}

typedef struct {
    const uint8_t *buf;
    size_t nbits;
    size_t pos;
    int err;
} br_t;

static uint32_t br_get(br_t *r, unsigned n)
{
    uint32_t v = 0;
    if (r->pos + n > r->nbits) { r->err = 1; return 0; }
    for (unsigned i = 0; i < n; i++, r->pos++)
        v |= (uint32_t)((r->buf[r->pos >> 3] >> (r->pos & 7)) & 1u) << i;
    return v;
}

/* ---- Common structure --------------------------------------------------- */
void sle_bcast_pdu_init(sle_bcast_pdu_t *pdu)
{
    memset(pdu, 0, sizeof(*pdu));
}

sle_acc_status_t sle_bcast_pdu_parse(const uint8_t *p, size_t n, sle_bcast_pdu_t *out)
{
    sle_bcast_pdu_init(out);
    if (n < 2) return SLE_ACC_TRUNCATED;
    if (n > SLE_MAX_PAYLOAD_BYTES) return SLE_ACC_BAD_LENGTH;
    br_t r = { p, 16, 0, 0 };
    out->present = (uint8_t)br_get(&r, 5);
    out->rsv0 = (uint8_t)br_get(&r, 3);
    out->local_id_type = (uint8_t)br_get(&r, 3);
    out->peer_id_type = (uint8_t)br_get(&r, 3);
    out->rsv1 = (uint8_t)br_get(&r, 2);
    size_t i = 2;
#define TAKE(dst, k) do { if (i + (k) > n) return SLE_ACC_TRUNCATED; \
                          memcpy((dst), p + i, (k)); i += (k); } while (0)
    if (out->present & SLE_PRESENT_LOCAL_ID) TAKE(out->local_id, 6);
    if (out->present & SLE_PRESENT_IRK_ID) TAKE(&out->irk_id, 1);
    if (out->present & SLE_PRESENT_PEER_ID) TAKE(out->peer_id, 6);
    if (out->present & SLE_PRESENT_RESOURCE) {
        uint8_t w[4];
        TAKE(w, 4);
        out->resource_word = (uint32_t)w[0] | (uint32_t)w[1] << 8 |
                             (uint32_t)w[2] << 16 | (uint32_t)w[3] << 24;
    }
#undef TAKE
    if (out->present & SLE_PRESENT_DATA) {
        while (i < n) {
            if (i + 2 > n) return SLE_ACC_TRUNCATED;
            uint8_t type = p[i], len = p[i + 1];
            i += 2;
            if (i + len > n) return SLE_ACC_TRUNCATED;
            if (out->n_tlv >= SLE_BCAST_MAX_TLV) return SLE_ACC_CAPACITY;
            sle_tlv_ref_t *t = &out->tlv[out->n_tlv++];
            t->type = type;
            t->len = len;
            t->off = out->data_len;
            memcpy(out->data + out->data_len, p + i, len);
            out->data_len = (uint16_t)(out->data_len + len);
            i += len;
        }
    }
    return i == n ? SLE_ACC_OK : SLE_ACC_TRAILING;
}

size_t sle_bcast_pdu_build(const sle_bcast_pdu_t *pdu, uint8_t *out, size_t cap)
{
    uint8_t tmp[SLE_MAX_PAYLOAD_BYTES];
    bw_t w = { tmp, 16, 0, 0 };
    bw_put(&w, pdu->present, 5);
    bw_put(&w, pdu->rsv0, 3);
    bw_put(&w, pdu->local_id_type, 3);
    bw_put(&w, pdu->peer_id_type, 3);
    bw_put(&w, pdu->rsv1, 2);
    if (w.err) return 0;
    size_t i = 2;
#define PUT(src, k) do { if (i + (k) > sizeof(tmp)) return 0; \
                         memcpy(tmp + i, (src), (k)); i += (k); } while (0)
    if (pdu->present & SLE_PRESENT_LOCAL_ID) PUT(pdu->local_id, 6);
    if (pdu->present & SLE_PRESENT_IRK_ID) PUT(&pdu->irk_id, 1);
    if (pdu->present & SLE_PRESENT_PEER_ID) PUT(pdu->peer_id, 6);
    if (pdu->present & SLE_PRESENT_RESOURCE) {
        uint8_t wb[4] = { (uint8_t)pdu->resource_word, (uint8_t)(pdu->resource_word >> 8),
                          (uint8_t)(pdu->resource_word >> 16), (uint8_t)(pdu->resource_word >> 24) };
        PUT(wb, 4);
    }
    if (pdu->present & SLE_PRESENT_DATA) {
        for (unsigned k = 0; k < pdu->n_tlv; k++) {
            const sle_tlv_ref_t *t = &pdu->tlv[k];
            if ((size_t)t->off + t->len > pdu->data_len) return 0;
            uint8_t h[2] = { t->type, t->len };
            PUT(h, 2);
            PUT(pdu->data + t->off, t->len);
        }
    } else if (pdu->n_tlv) {
        return 0;
    }
#undef PUT
    if (i > cap) return 0;
    memcpy(out, tmp, i);
    return i;
}

sle_acc_status_t sle_bcast_pdu_add_tlv(sle_bcast_pdu_t *pdu, uint8_t type,
                                       const uint8_t *data, size_t len)
{
    if (len > 255) return SLE_ACC_RANGE;
    if (pdu->n_tlv >= SLE_BCAST_MAX_TLV || pdu->data_len + len > sizeof(pdu->data))
        return SLE_ACC_CAPACITY;
    sle_tlv_ref_t *t = &pdu->tlv[pdu->n_tlv++];
    t->type = type;
    t->len = (uint8_t)len;
    t->off = pdu->data_len;
    if (len) memcpy(pdu->data + pdu->data_len, data, len);
    pdu->data_len = (uint16_t)(pdu->data_len + len);
    pdu->present |= SLE_PRESENT_DATA;
    return SLE_ACC_OK;
}

const uint8_t *sle_bcast_pdu_find_tlv(const sle_bcast_pdu_t *pdu, uint8_t type, size_t *len)
{
    for (unsigned k = 0; k < pdu->n_tlv; k++) {
        if (pdu->tlv[k].type == type) {
            if (len) *len = pdu->tlv[k].len;
            return pdu->data + pdu->tlv[k].off;
        }
    }
    return NULL;
}

/* ---- Resource word ------------------------------------------------------ */
sle_acc_status_t sle_resource_word_encode_layout(const sle_resource_word_t *rw,
                                                  sle_resource_layout_t layout, uint32_t *word)
{
    if (!rw || !word || (layout != SLE_RESOURCE_LEGACY_WS63 && layout != SLE_RESOURCE_STANDARD))
        return SLE_ACC_RANGE;
    uint8_t b[4] = { 0 };
    bw_t w = { b, 32, 0, 0 };
    bw_put(&w, rw->channel, 8);
    if (layout == SLE_RESOURCE_LEGACY_WS63) bw_put(&w, rw->unit, 1);
    bw_put(&w, rw->offset, 12);
    bw_put(&w, rw->frame_type, 4);
    bw_put(&w, rw->bandwidth, 2);
    bw_put(&w, rw->pilot, 2);
    bw_put(&w, rw->clock_accuracy, 3);
    if (layout == SLE_RESOURCE_STANDARD) bw_put(&w, rw->unit, 1);
    if (w.err) return SLE_ACC_RANGE;
    *word = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
    return SLE_ACC_OK;
}

sle_acc_status_t sle_resource_word_decode_layout(uint32_t word,
                                                  sle_resource_layout_t layout, sle_resource_word_t *rw)
{
    if (!rw || (layout != SLE_RESOURCE_LEGACY_WS63 && layout != SLE_RESOURCE_STANDARD))
        return SLE_ACC_RANGE;
    uint8_t b[4] = { (uint8_t)word, (uint8_t)(word >> 8), (uint8_t)(word >> 16), (uint8_t)(word >> 24) };
    br_t r = { b, 32, 0, 0 };
    rw->channel = (uint8_t)br_get(&r, 8);
    if (layout == SLE_RESOURCE_LEGACY_WS63) rw->unit = (uint8_t)br_get(&r, 1);
    rw->offset = (uint16_t)br_get(&r, 12);
    rw->frame_type = (uint8_t)br_get(&r, 4);
    rw->bandwidth = (uint8_t)br_get(&r, 2);
    rw->pilot = (uint8_t)br_get(&r, 2);
    rw->clock_accuracy = (uint8_t)br_get(&r, 3);
    if (layout == SLE_RESOURCE_STANDARD) rw->unit = (uint8_t)br_get(&r, 1);
    return SLE_ACC_OK;
}

sle_acc_status_t sle_resource_word_encode(const sle_resource_word_t *rw, uint32_t *word)
{
    return sle_resource_word_encode_layout(rw, SLE_RESOURCE_LEGACY_WS63, word);
}

void sle_resource_word_decode(uint32_t word, sle_resource_word_t *rw)
{
    (void)sle_resource_word_decode_layout(word, SLE_RESOURCE_LEGACY_WS63, rw);
}

uint32_t sle_resource_word_offset_us(const sle_resource_word_t *rw)
{
    return (uint32_t)rw->offset * (rw->unit ? 1250u : 125u);
}

/* ---- TLV 0x00 ----------------------------------------------------------- */
sle_acc_status_t sle_access_resource_parse(const uint8_t *p, size_t n,
                                           sle_access_resource_t *units,
                                           size_t max_units, size_t *n_units)
{
    size_t i = 0, k = 0;
    while (i < n) {
        if (i + 7 > n) return SLE_ACC_TRUNCATED;
        if (k >= max_units) return SLE_ACC_CAPACITY;
        sle_access_resource_t *u = &units[k];
        memset(u, 0, sizeof(*u));
        br_t r = { p + i, 56, 0, 0 };
        u->req_offset_us = (uint16_t)br_get(&r, 16);
        u->req_max_len = (uint8_t)br_get(&r, 8);
        u->rsp_offset_us = (uint16_t)br_get(&r, 16);
        u->gt = (uint8_t)br_get(&r, 2);
        u->count = (uint8_t)br_get(&r, 6);
        u->req_type = (uint8_t)br_get(&r, 2);
        u->carry_info = (uint8_t)br_get(&r, 2);
        u->peer_id_type = (uint8_t)br_get(&r, 3);
        u->id_present = (uint8_t)br_get(&r, 1);
        i += 7;
        if (u->id_present) {
            if (i + 6 > n) return SLE_ACC_TRUNCATED;
            memcpy(u->peer_id, p + i, 6);
            i += 6;
        }
        k++;
    }
    *n_units = k;
    return SLE_ACC_OK;
}

size_t sle_access_resource_build(const sle_access_resource_t *units, size_t n_units,
                                 uint8_t *out, size_t cap)
{
    size_t i = 0;
    for (size_t k = 0; k < n_units; k++) {
        const sle_access_resource_t *u = &units[k];
        size_t need = 7 + (u->id_present ? 6 : 0);
        if (i + need > cap) return 0;
        bw_t w = { out + i, 56, 0, 0 };
        bw_put(&w, u->req_offset_us, 16);
        bw_put(&w, u->req_max_len, 8);
        bw_put(&w, u->rsp_offset_us, 16);
        bw_put(&w, u->gt, 2);
        bw_put(&w, u->count, 6);
        bw_put(&w, u->req_type, 2);
        bw_put(&w, u->carry_info, 2);
        bw_put(&w, u->peer_id_type, 3);
        bw_put(&w, u->id_present, 1);
        if (w.err) return 0;
        i += 7;
        if (u->id_present) { memcpy(out + i, u->peer_id, 6); i += 6; }
    }
    return i;
}

uint32_t sle_access_window_len_us(const sle_access_resource_t *u)
{
    if (u->count == 0 || u->rsp_offset_us < (uint32_t)u->req_offset_us + 125u) return 0;
    return ((uint32_t)u->rsp_offset_us - u->req_offset_us - 125u) / u->count;
}

/* ---- TLV 0x01 ----------------------------------------------------------- */
uint32_t sle_sched_slot_us(uint8_t code)
{
    return code <= 4 ? 25u * (code + 1u) : 0u;
}

static void put_id48(bw_t *w, const uint8_t id[6])
{
    for (int k = 0; k < 6; k++) bw_put(w, id[k], 8);
}

static void get_id48(br_t *r, uint8_t id[6])
{
    for (int k = 0; k < 6; k++) id[k] = (uint8_t)br_get(r, 8);
}

sle_acc_status_t sle_tx_indication_parse(const uint8_t *p, size_t n, sle_tx_indication_t *o)
{
    memset(o, 0, sizeof(*o));
    if (n != SLE_TX_IND_LEN_2G4 && n != SLE_TX_IND_LEN_5G) return SLE_ACC_BAD_LENGTH;
    br_t r = { p, 400, 0, 0 };
    o->base_slot = br_get(&r, 32);
    o->start_offset_us = br_get(&r, 24);
    o->group_period_slots = (uint16_t)br_get(&r, 16);
    o->event_period_slots = (uint16_t)br_get(&r, 16);
    o->intra_event_gap_us = (uint16_t)br_get(&r, 16);
    o->inter_event_gap_us = (uint16_t)br_get(&r, 16);
    o->event_count = (uint8_t)br_get(&r, 8);
    get_id48(&r, o->peer_id);
    o->peer_id_type = (uint8_t)br_get(&r, 3);
    o->sleep_clock_accuracy = (uint8_t)br_get(&r, 3);
    o->first_second = (uint8_t)br_get(&r, 1);
    o->rsv0 = (uint8_t)br_get(&r, 1);
    o->first_frame_type = (uint8_t)br_get(&r, 4);
    o->second_frame_type = (uint8_t)br_get(&r, 4);
    o->first_crc_type = (uint8_t)br_get(&r, 1);
    o->second_crc_type = (uint8_t)br_get(&r, 1);
    o->first_feedback = (uint8_t)br_get(&r, 6);
    o->second_feedback = (uint8_t)br_get(&r, 3);
    o->sched_slot = (uint8_t)br_get(&r, 3);
    o->rsv1 = (uint8_t)br_get(&r, 2);
    o->first_lid = br_get(&r, 24);
    o->second_lid = br_get(&r, 24);
    o->first_bw = (uint8_t)br_get(&r, 2);
    o->second_bw = (uint8_t)br_get(&r, 2);
    o->first_pilot = (uint8_t)br_get(&r, 2);
    o->second_pilot = (uint8_t)br_get(&r, 2);
    o->first_pdu_max = (uint16_t)br_get(&r, 11);
    o->second_pdu_max = (uint16_t)br_get(&r, 11);
    o->first_max_time_offset = (uint16_t)br_get(&r, 9);
    o->second_max_time_offset = (uint16_t)br_get(&r, 9);
    o->first_crc_init = br_get(&r, 32);
    o->second_crc_init = br_get(&r, 32);
    o->latency_groups = (uint16_t)br_get(&r, 16);
    o->timeout_10ms = (uint16_t)br_get(&r, 16);
    if (r.err || r.pos != 400) return SLE_ACC_TRUNCATED;
    o->hop_map_len = (uint8_t)(n - 50);
    memcpy(o->hop_map, p + 50, o->hop_map_len);
    return SLE_ACC_OK;
}

size_t sle_tx_indication_build(const sle_tx_indication_t *in, uint8_t *out, size_t cap)
{
    if (in->hop_map_len != 10 && in->hop_map_len != 25) return 0;
    size_t total = 50u + in->hop_map_len;
    if (total > cap) return 0;
    bw_t w = { out, 400, 0, 0 };
    bw_put(&w, in->base_slot, 32);
    bw_put(&w, in->start_offset_us, 24);
    bw_put(&w, in->group_period_slots, 16);
    bw_put(&w, in->event_period_slots, 16);
    bw_put(&w, in->intra_event_gap_us, 16);
    bw_put(&w, in->inter_event_gap_us, 16);
    bw_put(&w, in->event_count, 8);
    put_id48(&w, in->peer_id);
    bw_put(&w, in->peer_id_type, 3);
    bw_put(&w, in->sleep_clock_accuracy, 3);
    bw_put(&w, in->first_second, 1);
    bw_put(&w, in->rsv0, 1);
    bw_put(&w, in->first_frame_type, 4);
    bw_put(&w, in->second_frame_type, 4);
    bw_put(&w, in->first_crc_type, 1);
    bw_put(&w, in->second_crc_type, 1);
    bw_put(&w, in->first_feedback, 6);
    bw_put(&w, in->second_feedback, 3);
    bw_put(&w, in->sched_slot, 3);
    bw_put(&w, in->rsv1, 2);
    bw_put(&w, in->first_lid, 24);
    bw_put(&w, in->second_lid, 24);
    bw_put(&w, in->first_bw, 2);
    bw_put(&w, in->second_bw, 2);
    bw_put(&w, in->first_pilot, 2);
    bw_put(&w, in->second_pilot, 2);
    bw_put(&w, in->first_pdu_max, 11);
    bw_put(&w, in->second_pdu_max, 11);
    bw_put(&w, in->first_max_time_offset, 9);
    bw_put(&w, in->second_max_time_offset, 9);
    bw_put(&w, in->first_crc_init, 32);
    bw_put(&w, in->second_crc_init, 32);
    bw_put(&w, in->latency_groups, 16);
    bw_put(&w, in->timeout_10ms, 16);
    if (w.err || w.pos != 400) return 0;
    memcpy(out + 50, in->hop_map, in->hop_map_len);
    return total;
}

/* ---- TLV 0x03 ----------------------------------------------------------- */
static const unsigned k_req_widths[8] = { 2, 4, 3, 13, 4, 5, 4, 2 };

static uint32_t req_get(const sle_access_req_info_t *q, unsigned i)
{
    switch (i) {
    case 0: return q->gt;
    case 1: return q->frame_struct;
    case 2: return q->bandwidth;
    case 3: return q->mcs;
    case 4: return q->pilot;
    case 5: return q->sched_slot;
    case 6: return q->switch_delay;
    default: return q->crc;
    }
}

static void req_set(sle_access_req_info_t *q, unsigned i, uint32_t v)
{
    switch (i) {
    case 0: q->gt = (uint8_t)v; break;
    case 1: q->frame_struct = (uint8_t)v; break;
    case 2: q->bandwidth = (uint8_t)v; break;
    case 3: q->mcs = (uint16_t)v; break;
    case 4: q->pilot = (uint8_t)v; break;
    case 5: q->sched_slot = (uint8_t)v; break;
    case 6: q->switch_delay = (uint8_t)v; break;
    default: q->crc = (uint8_t)v; break;
    }
}

sle_acc_status_t sle_access_req_info_parse(const uint8_t *p, size_t n, sle_access_req_info_t *o)
{
    memset(o, 0, sizeof(*o));
    if (n < 1) return SLE_ACC_TRUNCATED;
    br_t r = { p, 8 * n, 0, 0 };
    o->present = (uint8_t)br_get(&r, 8);
    for (unsigned i = 0; i < 8; i++)
        if (o->present >> i & 1u) req_set(o, i, br_get(&r, k_req_widths[i]));
    if (r.err) return SLE_ACC_TRUNCATED;
    size_t padw = r.nbits - r.pos;
    if (padw >= 8) return SLE_ACC_TRAILING;
    o->pad = (uint8_t)br_get(&r, (unsigned)padw);
    return SLE_ACC_OK;
}

size_t sle_access_req_info_build(const sle_access_req_info_t *in, uint8_t *out, size_t cap)
{
    size_t bits = 8;
    for (unsigned i = 0; i < 8; i++)
        if (in->present >> i & 1u) bits += k_req_widths[i];
    size_t nbytes = (bits + 7) / 8;
    if (nbytes > cap) return 0;
    bw_t w = { out, 8 * nbytes, 0, 0 };
    bw_put(&w, in->present, 8);
    for (unsigned i = 0; i < 8; i++)
        if (in->present >> i & 1u) bw_put(&w, req_get(in, i), k_req_widths[i]);
    bw_put(&w, in->pad, (unsigned)(8 * nbytes - bits));
    return w.err ? 0 : nbytes;
}

/* ---- TLV 0x04 ----------------------------------------------------------- */
static int rsp_has_cap(uint8_t repeat, unsigned k)
{
    return repeat == 2 || (repeat == 1 && k == 0);
}

sle_acc_status_t sle_access_rsp_info_parse(const uint8_t *p, size_t n, sle_access_rsp_info_t *o)
{
    memset(o, 0, sizeof(*o));
    if (n < 1) return SLE_ACC_TRUNCATED;
    o->count = p[0] & 0x3F;
    o->rsv = p[0] >> 6;
    if (o->count > SLE_ACCESS_RSP_MAX_UNITS) return SLE_ACC_CAPACITY;
    size_t i = 1;
    for (unsigned k = 0; k < o->count; k++) {
        sle_access_rsp_unit_t *u = &o->unit[k];
        if (i + 7 > n) return SLE_ACC_TRUNCATED;
        memcpy(u->peer_id, p + i, 6);
        u->rsp_type = p[i + 6] & 7u;
        u->peer_id_type = (p[i + 6] >> 3) & 7u;
        u->repeat = p[i + 6] >> 6;
        i += 7;
        if (rsp_has_cap(u->repeat, k)) {
            if (i + 6 > n) return SLE_ACC_TRUNCATED;
            u->has_capability = 1;
            memcpy(u->capability, p + i, 6);
            i += 6;
        }
    }
    return i == n ? SLE_ACC_OK : SLE_ACC_TRAILING;
}

size_t sle_access_rsp_info_build(const sle_access_rsp_info_t *in, uint8_t *out, size_t cap)
{
    if (in->count > SLE_ACCESS_RSP_MAX_UNITS || in->rsv > 3) return 0;
    size_t i = 0;
    if (cap < 1) return 0;
    out[i++] = (uint8_t)(in->count | in->rsv << 6);
    for (unsigned k = 0; k < in->count; k++) {
        const sle_access_rsp_unit_t *u = &in->unit[k];
        if (u->rsp_type > 7 || u->peer_id_type > 7 || u->repeat > 3) return 0;
        if (i + 7 > cap) return 0;
        memcpy(out + i, u->peer_id, 6);
        out[i + 6] = (uint8_t)(u->rsp_type | u->peer_id_type << 3 | u->repeat << 6);
        i += 7;
        if (rsp_has_cap(u->repeat, k)) {
            if (!u->has_capability || i + 6 > cap) return 0;
            memcpy(out + i, u->capability, 6);
            i += 6;
        }
    }
    return i;
}

/* ---- Complete payloads -------------------------------------------------- */
size_t sle_access_request_build(const uint8_t local_id[6], const uint8_t peer_id[6],
                                const sle_tx_indication_t *txi,
                                const sle_access_req_info_t *req,
                                uint8_t *out, size_t cap)
{
    sle_bcast_pdu_t pdu;
    uint8_t buf[80];
    sle_bcast_pdu_init(&pdu);
    pdu.present = SLE_PRESENT_LOCAL_ID | SLE_PRESENT_PEER_ID;
    memcpy(pdu.local_id, local_id, 6);
    memcpy(pdu.peer_id, peer_id, 6);
    size_t n = sle_tx_indication_build(txi, buf, sizeof(buf));
    if (!n || sle_bcast_pdu_add_tlv(&pdu, SLE_TLV_TX_INDICATION, buf, n) != SLE_ACC_OK) return 0;
    n = sle_access_req_info_build(req, buf, sizeof(buf));
    if (!n || sle_bcast_pdu_add_tlv(&pdu, SLE_TLV_ACCESS_REQ_INFO, buf, n) != SLE_ACC_OK) return 0;
    return sle_bcast_pdu_build(&pdu, out, cap);
}

size_t sle_access_response_build(const uint8_t local_id[6], const sle_access_rsp_info_t *rsp,
                                 uint8_t *out, size_t cap)
{
    sle_bcast_pdu_t pdu;
    uint8_t buf[1 + SLE_ACCESS_RSP_MAX_UNITS * 13];
    sle_bcast_pdu_init(&pdu);
    pdu.present = SLE_PRESENT_LOCAL_ID;
    memcpy(pdu.local_id, local_id, 6);
    size_t n = sle_access_rsp_info_build(rsp, buf, sizeof(buf));
    if (!n || sle_bcast_pdu_add_tlv(&pdu, SLE_TLV_ACCESS_RSP_INFO, buf, n) != SLE_ACC_OK) return 0;
    return sle_bcast_pdu_build(&pdu, out, cap);
}

size_t sle_access_encode_frame(uint8_t *out_bits, size_t cap_bits, const uint8_t *payload,
                               size_t len, uint8_t phys_channel, uint8_t btype, uint8_t ptype)
{
    if (len > SLE_MAX_PAYLOAD_BYTES || phys_channel > 127 || btype > 7 || ptype > 7) return 0;
    if (SLE_SYNC_BITS + SLE_HEADER_BITS + 8 * len + SLE_CRC24_BITS > cap_bits) return 0;
    return sle_encode_broadcast(out_bits, payload, len, phys_channel, btype, ptype, 0);
}
