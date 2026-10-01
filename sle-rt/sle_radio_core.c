#include "sle_radio_core.h"
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

void sle_rt_energy_reset(sle_rt_energy *g, int keep_floor)
{
    if (!keep_floor) { memset(g,0,sizeof *g); g->floor_sum=UINT64_MAX; }
    g->have_previous=g->previous_hot=g->previous_fed=0;
}
unsigned sle_rt_energy_step(sle_rt_energy *g, const int16_t iq[SLE_RT_BLOCK*2])
{
    uint64_t sum=0, bin=0, peak=0;
    g->clipped=0; g->sampled=SLE_RT_BLOCK/4;
    for (unsigned k=0;k<SLE_RT_BLOCK;k+=4) {
        int64_t i=iq[2*k], q=iq[2*k+1];
        bin+=(uint64_t)(i*i+q*q);
        if (i>=2047 || i<=-2048 || q>=2047 || q<=-2048) g->clipped++;
        if ((k & 127u)==124u) {
            sum+=bin; if (bin>peak) peak=bin; bin=0;
        }
    }
    g->last_sum=sum; g->last_bin_sum=peak;
    if (sum<g->floor_sum) g->floor_sum=sum;
    if (peak>g->peak_bin_sum) g->peak_bin_sum=peak;
    unsigned flags=0;
    if (g->learned<SLE_RT_ENERGY_LEARN_BLOCKS) { g->learned++; flags|=SLE_RT_GATE_LEARNING; }
    else if (g->floor_sum && g->peak_bin_sum*(SLE_RT_BLOCK/128)<=g->floor_sum*SLE_RT_ENERGY_FACTOR) flags|=SLE_RT_GATE_OPEN;
    int hot=flags || peak*(SLE_RT_BLOCK/128)>g->floor_sum*SLE_RT_ENERGY_FACTOR;
    if (hot) flags|=SLE_RT_GATE_HOT;
    if (hot || g->previous_hot) {
        flags|=SLE_RT_GATE_CURRENT;
        if (!hot) flags|=SLE_RT_GATE_POST;
        if (hot && g->have_previous && !g->previous_fed) flags|=SLE_RT_GATE_PREVIOUS;
    }
    g->have_previous=1; g->previous_hot=hot;
    g->previous_fed=(flags & SLE_RT_GATE_CURRENT)!=0;
    return flags;
}

int64_t sle_rt_access_lead(void)
{
    return SLE_RT_ACCESS_TX_RETUNE_US*4 + SLE_RT_ACCESS_DEPTH*SLE_RT_BLOCK + SLE_RT_TX_GUARD +
        sle_rt_sync_in_wave() - SLE_GFSK_PREAMBLE_BITS*4;
}
int64_t sle_rt_access_response_lead(int need_tx_retune)
{
    return (need_tx_retune ? SLE_RT_ACCESS_TX_RETUNE_US*4 : 0) +
        (SLE_RT_ACCESS_ACK_US+SLE_RT_ACCESS_RX_RETUNE_US+SLE_RT_ACCESS_SETTLE_US)*4 +
        SLE_RT_BLOCK + SLE_RT_REPLY_TOL + SLE_GFSK_PREAMBLE_BITS*4;
}
int sle_rt_maintained(int64_t first, int64_t last, int64_t now,
                  int64_t hold, int64_t supervision, int64_t fresh)
{
    return first>=0 && last>first && now>=last && hold>supervision && supervision>0 &&
        fresh>0 && fresh<supervision && last-first>=hold && now-last<=fresh;
}

const char *sle_rt_result_name(int r)
{
    static const char *const names[] = {"ok", "ignore", "bad_frame", "identity",
        "rejected", "late", "range", "no_calibration", "offset_jump", "timeout",
        "busy", "overlap", "cancelled"};
    return r >= 0 && (size_t)r < sizeof names / sizeof names[0] ? names[r] : "unknown";
}

int sle_rt_peer_init(sle_rt_peer *p, const uint8_t local[6], const uint8_t server[6],
                 uint32_t lid, uint32_t crc, uint32_t slot)
{
    if (!p || !local || !server || !lid || lid >= 0xffffff || slot > SLE_SLOT_MASK ||
        !memcmp(local, server, 6)) return SLE_RT_RANGE;
    memset(p, 0, sizeof *p);
    memcpy(p->local, local, 6); memcpy(p->server, server, 6);
    sle_tx_indication_t *t = &p->txi;
    t->base_slot = slot; t->start_offset_us = 9534;
    t->group_period_slots = t->event_period_slots = 100;
    t->intra_event_gap_us = 125; t->event_count = 1;
    memcpy(t->peer_id, server, 6);
    t->sleep_clock_accuracy = 1; t->sched_slot = 4;
    t->first_lid = t->second_lid = lid;
    t->first_pdu_max = t->second_pdu_max = 2047;
    t->first_max_time_offset = t->second_max_time_offset = 100;
    t->first_crc_init = t->second_crc_init = crc;
    t->timeout_10ms = 508; t->hop_map_len = 10;
    const uint8_t map[10] = {0xfe,0xff,0xbf,0xff,0xff,0xff,0xff,0xff,0xff,0x3f};
    memcpy(t->hop_map, map, 10);
    const uint8_t info[6] = {0xff,0xcd,0x81,0x6a,0x43,0x18};
    return sle_access_req_info_parse(info, sizeof info, &p->req) == SLE_ACC_OK ? SLE_RT_OK : SLE_RT_RANGE;
}

static int frame_ok(const sle_frame_t *f)
{
    return f->crc12_ok && (!f->has_crc24 || f->crc24_ok) &&
           f->length == f->payload_len && f->payload_len <= sizeof f->payload;
}

int sle_rt_primary_layout(const sle_rt_peer *p, const sle_found_frame_t *f, int64_t now,
                      int64_t lead, int64_t shift, sle_resource_layout_t layout,
                      sle_access_plan_t *plan)
{
    if (!p || !f || !plan || now < 0 || now > INT64_MAX / 1000 || lead < 0 || lead > SLE_RT_FS ||
        shift < -400 || shift > 400 || f->sample_index > INT64_MAX / 1000 ||
        (layout != SLE_RESOURCE_LEGACY_WS63 && layout != SLE_RESOURCE_STANDARD)) return SLE_RT_RANGE;
    const sle_frame_t *a = &f->frame;
    if (a->kind != SLE_FRAME_BROADCAST || f->channel_mhz != 2424 || a->seed != 77 ||
        a->packet_type != SLE_PTYPE_PRIMARY || a->broadcast_type != SLE_BTYPE_CONN_QUERY)
        return SLE_RT_IGNORE;
    if (!frame_ok(a) || !a->has_crc24 || a->reserved) return SLE_RT_BAD_FRAME;
    sle_bcast_pdu_t b;
    if (sle_bcast_pdu_parse(a->payload, a->payload_len, &b) || b.present != 9 ||
        b.local_id_type || b.rsv0 || b.rsv1) return SLE_RT_BAD_FRAME;
    if (memcmp(b.local_id, p->server, 6)) return SLE_RT_IDENTITY;
    sle_resource_word_t rw;
    if (sle_resource_word_decode_layout(b.resource_word, layout, &rw)) return SLE_RT_RANGE;
    if (rw.channel >= 76 || rw.frame_type || rw.bandwidth || rw.pilot || !rw.offset)
        return SLE_RT_RANGE;
    /* Explicit O4 WS63 profile: auxiliary TLV was constant in that recording.
     * It is not negotiated by the primary. Validate this assumption on air. */
    sle_access_resource_t u = {.req_offset_us=2500, .req_max_len=255,
        .rsp_offset_us=6250, .count=1, .req_type=2};
    /* sle_clock's existing plan API consumes legacy packing. Re-encode the
     * explicitly selected interpretation without changing its timing policy. */
    uint32_t normalized;
    if (sle_resource_word_encode(&rw, &normalized)) return SLE_RT_RANGE;
    sle_access_plan_in_t in = {.primary_sync_ns=sle_samples_to_ns((int64_t)f->sample_index, SLE_RT_FS),
        .resource_word=normalized, .aux_correction_ns=25000,
        .now_ns=0, .tx_lead_ns=0,
        .request_len=84};
    int r = sle_access_plan(&in, &u, plan);
    if (r != SLE_PLAN_OK) return r == SLE_PLAN_LATE ? SLE_RT_LATE : SLE_RT_RANGE;
    plan->req_sync_ns += sle_samples_to_ns(shift, SLE_RT_FS);
    plan->req_tx_start_ns += sle_samples_to_ns(shift, SLE_RT_FS);
    /* Keep predicted times even for a late primary, for age/slack telemetry.
     * The O4 profile has only window 0; no late-window fallback is allowed. */
    return plan->req_tx_start_ns < sle_samples_to_ns(now+lead,SLE_RT_FS) ? SLE_RT_LATE : SLE_RT_OK;
}

int sle_rt_primary(const sle_rt_peer *p, const sle_found_frame_t *f, int64_t now,
               int64_t lead, int64_t shift, sle_access_plan_t *plan)
{
    return sle_rt_primary_layout(p, f, now, lead, shift, SLE_RESOURCE_LEGACY_WS63, plan);
}

int sle_rt_response(const sle_rt_peer *p, const sle_access_plan_t *plan, const sle_found_frame_t *f)
{
    if (!p || !plan || !f || f->sample_index > INT64_MAX / 1000) return SLE_RT_RANGE;
    const sle_frame_t *a = &f->frame;
    if (a->kind != SLE_FRAME_BROADCAST || a->packet_type != SLE_PTYPE_ACCESS_RSP ||
        a->broadcast_type != 3 || f->channel_mhz != plan->aux_mhz || a->seed != plan->aux_channel)
        return SLE_RT_IGNORE;
    if (!frame_ok(a) || !a->has_crc24 || a->reserved) return SLE_RT_BAD_FRAME;
    if (llabs((int64_t)f->sample_index - sle_ns_to_samples(plan->rsp_sync_ns, SLE_RT_FS)) > SLE_RT_REPLY_TOL)
        return SLE_RT_LATE;
    sle_bcast_pdu_t b;
    if (sle_bcast_pdu_parse(a->payload, a->payload_len, &b) || b.present != 0x11 ||
        b.local_id_type || b.rsv0 || b.rsv1) return SLE_RT_BAD_FRAME;
    if (memcmp(b.local_id, p->server, 6)) return SLE_RT_IDENTITY;
    size_t n;
    const uint8_t *v = sle_bcast_pdu_find_tlv(&b, SLE_TLV_ACCESS_RSP_INFO, &n);
    sle_access_rsp_info_t rsp;
    if (!v || b.n_tlv != 1 || sle_access_rsp_info_parse(v, n, &rsp) || rsp.rsv) return SLE_RT_BAD_FRAME;
    for (unsigned i = 0; i < rsp.count; i++) {
        const sle_access_rsp_unit_t *u = &rsp.unit[i];
        if (memcmp(u->peer_id, p->local, 6) || u->peer_id_type) continue;
        if (u->rsp_type) return SLE_RT_REJECTED;
        /* The auxiliary profile's validated single-unit, capability-once response. */
        const uint8_t cap[6] = {0xff,0xcc,0x81,0x6a,0x43,0x18};
        if (rsp.count != 1 || u->repeat != 1 || !u->has_capability ||
            memcmp(u->capability, cap, 6)) return SLE_RT_BAD_FRAME;
        return SLE_RT_OK;
    }
    return SLE_RT_IDENTITY;
}

void sle_rt_cal_clear(sle_rt_cal *c) { memset(c, 0, sizeof *c); }
int sle_rt_cal_observe(sle_rt_cal *c, int64_t tx, int64_t rx)
{
    if (!c || tx < 0 || rx < 0) return SLE_RT_RANGE;
    int64_t off = rx - tx;
    if (llabs(off) > SLE_RT_FS / 5) { sle_rt_cal_clear(c); return SLE_RT_RANGE; }
    if (c->count && llabs(off - c->offset) > SLE_RT_OFFSET_TOL) {
        sle_rt_cal_clear(c); return SLE_RT_OFFSET_JUMP;
    }
    if (!c->count) c->offset = off;
    if (c->count < SLE_RT_CAL_COUNT) c->count++;
    c->valid = c->count == SLE_RT_CAL_COUNT; c->last_sample = rx;
    return SLE_RT_OK;
}
int sle_rt_cal_fresh(const sle_rt_cal *c, int64_t now, int64_t ttl)
{
    return c && c->valid && now >= c->last_sample && now - c->last_sample <= ttl;
}

int64_t sle_rt_sync_in_wave(void)
{
    sle_gfsk_cfg_t c; sle_gfsk_default(&c, SLE_RT_FS);
    return c.lead + SLE_GFSK_PREAMBLE_BITS * (SLE_RT_FS / 1000000);
}
int sle_rt_modulate(sle_rt_wave *w, const uint8_t *bits, size_t n, double cfo)
{
    uint8_t all[1024];
    if (!w || !bits || !isfinite(cfo) || fabs(cfo) > 200000 || n > sizeof all - 10) return SLE_RT_RANGE;
    sle_gfsk_cfg_t c; sle_gfsk_default(&c, SLE_RT_FS);
    size_t nb = sle_gfsk_with_preamble(bits, n, all, sizeof all);
    if (!nb) return SLE_RT_RANGE;
    w->n = sle_gfsk_mod(&c, all, nb, cfo, w->iq, SLE_RT_WAVE_MAX);
    return w->n ? SLE_RT_OK : SLE_RT_RANGE;
}
void sle_rt_rotate(sle_rt_wave *out, const sle_rt_wave *in, double cfo)
{
    size_t n = in->n;
    out->n = 0;
    if (n > SLE_RT_WAVE_MAX || !isfinite(cfo) || fabs(cfo) > 200000) return;
    double ph = 6.283185307179586 * cfo / SLE_RT_FS;
    double cr = cos(ph), ci = sin(ph), re = 1, im = 0;
    for (size_t k = 0; k < n; k++) {
        double i = in->iq[2*k], q = in->iq[2*k+1];
        out->iq[2*k] = (int16_t)lrint(i*re-q*im);
        out->iq[2*k+1] = (int16_t)lrint(i*im+q*re);
        double r = re*cr-im*ci; im = re*ci+im*cr; re = r;
    }
    out->n = n;
}
int sle_rt_tx_index(const sle_rt_cal *c, int64_t rx, int64_t head, int64_t *start)
{
    if (!c || !c->valid) return SLE_RT_NO_CAL;
    if (!start || rx < 0 || rx > INT64_MAX / 2 || c->offset < -SLE_RT_FS || c->offset > SLE_RT_FS || head < 0)
        return SLE_RT_RANGE;
    *start = rx - c->offset - sle_rt_sync_in_wave();
    return *start < head ? SLE_RT_LATE : SLE_RT_OK;
}
int sle_rt_render_arm(sle_rt_renderer *r, int64_t head, int64_t start, const sle_rt_wave *w)
{
    if (!r || !w || !w->n || w->n > SLE_RT_WAVE_MAX || head < 0 || start < 0 ||
        start > INT64_MAX - (int64_t)w->n) return SLE_RT_RANGE;
    if (r->active) return SLE_RT_BUSY;
    if (start < head) return SLE_RT_LATE;
    r->start = start; r->next_head = head; r->wave = *w; r->active = 1;
    return SLE_RT_OK;
}
int sle_rt_render_block(sle_rt_renderer *r, int16_t *dst, int64_t base, size_t n)
{
    if (!r || !dst || n > SLE_RT_BLOCK || base < 0 || base > INT64_MAX - (int64_t)n) return SLE_RT_RANGE;
    memset(dst, 0, n * 2 * sizeof *dst);
    if (!r->active) return SLE_RT_OK;
    if (base != r->next_head) { sle_rt_render_clear(r); return SLE_RT_LATE; }
    r->next_head = base + (int64_t)n;
    int64_t end = r->start + (int64_t)r->wave.n;
    if (end <= base) { sle_rt_render_clear(r); return SLE_RT_LATE; }
    int64_t a = base > r->start ? base : r->start;
    int64_t b = base + (int64_t)n < end ? base + (int64_t)n : end;
    if (b > a) memcpy(dst + 2*(a-base), r->wave.iq + 2*(a-r->start), (size_t)(b-a)*4);
    if (end <= base + (int64_t)n) sle_rt_render_clear(r);
    return SLE_RT_OK;
}
void sle_rt_render_clear(sle_rt_renderer *r) { r->active = 0; r->wave.n = 0; }
int sle_rt_expired(int64_t now, int64_t deadline) { return now > deadline; }

int sle_rt_reply_matches(const sle_link_tx_t *tx, const sle_conn_sched_t *s,
                     const sle_found_frame_t *f, int64_t *error)
{
    if (f->frame.kind != SLE_FRAME_CONNECT || f->channel_mhz != tx->ev.mhz ||
        f->frame.seed != tx->ev.white_seed || !f->frame.crc12_ok) return SLE_RT_IGNORE;
    int64_t expect = sle_ns_to_samples(tx->ev.t_ns +
        sle_second_sender_offset_ns(s, tx->len, tx->empty) - 3000, SLE_RT_FS);
    *error = (int64_t)f->sample_index - expect;
    return llabs(*error) <= SLE_RT_REPLY_TOL ? SLE_RT_OK : SLE_RT_LATE;
}
