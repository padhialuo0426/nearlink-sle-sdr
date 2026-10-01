/* sle_clock.c - see sle_clock.h. */
#include "sle_clock.h"

#include <string.h>

int sle_phys_to_rf(int phys)
{
    if (phys == 76) return 0;
    if (phys == 77) return 22;
    if (phys == 78) return 78;
    if (phys >= 0 && phys <= 20) return phys + 1;
    if (phys >= 21 && phys <= 75) return phys + 2;
    return -1;
}

int sle_rf_to_phys(int rf)
{
    for (int p = 0; p <= 78; p++)
        if (sle_phys_to_rf(p) == rf) return p;
    return -1;
}

int sle_phys_to_mhz(int phys)
{
    int rf = sle_phys_to_rf(phys);
    return rf < 0 ? -1 : 2402 + rf;
}

sle_time_ns_t sle_samples_to_ns(int64_t samples, uint32_t fs_hz)
{
    /* split to avoid overflow for long runs */
    int64_t q = samples / (int64_t)fs_hz, r = samples % (int64_t)fs_hz;
    return q * 1000000000LL + (r * 1000000000LL) / (int64_t)fs_hz;
}

int64_t sle_ns_to_samples(sle_time_ns_t t, uint32_t fs_hz)
{
    int64_t q = t / 1000000000LL, r = t % 1000000000LL;
    return q * (int64_t)fs_hz + (r * (int64_t)fs_hz + 500000000LL) / 1000000000LL;
}

int64_t sle_frame_air_ns(uint32_t payload_len, int connect_empty)
{
    int64_t bits = SLE_SYNC_BITS + SLE_HEADER_BITS;
    if (!connect_empty) bits += 8LL * payload_len + SLE_CRC24_BITS;
    return SLE_PREAMBLE_NS + bits * 1000LL;
}

sle_plan_status_t sle_access_plan(const sle_access_plan_in_t *in,
                                  const sle_access_resource_t *unit,
                                  sle_access_plan_t *out)
{
    sle_resource_word_t rw;
    memset(out, 0, sizeof(*out));
    sle_resource_word_decode(in->resource_word, &rw);
    out->aux_channel = rw.channel;
    out->aux_mhz = sle_phys_to_mhz(rw.channel);
    out->window_len_us = sle_access_window_len_us(unit);
    if (out->aux_mhz < 0 || rw.channel > 75 || out->window_len_us == 0 ||
        unit->req_type == 0 || unit->req_type == 3) {
        out->status = SLE_PLAN_BAD;
        return out->status;
    }
    out->aux_sync_ns = in->have_aux ? in->aux_sync_ns
        : in->primary_sync_ns + (int64_t)sle_resource_word_offset_us(&rw) * 1000 + in->aux_correction_ns;
    int64_t air = sle_frame_air_ns(in->request_len, 0);
    if (in->request_len > unit->req_max_len || air > (int64_t)out->window_len_us * 1000) {
        out->status = SLE_PLAN_TOO_LONG;
        return out->status;
    }
    unsigned nwin = in->allow_later_window ? unit->count : 1u;
    out->status = SLE_PLAN_LATE;
    for (unsigned n = 0; n < nwin; n++) {
        sle_time_ns_t req = out->aux_sync_ns +
            ((int64_t)unit->req_offset_us + (int64_t)n * out->window_len_us) * 1000;
        out->window = (uint8_t)n;
        out->req_sync_ns = req;
        out->req_tx_start_ns = req - SLE_PREAMBLE_NS;
        if (in->now_ns + in->tx_lead_ns <= out->req_tx_start_ns) {
            out->status = SLE_PLAN_OK;
            break;
        }
    }
    out->rsp_sync_ns = out->aux_sync_ns + (int64_t)unit->rsp_offset_us * 1000;
    return out->status;
}

uint32_t sle_sync32_from_lid(uint32_t lid)
{
    uint8_t b[32];
    sle_sync_from_lid(lid, b);
    return sle_bits_to_u32_lsb(b, 32);
}

static uint16_t rev_bytes16(uint16_t x)
{
    uint16_t y = 0;
    for (int i = 0; i < 8; i++) {
        if (x >> i & 1u) y |= (uint16_t)(1u << (7 - i));
        if (x >> (8 + i) & 1u) y |= (uint16_t)(1u << (15 - i));
    }
    return y;
}

uint16_t sle_hop_prng(uint32_t slot, uint32_t sync32)
{
    uint16_t p2 = (uint16_t)((sync32 & 0xFFFFu) ^ (sync32 >> 16));
    uint16_t x = (uint16_t)((slot & 0xFFFFu) ^ p2);
    for (int i = 0; i < 3; i++)
        x = (uint16_t)(rev_bytes16(x) * 17u + p2);
    return (uint16_t)(x ^ p2);
}

int sle_hop_channel(uint16_t r, const uint8_t *used, uint8_t n_used)
{
    if (n_used == 0) return -1;
    int p = r % 76;
    for (unsigned i = 0; i < n_used; i++)
        if (used[i] == p) return p;
    return used[((uint32_t)r * n_used) >> 16];
}

uint8_t sle_hop_map_used(const uint8_t *hop_map, uint8_t map_len, uint8_t used[76])
{
    uint8_t n = 0;
    for (int p = 0; p < 76; p++) {
        int rf = sle_phys_to_rf(p);
        if (rf / 8 < map_len && (hop_map[rf / 8] >> (rf % 8) & 1u)) used[n++] = (uint8_t)p;
    }
    return n;
}

int sle_conn_sched_init(sle_conn_sched_t *s, sle_time_ns_t anchor_sync_ns,
                        const sle_tx_indication_t *txi)
{
    memset(s, 0, sizeof(*s));
    uint32_t slot_us = sle_sched_slot_us(txi->sched_slot);
    if (slot_us == 0 || txi->group_period_slots == 0 || txi->hop_map_len != 10) return -1;
    s->t0_ns = anchor_sync_ns + (int64_t)txi->start_offset_us * 1000;
    s->base_slot = txi->base_slot & SLE_SLOT_MASK;
    s->period_slots = txi->group_period_slots;
    s->slot_ns = (int64_t)slot_us * 1000;
    s->lid = txi->first_lid;
    s->sync32 = sle_sync32_from_lid(txi->first_lid);
    s->n_used = sle_hop_map_used(txi->hop_map, txi->hop_map_len, s->used);
    s->intra_gap_ns = (int64_t)txi->intra_event_gap_us * 1000;
    s->timeout_ms = (uint32_t)txi->timeout_10ms * 10u;
    return s->n_used ? 0 : -1;
}

void sle_conn_event(const sle_conn_sched_t *s, uint32_t k, sle_conn_event_t *ev)
{
    ev->k = k;
    ev->t_ns = s->t0_ns + (int64_t)k * s->period_slots * s->slot_ns;
    ev->slot = (s->base_slot + k * s->period_slots) & SLE_SLOT_MASK;
    ev->phys = (uint8_t)sle_hop_channel(sle_hop_prng(ev->slot, s->sync32), s->used, s->n_used);
    ev->mhz = sle_phys_to_mhz(ev->phys);
    ev->white_seed = (uint8_t)(0x40u | (ev->slot & 0x3Fu));
}

uint32_t sle_conn_next_event(const sle_conn_sched_t *s, sle_time_ns_t not_before_ns)
{
    int64_t span = (int64_t)s->period_slots * s->slot_ns;
    int64_t d = not_before_ns - (s->t0_ns - SLE_PREAMBLE_NS);
    if (d <= 0) return 0;
    return (uint32_t)((d + span - 1) / span);
}

int64_t sle_second_sender_offset_ns(const sle_conn_sched_t *s, uint32_t first_payload_len,
                                    int first_empty)
{
    int64_t dur = sle_frame_air_ns(first_payload_len, first_empty);
    int64_t need = dur + s->intra_gap_ns;
    /* preamble-start grid: first preamble at slot boundary */
    return ((need + s->slot_ns - 1) / s->slot_ns) * s->slot_ns;
}

int sle_conn_timed_out(const sle_conn_sched_t *s, sle_time_ns_t last_rx_ns, sle_time_ns_t now_ns)
{
    return now_ns - last_rx_ns > (int64_t)s->timeout_ms * 1000000LL;
}
