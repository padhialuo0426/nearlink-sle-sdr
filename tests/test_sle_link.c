/* test_sle_link.c - O5 link model tests.
 *
 * 1. ARQ core and link edge cases (loss, duplicates, stale ack, bad body,
 *    late host, supervision, instants, parameter update boundaries).
 * 2. Control PDU codecs with hand-computed byte vectors.
 * 3. Closed loop: G and T links over a simulated channel with real A2
 *    encode/decode, frame loss and bit errors, a hop map update (remap
 *    branch), a parameter update and a final disconnect.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sle_link.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static const uint8_t MAP_ALL[10] = { 0xfe, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f };
#define LID 0x66A275u
#define PERIOD_NS 12500000LL

static void make_sched(sle_conn_sched_t *s, uint32_t base_slot, uint32_t timeout_10ms)
{
    memset(s, 0, sizeof(*s));
    s->t0_ns = 1000000000LL;
    s->base_slot = base_slot;
    s->period_slots = 100;
    s->slot_ns = 125000;
    s->lid = LID;
    s->sync32 = sle_sync32_from_lid(LID);
    s->n_used = sle_hop_map_used(MAP_ALL, 10, s->used);
    s->intra_gap_ns = 125000;
    s->timeout_ms = timeout_10ms * 10u;
}

static sle_link_rx_t reply(sle_rx_kind_t kind, int empty, int sn, int nesn, const uint8_t *d, int n)
{
    sle_link_rx_t r;
    memset(&r, 0, sizeof r);
    r.kind = kind;
    r.empty = (uint8_t)empty;
    r.sn = (uint8_t)sn;
    r.nesn = (uint8_t)nesn;
    r.ptype = SLE_PTYPE_DATA;
    r.data = d;
    r.len = (uint16_t)n;
    return r;
}

/* Prepare the next consecutive event. */
static int next(sle_link_t *l, sle_link_tx_t *tx)
{
    return sle_link_g_prepare(l, 0, 0, tx);
}

static void test_arq_core(void)
{
    sle_arq_t a = { 0, 0, 1 };
    sle_arq_out_t o;
    sle_arq_rx(&a, 1, 0, 0, 1, &o);           /* peer did not get it (NESN still 0) */
    CHECK(!o.acked && a.tx_sn == 0 && a.has_cur);
    sle_arq_rx(&a, 1, 1, 1, 1, &o);           /* empty with SN 1: SN ignored, ack */
    CHECK(o.acked && !o.deliver && !o.dup && a.tx_sn == 1 && !a.has_cur);
    sle_arq_rx(&a, 0, 0, 1, 0, &o);           /* data with bad body: nothing */
    CHECK(!o.deliver && !o.dup && a.rx_nesn == 0);
    sle_arq_rx(&a, 0, 0, 1, 1, &o);           /* new data */
    CHECK(o.deliver && a.rx_nesn == 1);
    sle_arq_rx(&a, 0, 0, 1, 1, &o);           /* same SN again: duplicate */
    CHECK(o.dup && !o.deliver && a.rx_nesn == 1);
    sle_arq_rx(&a, 0, 1, 0, 1, &o);           /* no outstanding PDU: NESN ignored */
    CHECK(!o.acked && o.deliver && a.tx_sn == 1 && a.rx_nesn == 0);
}

static void test_ctrl_codecs(void)
{
    uint8_t b[32], map[10];
    uint32_t lid, instant;
    uint8_t reason;
    static const uint8_t disc[] = { 0x1e, 0x00, 0x04, 0x75, 0xa2, 0x66, 0x13 };
    CHECK(sle_ctrl_disconnect_build(LID, 0x13, b, sizeof b) == 7 && !memcmp(b, disc, 7));
    CHECK(sle_ctrl_disconnect_parse(b, 7, &lid, &reason) == 0 && lid == LID && reason == 0x13);
    CHECK(sle_ctrl_disconnect_parse(b, 6, &lid, &reason) < 0);

    static const uint8_t hm[] = { 0x13, 0x00, 0x0e, 0xfe, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff,
                                  0xff, 0xff, 0x3f, 0x78, 0x56, 0x34, 0x12 };
    CHECK(sle_ctrl_hopmap_build(MAP_ALL, 0x12345678u, b, sizeof b) == 17 && !memcmp(b, hm, 17));
    CHECK(sle_ctrl_hopmap_parse(b, 17, map, &instant) == 0 && instant == 0x12345678u &&
          !memcmp(map, MAP_ALL, 10));

    /* Table 75 fields in order, LSB-first; last byte: sched 4 (3 bits) | first_second 1 << 3. */
    sle_param_update_t p = { 2400, 6, 200, 150, 0x0102, 7, 100, 4, 1 }, q;
    static const uint8_t pu[] = { 0x3a, 0x00, 0x11, 0x60, 0x09, 0x00, 0x00, 0x06, 0x00, 0xc8, 0x00,
                                  0x96, 0x00, 0x02, 0x01, 0x07, 0x00, 0x64, 0x00, 0x0c };
    CHECK(sle_ctrl_param_update_build(&p, b, sizeof b) == 20 && !memcmp(b, pu, 20));
    CHECK(sle_ctrl_param_update_parse(b, 20, &q) == 0 && q.ref_slot == p.ref_slot &&
          q.offset_slots == p.offset_slots && q.period_slots == p.period_slots &&
          q.intra_gap_us == p.intra_gap_us && q.inter_gap_us == p.inter_gap_us &&
          q.latency_groups == p.latency_groups && q.timeout_10ms == p.timeout_10ms &&
          q.sched_slot == p.sched_slot && q.first_second == p.first_second);
    b[19] |= 0x10;                                   /* reserved bit set */
    CHECK(sle_ctrl_param_update_parse(b, 20, &q) < 0);
    CHECK(sle_ctrl_param_update_build(&p, b, 19) == 0);
}

static void test_loss_dup_stale(void)
{
    sle_conn_sched_t s;
    sle_link_t *l = calloc(1, sizeof *l);
    sle_link_tx_t tx;
    sle_link_rx_out_t o;
    static const uint8_t m1[] = { 1, 2, 3 }, m2[] = { 4 }, pd[] = { 9, 9 };
    make_sched(&s, 1000, 508);
    sle_link_init(l, SLE_LINK_ROLE_G, &s, 0x4C6E);
    sle_link_push(l, 0, m1, 3);
    sle_link_push(l, 0, m2, 1);

    CHECK(next(l, &tx) == 0 && tx.k == 0 && !tx.empty && tx.sn == 0 && tx.flow == 1 && !tx.retx);
    sle_link_rx_t r = reply(SLE_RX_NONE, 1, 0, 0, NULL, 0);
    sle_link_on_rx(l, &r, &o);                       /* lost reply */
    CHECK(!o.acked);
    CHECK(next(l, &tx) == 0 && tx.k == 1 && tx.sn == 0 && tx.len == 3 && tx.retx);
    r = reply(SLE_RX_HDRFAIL, 1, 0, 1, NULL, 0);     /* header CRC failed: ignored */
    sle_link_on_rx(l, &r, &o);
    CHECK(!o.acked && l->last_valid_ns == s.t0_ns);
    CHECK(next(l, &tx) == 0 && tx.sn == 0 && tx.retx);
    r = reply(SLE_RX_OK, 1, 1, 0, NULL, 0);          /* stale ack (NESN == our SN) */
    sle_link_on_rx(l, &r, &o);
    CHECK(!o.acked && l->last_valid_ns == tx.ev.t_ns);
    CHECK(next(l, &tx) == 0 && tx.sn == 0 && tx.retx);
    r = reply(SLE_RX_OK, 0, 0, 1, pd, 2);            /* ack + peer data */
    sle_link_on_rx(l, &r, &o);
    CHECK(o.acked && o.acked_sn == 0 && o.deliver && o.len == 2);
    CHECK(next(l, &tx) == 0 && tx.sn == 1 && tx.len == 1 && tx.nesn == 1 && tx.flow == 0 && !tx.retx);
    r = reply(SLE_RX_OK, 0, 0, 1, pd, 2);            /* peer lost our ack: repeats SN 0 */
    sle_link_on_rx(l, &r, &o);
    CHECK(o.dup && !o.deliver && !o.acked);
    CHECK(next(l, &tx) == 0 && tx.sn == 1 && tx.retx && tx.nesn == 1);
    r = reply(SLE_RX_BODYFAIL, 0, 1, 0, NULL, 5);    /* ack in header, body lost */
    sle_link_on_rx(l, &r, &o);
    CHECK(o.acked && o.badbody && !o.deliver);
    CHECK(next(l, &tx) == 0 && tx.empty && tx.sn == 0 && tx.nesn == 1 && tx.len == 0);
    CHECK(l->n_retx == 4 && l->n_dup == 1 && l->n_badbody == 1 && l->n_deliver == 1);
    free(l);
}

static void test_late_and_timeout(void)
{
    sle_conn_sched_t s;
    sle_link_t *l = calloc(1, sizeof *l);
    sle_link_tx_t tx;
    make_sched(&s, 1000, 5);                         /* 50 ms supervision */
    sle_link_init(l, SLE_LINK_ROLE_G, &s, 0);
    /* preamble of event 3 starts at t0 + 3*12.5 ms - 10 us */
    sle_time_ns_t pre3 = s.t0_ns + 3 * PERIOD_NS - SLE_PREAMBLE_NS;
    CHECK(sle_link_g_prepare(l, pre3 - 5000, 5000, &tx) == 0 && tx.k == 3);  /* lead counts */
    CHECK(sle_link_g_prepare(l, pre3, 0, &tx) == 0 && tx.k == 4);       /* never the same event */
    /* supervision: event 4 at exactly t0 + 50 ms was allowed, event 5 is not */
    CHECK(tx.ev.t_ns - s.t0_ns == 4 * PERIOD_NS);
    CHECK(next(l, &tx) == 1 && tx.down && l->down_reason == SLE_LINK_REASON_TIMEOUT);
    CHECK(next(l, &tx) == 1);
    sle_link_init(l, SLE_LINK_ROLE_G, &s, 0);
    CHECK(sle_link_g_prepare(l, pre3 + 1, 0, &tx) == 0 && tx.k == 4);   /* 1 ns late: skip 0..3 */
    free(l);
}

static void test_hopmap_instant(void)
{
    sle_conn_sched_t s;
    sle_link_t *l = calloc(1, sizeof *l);
    sle_link_tx_t tx;
    uint8_t few[10] = { 0 };
    few[1] = 0x0f;                                   /* RF 8..11 -> 4 channels */
    make_sched(&s, 1000, 508);
    sle_link_init(l, SLE_LINK_ROLE_G, &s, 0);
    CHECK(next(l, &tx) == 0 && tx.ev.slot == 1000);
    uint8_t one[10] = { 0 };
    one[1] = 0x01;
    CHECK(sle_link_hopmap_update(l, one, 1500) < 0);          /* < 2 channels */
    CHECK(sle_link_hopmap_update(l, few, 1000) < 0);          /* instant passed */
    CHECK(sle_link_hopmap_update(l, few, 1350) == 0);         /* between slots 1300/1400 */
    CHECK(sle_link_hopmap_update(l, few, 1600) < 0);          /* one pending */
    for (int k = 1; k <= 3; k++) { CHECK(next(l, &tx) == 0 && tx.n_apply == 0); }
    CHECK(next(l, &tx) == 0 && tx.k == 4 && tx.n_apply == 1 && tx.apply[0].what == 2 &&
          tx.apply[0].k == 4 && tx.ev.mhz >= 2410 && tx.ev.mhz <= 2413);
    for (int k = 0; k < 50; k++) { next(l, &tx); CHECK(tx.ev.mhz >= 2410 && tx.ev.mhz <= 2413); }
    /* instant exactly on an event slot, applied while events are skipped */
    uint32_t cur = tx.ev.slot;
    CHECK(sle_link_hopmap_update(l, MAP_ALL, (cur + 300) & SLE_SLOT_MASK) == 0);
    sle_time_ns_t late = tx.ev.t_ns + 5 * PERIOD_NS;
    CHECK(sle_link_g_prepare(l, late, 0, &tx) == 0 && tx.k == l->last_k && tx.n_apply == 1 &&
          tx.apply[0].k == tx.k - 3);
    free(l);
}

static void test_param_update(void)
{
    sle_conn_sched_t s;
    sle_link_t *l = calloc(1, sizeof *l);
    sle_link_tx_t tx;
    make_sched(&s, 1000, 508);
    sle_link_init(l, SLE_LINK_ROLE_G, &s, 0);
    next(l, &tx);                                              /* k=0, slot 1000 */
    sle_param_update_t p = { 1450, 6, 60, 150, 0, 0, 100, 4, 0 };
    CHECK(sle_link_param_update(l, &p) < 0);                   /* not an event slot */
    p.ref_slot = 1000;
    CHECK(sle_link_param_update(l, &p) < 0);                   /* ref already used */
    p.ref_slot = 1500; p.offset_slots = 0;
    CHECK(sle_link_param_update(l, &p) < 0);
    p.offset_slots = 6; p.sched_slot = 5;
    CHECK(sle_link_param_update(l, &p) < 0);
    p.sched_slot = 4;
    CHECK(sle_link_param_update(l, &p) == 0);                  /* k_ref = 5 */
    CHECK(sle_link_param_update(l, &p) < 0);                   /* pending */
    sle_time_ns_t t5 = s.t0_ns + 5 * PERIOD_NS;
    for (int k = 1; k <= 5; k++) next(l, &tx);
    CHECK(tx.k == 5 && tx.ev.slot == 1500 && tx.ev.t_ns == t5 && tx.n_apply == 0);
    CHECK(next(l, &tx) == 0 && tx.k == 6 && tx.n_apply == 1 && tx.apply[0].what == 1 &&
          tx.apply[0].k == 6 && tx.ev.slot == 1506 && tx.ev.t_ns == t5 + 6 * 125000);
    CHECK(next(l, &tx) == 0 && tx.ev.slot == 1566 && tx.ev.t_ns == t5 + 66 * 125000);
    CHECK(l->s.timeout_ms == 1000);
    /* slot length change: numbering restarts at 0 at the instant */
    uint32_t ref = (tx.ev.slot + 60) & SLE_SLOT_MASK;
    sle_param_update_t p2 = { ref, 3, 50, 150, 0, 0, 508, 3, 0 };
    CHECK(sle_link_param_update(l, &p2) == 0);
    next(l, &tx);
    sle_time_ns_t tref = tx.ev.t_ns;
    CHECK(next(l, &tx) == 0 && tx.n_apply == 1 && tx.ev.slot == 0 && tx.ev.white_seed == 0x40 &&
          tx.ev.t_ns == tref + 3 * 125000);
    CHECK(next(l, &tx) == 0 && tx.ev.slot == 50 && tx.ev.t_ns == tref + 3 * 125000 + 50 * 100000);
    free(l);
}

static void test_disconnect_and_wrap(void)
{
    sle_conn_sched_t s;
    sle_link_t *l = calloc(1, sizeof *l);
    sle_link_tx_t tx;
    sle_link_rx_out_t o;
    make_sched(&s, SLE_SLOT_MASK - 150, 508);                  /* wraps after event 1 */
    sle_link_init(l, SLE_LINK_ROLE_G, &s, 0);
    next(l, &tx);
    CHECK(tx.ev.slot == SLE_SLOT_MASK - 150);
    next(l, &tx);
    CHECK(tx.ev.slot == SLE_SLOT_MASK - 50);
    next(l, &tx);
    CHECK(tx.ev.slot == 49 && tx.ev.white_seed == (0x40 | 49));
    CHECK(sle_link_hopmap_update(l, MAP_ALL, SLE_SLOT_MASK - 10) < 0);  /* behind, across wrap */
    CHECK(sle_link_hopmap_update(l, MAP_ALL, 200) == 0);
    sle_link_disconnect(l, 0x13);
    next(l, &tx);                                              /* hop map PDU */
    sle_link_rx_t r = reply(SLE_RX_OK, 1, 0, 1, NULL, 0);
    sle_link_on_rx(l, &r, &o);
    CHECK(o.acked && !l->down);
    next(l, &tx);
    CHECK(tx.ptype == SLE_PTYPE_CTRL && tx.len == 7 && tx.data[0] == 0x1e && tx.sn == 1);
    r = reply(SLE_RX_OK, 1, 0, 0, NULL, 0);
    sle_link_on_rx(l, &r, &o);
    CHECK(o.acked && o.went_down && l->down && l->down_reason == 0x13);
    CHECK(next(l, &tx) == 1);

    /* peer-initiated disconnect */
    sle_link_init(l, SLE_LINK_ROLE_G, &s, 0);
    next(l, &tx);
    uint8_t d[8];
    sle_ctrl_disconnect_build(LID, 0x16, d, sizeof d);
    r = reply(SLE_RX_OK, 0, 0, 0, d, 7);
    r.ptype = SLE_PTYPE_CTRL;
    sle_link_on_rx(l, &r, &o);
    CHECK(o.deliver && o.went_down && l->down_reason == 0x16);
    free(l);
}

static void test_t_instant_passed(void)
{
    sle_conn_sched_t s;
    sle_link_t *t = calloc(1, sizeof *t);
    sle_link_tx_t tx;
    sle_link_rx_out_t o;
    uint8_t d[24];
    make_sched(&s, 1000, 508);
    sle_link_init(t, SLE_LINK_ROLE_T, &s, 0);
    for (int k = 0; k < 3; k++) sle_link_t_listen(t, 0, 0, &tx);   /* k=2, slot 1200 */
    CHECK(sle_link_t_reply(t, &tx) == 1);                          /* nothing received yet */
    size_t n = sle_ctrl_hopmap_build(MAP_ALL, 1300, d, sizeof d);  /* next event: still valid */
    sle_link_rx_t r = reply(SLE_RX_OK, 0, 0, 0, d, (int)n);
    r.ptype = SLE_PTYPE_CTRL;
    sle_link_on_rx(t, &r, &o);
    CHECK(o.deliver && !t->down && t->pend_map.active);
    CHECK(sle_link_t_reply(t, &tx) == 0 && tx.empty && tx.nesn == 1);
    sle_link_t_listen(t, 0, 0, &tx);                               /* k=3, applies */
    CHECK(tx.n_apply == 1 && tx.apply[0].k == 3);
    n = sle_ctrl_hopmap_build(MAP_ALL, 1300, d, sizeof d);         /* now in the past */
    r = reply(SLE_RX_OK, 0, 1, 0, d, (int)n);
    r.ptype = SLE_PTYPE_CTRL;
    sle_link_on_rx(t, &r, &o);
    CHECK(t->down && t->down_reason == SLE_LINK_REASON_INSTANT_PASSED);
    free(t);
}

/* ---- 3. attempt-8 recording ---------------------------------------------- */

/* ---- 4. closed loop ------------------------------------------------------ */

static uint32_t rng = 12345;
static uint32_t rnd(void) { rng = rng * 1664525u + 1013904223u; return rng >> 8; }

#define NMSG 200
static uint8_t g_msgs[NMSG][300], t_msgs[NMSG][300];
static uint16_t g_len[NMSG], t_len[NMSG];

static int channel(const uint8_t *in, size_t n, uint8_t *out, int loss_pct, int err_pct)
{
    if ((int)(rnd() % 100) < loss_pct) return 0;
    memcpy(out, in, n);
    if ((int)(rnd() % 100) < err_pct) {
        int flips = 1 + (int)(rnd() % 3);
        for (int i = 0; i < flips; i++) out[32 + rnd() % (n - 32)] ^= 1u;   /* after the sync */
    }
    return 1;
}

static void run_loop(int loss_pct, int err_pct, int late_pct)
{
    sle_conn_sched_t s;
    sle_link_t *g = calloc(1, sizeof *g), *t = calloc(1, sizeof *t);
    static uint8_t bits[SLE_MAX_FRAME_BITS], air[SLE_MAX_FRAME_BITS];
    static sle_frame_t fr;
    int g_got = 0, t_got = 0, same_ev = 0, map_k = -1, map_kt = -1, par_k = -1, par_kt = -1;
    int bad_order = 0;
    make_sched(&s, 0x1234567, 508);
    sle_link_init(g, SLE_LINK_ROLE_G, &s, 0xE4004C6E);
    sle_link_init(t, SLE_LINK_ROLE_T, &s, 0xE4004C6E);
    for (int i = 0; i < NMSG; i++) {
        g_len[i] = (uint16_t)(1 + rnd() % 300);
        t_len[i] = (uint16_t)(1 + rnd() % 300);
        for (int j = 0; j < g_len[i]; j++) { g_msgs[i][j] = (uint8_t)rnd(); t_msgs[i][j] = (uint8_t)rnd(); }
        sle_link_push(g, SLE_PTYPE_DATA, g_msgs[i], g_len[i]);
        sle_link_push(t, SLE_PTYPE_DATA, t_msgs[i], t_len[i]);
    }
    uint8_t few[10] = { 0 };
    few[2] = 0xf0; few[3] = 0xff; few[4] = 0x0f;               /* RF 20..35: remap branch */
    sle_time_ns_t now = 0;
    int ev_count = 0;
    while (ev_count < 3000 && !(g->down && t->down)) {
        sle_link_tx_t gt, tt;
        if (ev_count == 100) {
            sle_conn_sched_t *cs = &g->s;
            uint32_t next_slot = (cs->base_slot + (uint32_t)((g->last_k + 1 - g->k_first) * cs->period_slots)) & SLE_SLOT_MASK;
            CHECK(sle_link_hopmap_update(g, few, (next_slot + 30 * cs->period_slots) & SLE_SLOT_MASK) == 0);
        }
        if (ev_count == 400) {
            sle_conn_event_t e;
            sle_link_event(g, g->last_k + 60, &e);
            sle_param_update_t p = { e.slot, 8, 80, 150, 0, 0, 508, 4, 0 };
            CHECK(sle_link_param_update(g, &p) == 0);
        }
        if (ev_count == 2500) sle_link_disconnect(g, 0x13);
        int late = (int)(rnd() % 100) < late_pct;
        if (sle_link_g_prepare(g, now + (late ? 3 * PERIOD_NS : 0), 0, &gt)) {
            /* G down: let T run out its supervision */
            if (sle_link_t_listen(t, now, 0, &tt)) break;
            sle_link_rx_t none = { SLE_RX_NONE, 0, 0, 0, 0, 0, NULL, 0 };
            sle_link_rx_out_t o;
            sle_link_on_rx(t, &none, &o);
            now = tt.ev.t_ns + 1;
            continue;
        }
        for (int i = 0; i < gt.n_apply; i++) {
            if (gt.apply[i].what == 2) map_k = (int)gt.apply[i].k;
            else par_k = (int)gt.apply[i].k;
        }
        size_t nb = sle_link_encode(g, &gt, bits, sizeof bits);
        CHECK(nb > 0);
        /* T listens to every event up to G's; skipped ones carry nothing */
        for (;;) {
            if (sle_link_t_listen(t, 0, 0, &tt)) break;
            for (int i = 0; i < tt.n_apply; i++) {
                if (tt.apply[i].what == 2) map_kt = (int)tt.apply[i].k;
                else par_kt = (int)tt.apply[i].k;
            }
            if (tt.k == gt.k) break;
            sle_link_rx_t none = { SLE_RX_NONE, 0, 0, 0, 0, 0, NULL, 0 };
            sle_link_rx_out_t o;
            sle_link_on_rx(t, &none, &o);
        }
        if (t->down) break;
        CHECK(tt.k == gt.k && tt.ev.slot == gt.ev.slot && tt.ev.phys == gt.ev.phys &&
              tt.ev.t_ns == gt.ev.t_ns);
        same_ev++;
        sle_link_rx_t rx;
        sle_link_rx_out_t o;
        if (channel(bits, nb, air, loss_pct, err_pct)) sle_link_decode(t, &tt.ev, air, nb, &fr, &rx);
        else memset(&rx, 0, sizeof rx);
        sle_link_on_rx(t, &rx, &o);
        if (o.deliver && o.ptype == SLE_PTYPE_DATA) {
            if (t_got >= NMSG || o.len != g_len[t_got] || memcmp(o.data, g_msgs[t_got], o.len)) bad_order++;
            t_got++;
        }
        sle_link_tx_t rt;
        memset(&rx, 0, sizeof rx);
        if (sle_link_t_reply(t, &rt) == 0) {
            CHECK(rt.ev.phys == gt.ev.phys);
            nb = sle_link_encode(t, &rt, bits, sizeof bits);
            CHECK(nb > 0);
            if (channel(bits, nb, air, loss_pct, err_pct)) sle_link_decode(g, &gt.ev, air, nb, &fr, &rx);
        }
        sle_link_on_rx(g, &rx, &o);
        if (o.deliver && o.ptype == SLE_PTYPE_DATA) {
            if (g_got >= NMSG || o.len != t_len[g_got] || memcmp(o.data, t_msgs[g_got], o.len)) bad_order++;
            g_got++;
        }
        now = gt.ev.t_ns + 1;
        ev_count++;
    }
    /* T stopped after acknowledging the disconnect; if that reply was lost G
     * retransmits into silence until its supervision timeout. */
    int g_tail = 0;
    sle_link_tx_t gt;
    sle_link_rx_t none = { SLE_RX_NONE, 0, 0, 0, 0, 0, NULL, 0 };
    sle_link_rx_out_t o;
    while (sle_link_g_prepare(g, now, 0, &gt) == 0) { sle_link_on_rx(g, &none, &o); now = gt.ev.t_ns + 1; g_tail++; }
    printf("loop loss=%d%% err=%d%% late=%d%%: G tail %d, events %d, G->T %d/%d, T->G %d/%d, G retx %u, T retx %u, "
           "dup G %u T %u, badbody G %u T %u, map k %d/%d, param k %d/%d, down G %d(%u) T %d(%u)\n",
           loss_pct, err_pct, late_pct, g_tail, same_ev, t_got, NMSG, g_got, NMSG, g->n_retx, t->n_retx,
           g->n_dup, t->n_dup, g->n_badbody, t->n_badbody, map_k, map_kt, par_k, par_kt,
           g->down, g->down_reason, t->down, t->down_reason);
    CHECK(bad_order == 0 && t_got == NMSG && g_got == NMSG);
    CHECK(map_k > 0 && map_k == map_kt && par_k > 0 && par_k == par_kt);
    CHECK(t->down && t->down_reason == 0x13 && g->down &&
          (g->down_reason == 0x13 || (g->down_reason == SLE_LINK_REASON_TIMEOUT && g_tail > 400)));
    free(g);
    free(t);
}

static void test_loss_timeout(void)
{
    sle_conn_sched_t s;
    sle_link_t *g = calloc(1, sizeof *g);
    sle_link_tx_t tx;
    sle_link_rx_out_t o;
    make_sched(&s, 1000, 508);
    sle_link_init(g, SLE_LINK_ROLE_G, &s, 0);
    int k = 0;
    sle_link_rx_t none = { SLE_RX_NONE, 0, 0, 0, 0, 0, NULL, 0 };
    while (next(g, &tx) == 0) { sle_link_on_rx(g, &none, &o); k++; }
    /* 5.08 s / 12.5 ms = 406.4: events 0..406 are sent, 407 is past the timeout */
    CHECK(k == 407 && g->down_reason == SLE_LINK_REASON_TIMEOUT);
    free(g);
}

int main(void)
{
    test_arq_core();
    test_ctrl_codecs();
    test_loss_dup_stale();
    test_late_and_timeout();
    test_hopmap_instant();
    test_param_update();
    test_disconnect_and_wrap();
    test_t_instant_passed();
    test_loss_timeout();
    run_loop(0, 0, 0);
    run_loop(10, 10, 5);
    run_loop(30, 20, 10);
    printf("test_sle_link: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
