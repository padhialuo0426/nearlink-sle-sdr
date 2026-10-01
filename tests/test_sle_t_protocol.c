/* Host-only G/T protocol dialogue. Deterministic fixture RNG is NOT radio RNG.
 */
#define _GNU_SOURCE
#include "sle_t_pair.h"
#include "sle_t_runtime.h"
#include "sle_ssap_server.h"
#include "sle_cmtc.h"
#include "sle_ssap.h"
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned checks;
static int official_capabilities;
static unsigned test_variant = SLE_PAIR_PROFILE_WS63;
#define CHECK(x)                                                               \
  do {                                                                         \
    checks++;                                                                  \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static int random_bytes(void *ctx, unsigned char *out, size_t n) {
  uint64_t *s = ctx;
  for (size_t i = 0; i < n; i++) {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    out[i] = (uint8_t)*s;
  }
  return 0;
}
static int bad_rng(void *ctx, unsigned char *out, size_t n) {
  (void)ctx;
  memset(out, 0, n);
  return -1;
}
static const uint8_t ga[6] = {0xc2, 0x53, 0x4c, 0x45, 0, 0x10},
                     ta[6] = {1, 2, 3, 4, 5, 6};
typedef struct {
  sle_pair_t g;
  sle_t_pair t;
  uint64_t grng, trng, gplain_tx, gplain_rx, now;
  uint8_t gsn, tsn;
} dialogue;
static void init(dialogue *d) {
  memset(d, 0, sizeof *d);
  d->grng = 12345678;
  d->trng = 987654321;
  d->now = 1;
  sle_pair_config_t c = {.sync_low32 = 0x1c4eac4a,
                         .rng = random_bytes,
                         .variant = test_variant};
  memcpy(c.g_addr, ga, 6);
  memcpy(c.t_addr, ta, 6);
  c.rng_ctx = &d->grng;
  CHECK(!sle_pair_init(&d->g, &c));
  CHECK(!sle_pair_prepare(&d->g));
  c.rng_ctx = &d->trng;
  CHECK(!sle_t_pair_init(&d->t, &c));
  CHECK(!sle_t_pair_prepare(&d->t));
  CHECK(!sle_pair_start(&d->g, d->now));
}
static void work(dialogue *d) {
  sle_pair_work_t w;
  sle_pair_work_result_t r;
  if (d->g.state == SLE_PAIR_WAIT_ECDH && !d->g.work_taken) {
    CHECK(!sle_pair_take_work(&d->g, &w));
    CHECK(!sle_pair_run_work(&w, &r));
    CHECK(!sle_pair_finish_work(&d->g, &r, ++d->now));
  }
  if (d->t.state == SLE_T_PAIR_WAIT_WORK && !d->t.work_taken) {
    CHECK(!sle_t_pair_take_work(&d->t, &w));
    CHECK(!sle_pair_run_work(&w, &r));
    CHECK(!sle_t_pair_finish_work(&d->t, &r, ++d->now));
  }
}
static void g_to_t(dialogue *d, sle_pair_pdu_t *pdu) {
  uint8_t wire[128], retry[128], plain[128];
  size_t n = pdu->len, rn, pn;
  int pair;
  if (official_capabilities && pdu->len==13 && pdu->data[0]==0x34 && pdu->data[1]==1) {
    static const uint8_t captured[]={0x34,1,10,3,0,5,16,0,3,3,3,2,0};
    memcpy(pdu->data,captured,sizeof captured);
  }
  if (d->g.secure) {
    CHECK(!sle_pair_protect(&d->g, pdu->data, pdu->len, d->gsn, 0, wire,
                            sizeof wire, &n));
    uint64_t count = d->g.cipher.tx_next;
    CHECK(!sle_pair_protect(&d->g, pdu->data, pdu->len, d->gsn, 1, retry,
                            sizeof retry, &rn));
    CHECK(n == rn && !memcmp(wire, retry, n) && count == d->g.cipher.tx_next);
  } else {
    memcpy(wire, pdu->data, n);
    d->gplain_tx++;
  }
  CHECK(!sle_t_pair_rx(&d->t, ga, 3, wire, n, d->gsn, 0, ++d->now, plain,
                      sizeof plain, &pn, &pair));
  CHECK(pair && pn == pdu->len && !memcmp(plain, pdu->data, pn));
  uint64_t count = d->t.rx_next;
  CHECK(sle_t_pair_rx(&d->t, ga, 3, wire, n, d->gsn, 1, ++d->now, plain,
                     sizeof plain, &pn, &pair) == SLE_PAIR_DUPLICATE);
  CHECK(pn == 0 && pair && count == d->t.rx_next);
  d->gsn ^= 1;
}
static void t_to_g(dialogue *d, sle_pair_pdu_t *pdu) {
  uint8_t wire[128], retry[128], plain[128];
  size_t n, rn, pn;
  int pair;
  uint64_t before = d->t.tx_next;
  CHECK(!sle_t_pair_tx(&d->t, 3, pdu->data, pdu->len, d->tsn, 0, wire,
                      sizeof wire, &n));
  uint64_t prepared = d->t.tx_next;
  CHECK(prepared == before + (pdu->encrypted ? 1u : 0u));
  CHECK(!sle_t_pair_tx(&d->t, 3, pdu->data, pdu->len, d->tsn, 1, retry,
                      sizeof retry, &rn));
  CHECK(n == rn && !memcmp(wire, retry, n) && prepared == d->t.tx_next);
  CHECK(!sle_t_pair_submitted(&d->t, d->tsn));
  CHECK(d->t.tx_next == before + 1);
  CHECK(!sle_t_pair_submitted(&d->t, d->tsn));
  CHECK(d->t.tx_next == before + 1);
  if (pdu->len==3 && pdu->data[0]==6) {
    /* Predictive T: witness/submitted precedes processing this event's old
     * plaintext G0004 retry. It must use cached plaintext classification. */
    uint64_t count=d->t.rx_next;
    CHECK(d->t.rx_secure && d->t.rx_wire[0]==4);
    CHECK(sle_t_pair_rx(&d->t,ga,3,d->t.rx_wire,d->t.rx_len,d->t.rx_sn,1,
                        ++d->now,plain,sizeof plain,&pn,&pair)==SLE_PAIR_DUPLICATE);
    CHECK(pair && !pn && d->t.rx_next==count && !d->t.rx_cached_secure);
    sle_t_pair copy=d->t;
    CHECK(sle_t_pair_rx(&copy,ga,3,d->t.rx_wire,d->t.rx_len,d->t.rx_sn^1,0,
                        ++d->now,plain,sizeof plain,&pn,&pair)==SLE_PAIR_ERR_MIC);
    sle_t_pair_clear(&copy);
  }
  int secure = d->g.secure;
  CHECK(!sle_pair_on_control_ex(&d->g, ta, wire, n, d->tsn, 0, ++d->now, plain,
                                sizeof plain, &pn, &pair));
  CHECK(pair && pn == pdu->len && !memcmp(plain, pdu->data, pn));
  if (!secure) {
    d->gplain_rx++;
    if (d->g.secure)
      CHECK(!sle_pair_seed_plain_counters(&d->g, d->gplain_tx, d->gplain_rx));
  }
  uint64_t count = d->g.cipher.rx_next;
  CHECK(sle_pair_on_control_ex(&d->g, ta, wire, n, d->tsn, 1, ++d->now, plain,
                               sizeof plain, &pn, &pair) == SLE_PAIR_DUPLICATE);
  CHECK(pn == 0 && count == d->g.cipher.rx_next);
  d->tsn ^= 1;
}
static void pair_loop(dialogue *d, uint64_t plain_tx, uint64_t plain_rx);
static void handshake(dialogue *d) {
  init(d);
  pair_loop(d, 5, 7);
}
static void pair_loop(dialogue *d, uint64_t plain_tx, uint64_t plain_rx) {
  for (int i = 0; i < 40; i++) {
    work(d);
    sle_pair_pdu_t pdu;
    int any = 0;
    while (sle_pair_pop(&d->g, &pdu) == 1) {
      g_to_t(d, &pdu);
      any = 1;
    }
    work(d);
    while (sle_t_pair_pop(&d->t, &pdu) == 1) {
      t_to_g(d, &pdu);
      any = 1;
    }
    if (d->g.state == SLE_PAIR_ENCRYPTED && d->t.state == SLE_T_PAIR_ENCRYPTED)
      break;
    CHECK(any || d->g.state == SLE_PAIR_WAIT_ECDH ||
          d->t.state == SLE_T_PAIR_WAIT_WORK);
  }
  CHECK(d->g.state == SLE_PAIR_ENCRYPTED && d->t.state == SLE_T_PAIR_ENCRYPTED);
  CHECK(d->g.confirm_matches == 1);
  CHECK(!memcmp(d->g.cipher.key, d->t.key, 16) &&
        !memcmp(d->g.cipher.iv, d->t.iv, 8));
  CHECK(d->g.cipher.tx_next == d->t.rx_next &&
        d->g.cipher.rx_next == d->t.tx_next);
  CHECK(d->gplain_tx == plain_tx && d->gplain_rx == plain_rx);
}
static size_t protected_g_data(dialogue *d, const uint8_t *data, size_t len,
                               uint8_t *plain) {
  uint8_t wire[1100];
  size_t n, pn;
  int pair;
  CHECK(!sle_pair_protect(&d->g, data, len, d->gsn, 0, wire, sizeof wire, &n));
  CHECK(!sle_t_pair_rx(&d->t, ga, 0, wire, n, d->gsn, 0, ++d->now, plain, 1100,
                      &pn, &pair));
  CHECK(!pair && pn == len && !memcmp(data, plain, len));
  CHECK(sle_t_pair_rx(&d->t, ga, 0, wire, n, d->gsn, 1, ++d->now, plain, 1100,
                     &n, &pair) == SLE_PAIR_DUPLICATE &&
        n == 0);
  d->gsn ^= 1;
  return pn;
}
static size_t protected_t_data(dialogue *d, const uint8_t *data, size_t len,
                               uint8_t *plain) {
  uint8_t wire[1100];
  size_t n, pn;
  CHECK(!sle_t_pair_tx(&d->t, 0, data, len, d->tsn, 0, wire, sizeof wire, &n));
  CHECK(!sle_t_pair_submitted(&d->t, d->tsn));
  CHECK(!sle_pair_unprotect(&d->g, wire, n, d->tsn, 0, plain, 1100, &pn));
  CHECK(pn == len && !memcmp(data, plain, len));
  CHECK(sle_pair_unprotect(&d->g, wire, n, d->tsn, 1, plain, 1100, &n) ==
            SLE_PAIR_DUPLICATE &&
        n == 0);
  d->tsn ^= 1;
  return pn;
}
static size_t dtap(uint8_t *d, const uint8_t *p, size_t n) {
  d[0] = 10;
  d[1] = 0;
  d[2] = (uint8_t)n;
  d[3] = (uint8_t)(n >> 8);
  memcpy(d + 4, p, n);
  return n + 4;
}
static void business(dialogue *d) {
  sle_ssap_server s;
  CHECK(!sle_ssap_server_init(&s, 520));
  uint8_t msg[1100], req[1100], rx[1100], reply[1100], decoded[1100];
  size_t n, m, rn;
  sle_ssap_exchange_info_t x = {
      .mtu_present = 1, .version_present = 1, .mtu = 520, .version = 1};
  n = sle_ssap_exchange_info_build(2, &x, msg, sizeof msg);
  CHECK(n > 0);
  m = dtap(req, msg, n);
  CHECK(sle_ssap_server_rx(&s, 0, req, m, reply, sizeof reply, &rn) ==
            SLE_SSAP_SERVER_STATE &&
        !s.negotiated);
  CHECK(protected_g_data(d, req, m, rx) == m);
  CHECK(!sle_ssap_server_rx(&s, 1, rx, m, reply, sizeof reply, &rn));
  CHECK(protected_t_data(d, reply, rn, decoded) == rn);
  CHECK(!sle_ssap_exchange_info_parse(decoded + 4, rn - 4, &x) &&
        x.mtu == 520 && s.mtu == 520);
  sle_ssap_find_structure_req_t f = {.find_type = SLE_SSAP_FIND_TYPE_PROPERTY,
                                     .start_handle = 1,
                                     .end_handle = 65535};
  n = sle_ssap_find_structure_req_build(4, &f, msg, sizeof msg);
  CHECK(n > 0);
  m = dtap(req, msg, n);
  CHECK(protected_g_data(d, req, m, rx) == m);
  CHECK(!sle_ssap_server_rx(&s, 1, rx, m, reply, sizeof reply, &rn));
  CHECK(protected_t_data(d, reply, rn, decoded) == rn && rn == 16 &&
        decoded[4] == 5 && decoded[6] == 2);
  /* 1.10.108 client asks itemType MIX (captured 04 13 01 00 ff ff). */
  {
    static const uint8_t mix_req[] = {0x0a, 0, 6, 0, 4, 0x13, 1, 0, 0xff, 0xff};
    static const uint8_t mix_rsp[] = {0x0a, 0, 14, 0, 5, 0x0b, 0x01, 2, 0, 0x23,
                                      0x23, 9, 0, 0, 0, 1, 1, 0x80};
    uint8_t r2[64];
    size_t n2;
    CHECK(!sle_ssap_server_rx(&s, 1, mix_req, sizeof mix_req, r2, sizeof r2, &n2));
    CHECK(n2 == sizeof mix_rsp && !memcmp(r2, mix_rsp, n2));
    uint8_t bad[sizeof mix_req];
    memcpy(bad, mix_req, sizeof bad);
    bad[5] = 0x0b; /* itemType CUSTOM stays unsupported */
    CHECK(sle_ssap_server_rx(&s, 1, bad, sizeof bad, r2, sizeof r2, &n2) ==
          SLE_SSAP_SERVER_UNSUPPORTED);
  }
  uint8_t value[81];
  for (size_t i = 0; i < sizeof value; i++)
    value[i] = (uint8_t)i;
  sle_ssap_write_t w = {.fragment = 3,
                        .verify = 1,
                        .item = {.handle = 2, .value = value, .value_len = 48}};
  n = sle_ssap_write_build(13, &w, msg, sizeof msg);
  CHECK(n > 0);
  m = dtap(req, msg, n);
  CHECK(protected_g_data(d, req, m, rx) == m);
  CHECK(sle_ssap_server_rx(&s, 1, rx, m, reply, 1, &rn) == SLE_SSAP_SERVER_BUFFER &&
        !s.writes);
  CHECK(!sle_ssap_server_rx(&s, 1, rx, m, reply, sizeof reply, &rn));
  CHECK(s.writes == 1 && s.value_len == 48 && !memcmp(s.value, value, 48));
  CHECK(protected_t_data(d, reply, rn, decoded) == rn && rn == 57 &&
        !memcmp(decoded + 9, value, 48));
  CHECK(!sle_ssap_server_notify(&s, 1, value, 81, reply, sizeof reply, &rn));
  CHECK(protected_t_data(d, reply, rn, decoded) == 91 && decoded[4] == 15 &&
        !memcmp(decoded + 10, value, 81));
  CHECK(sle_ssap_server_notify(&s, 1, value, 81, reply, 1, &rn) ==
            SLE_SSAP_SERVER_BUFFER &&
        s.notifications == 1);
  w.item.handle = 3;
  n = sle_ssap_write_build(13, &w, msg, sizeof msg);
  m = dtap(req, msg, n);
  CHECK(sle_ssap_server_rx(&s, 1, req, m, reply, sizeof reply, &rn) ==
            SLE_SSAP_SERVER_UNSUPPORTED &&
        s.writes == 1);
  sle_ssap_server_clear(&s);
  CHECK(!s.mtu && !s.writes);
}
static void negative(dialogue *d) {
  sle_t_pair t = d->t;
  uint8_t wire[128], out[128];
  size_t n, pn;
  int pair;
  const uint8_t data[] = {1, 2, 3};
  CHECK(!sle_pair_protect(&d->g, data, 3, d->gsn, 0, wire, sizeof wire, &n));
  uint64_t count = t.rx_next;
  memset(out, 0xa5, sizeof out);
  wire[n - 1] ^= 1;
  CHECK(sle_t_pair_rx(&t, ga, 0, wire, n, d->gsn, 0, ++d->now, out, sizeof out,
                     &pn, &pair) == SLE_PAIR_ERR_MIC);
  CHECK(t.state == SLE_T_PAIR_FAILED && t.rx_next == count && !pn && out[0] == 0xa5);
  CHECK(t.mic_probe == -1); /* corrupted tag: no counter verifies */
  /* Valid frame sent at a counter the receiver does not expect: the probe
   * reports the counter that verifies, and the frame is still rejected. */
  {
    sle_t_pair tt = d->t;
    uint8_t w2[128], nc[13], aad = 0;
    uint64_t c = tt.rx_next + 3;
    for (int i = 0; i < 5; i++)
      nc[i] = (uint8_t)(c >> (8 * i));
    nc[4] |= 0x80; /* G->T direction, as sle_t_pair nonce(tx=0) */
    memcpy(nc + 5, tt.iv, 8);
    CHECK(!sle_aes_ccm_encrypt(tt.key, nc, 13, &aad, 1, data, 3, w2, w2 + 3,
                               4));
    CHECK(sle_t_pair_rx(&tt, ga, 0, w2, 7, d->gsn, 0, ++d->now, out,
                       sizeof out, &pn, &pair) == SLE_PAIR_ERR_MIC);
    CHECK(tt.mic_probe == (int)c && tt.state == SLE_T_PAIR_FAILED);
  }
  wire[n - 1] ^= 1;
  t = d->t;
  CHECK(sle_t_pair_rx(&t, ga, 0, wire, n, d->gsn, 1, ++d->now, out, sizeof out,
                     &pn, &pair) == SLE_PAIR_ERR_SEQUENCE);
  t = d->t;
  CHECK(sle_t_pair_rx(&t, ga, 0, wire, n, d->gsn, 0, ++d->now, out, 1, &pn,
                     &pair) == SLE_PAIR_ERR_BUFFER);
  CHECK(t.rx_next == count && t.state == SLE_T_PAIR_ENCRYPTED);
  CHECK(!sle_t_pair_rx(&t, ga, 0, wire, n, d->gsn, 0, ++d->now, out, sizeof out,
                      &pn, &pair));
  /* Replay previously valid ciphertext under the next ARQ position fails MIC.
   */
  CHECK(sle_t_pair_rx(&t, ga, 0, wire, n, d->gsn ^ 1, 0, ++d->now, out,
                     sizeof out, &pn, &pair) == SLE_PAIR_ERR_MIC);
  t = d->t;
  t.tx_next = SLE_PAIR_COUNTER_LIMIT;
  CHECK(sle_t_pair_tx(&t, 0, data, 3, d->tsn, 0, wire, sizeof wire, &n) ==
        SLE_PAIR_ERR_COUNTER);
  t = d->t;
  CHECK(sle_t_pair_rx(&t, ta, 0, wire, 7, d->gsn, 0, ++d->now, out, sizeof out,
                     &pn, &pair) == SLE_PAIR_ERR_IDENTITY);
  sle_t_pair_clear(&t);
}
static void setup_errors(void) {
  sle_t_pair t={0};
  CHECK(sle_t_pair_prepare(&t)==SLE_PAIR_ERR_STATE);
  sle_pair_config_t c = {.rng = bad_rng, .variant = SLE_PAIR_PROFILE_WS63};
  memcpy(c.g_addr, ga, 6);
  memcpy(c.t_addr, ta, 6);
  CHECK(!sle_t_pair_init(&t, &c));
  CHECK(sle_t_pair_prepare(&t) == SLE_PAIR_ERR_RNG);
  c.variant = 0;
  CHECK(sle_t_pair_init(&t, &c) == SLE_PAIR_ERR_ARGUMENT);
  dialogue d;
  init(&d);
  sle_pair_pdu_t pdu;
  CHECK(sle_pair_pop(&d.g, &pdu) == 1);
  g_to_t(&d, &pdu);
  CHECK(sle_t_pair_tick(&d.t, d.now + 5000) == SLE_PAIR_ERR_TIMEOUT);
  sle_pair_clear(&d.g);
  sle_t_pair_clear(&d.t);
}
static void runtime_checks(dialogue *original) {
  dialogue copy=*original;
  dialogue *d=&copy;
  sle_t_runtime r;
  int cpu = sched_getcpu();
  CHECK(cpu >= 0);
  CHECK(!sle_t_runtime_init(&r, ta, cpu));
  CHECK(!sle_t_runtime_bind(&r, ga, 0x1c4eac4a));
  CHECK(sle_t_runtime_bind(&r, ga, 0x1c4eac4a) == SLE_PAIR_ERR_STATE);
  CHECK(!sle_t_runtime_poll(&r, 1));
  /* Generic feature control must stay outside pair dispatch. */
  uint8_t ctrl[] = {0x0a, 0, 0};
  sle_link_t l = {0};
  l.have_event = 1;
  sle_link_rx_t rx = {.kind = SLE_RX_OK, .ptype = 3, .data = ctrl, .len = 3};
  sle_link_rx_out_t out;
  sle_rt_rx scratch;
  CHECK(!sle_t_runtime_rx(&r, &l, &rx, &out, &scratch, 2));
  CHECK(!scratch.pair_control && scratch.opcode == 10 && r.pair.rx_next == 1);
  CHECK(!sle_t_runtime_destroy(&r));
  CHECK(r.rng_fd == -1 && !r.initialized);
  CHECK(!sle_t_runtime_destroy(&r));
  /* Exercise the real mailbox with independent valid G public material. */
  CHECK(!sle_t_runtime_init(&r, ta, cpu));
  CHECK(!sle_t_runtime_bind(&r, ga, 0x1c4eac4a));
  r.pair.state = SLE_T_PAIR_WAIT_WORK;
  /* Existing G erases public material late; use T's retained valid public. */
  memcpy(r.pair.g_public, d->t.public_le, 64);
  CHECK(!sle_t_runtime_poll(&r, 1));
  for (int i = 0; i < 1000 && r.pair.state == SLE_T_PAIR_WAIT_WORK; i++) {
    usleep(1000);
    if (sle_t_runtime_poll(&r, 2)) { fprintf(stderr,"worker poll failed\n"); exit(1); }
  }
  CHECK(r.pair.state == SLE_T_PAIR_WAIT_RA && r.pair.count == 1);
  CHECK(!sle_t_runtime_destroy(&r));
  /* A bad MIC carrying an ACK must leave ARQ and supervision unchanged. */
  memset(&r, 0, sizeof r);
  r.rng_fd = -1;
  r.bound = 1;
  r.pair = d->t;
  atomic_init(&r.worker.job, 0);
  atomic_init(&r.worker.stop, 0);
  memcpy(r.peer, ga, 6);
  uint8_t wire[128];
  size_t wn;
  uint8_t msg[] = {1, 2, 3};
  CHECK(!sle_pair_protect(&d->g, msg, 3, d->gsn, 0, wire, sizeof wire, &wn));
  wire[wn - 1] ^= 1;
  memset(&l, 0, sizeof l);
  l.have_event = 1;
  l.arq.rx_nesn = d->gsn;
  l.arq.has_cur = 1;
  l.last_valid_ns = 1234;
  rx = (sle_link_rx_t){.kind = SLE_RX_OK,
                       .ptype = 0,
                       .data = wire,
                       .len = (uint16_t)wn,
                       .sn = d->gsn,
                       .nesn = 1};
  sle_link_t before = l;
  CHECK(sle_t_runtime_rx(&r, &l, &rx, &out, &scratch, ++d->now) ==
        SLE_PAIR_ERR_MIC);
  CHECK(!memcmp(&l, &before, sizeof l) && !out.acked && !out.deliver);
  CHECK(r.mic_failed == 1 && scratch.mic == -1);
  CHECK(!sle_t_runtime_destroy(&r));
}
/* WS63 SDK 1.10.108 CMTC capability exchange. Request is the frame captured
 * in logs/e310/sdk-upgrade-t-standard-a-20260928/p7.jsonl; the response
 * layout follows gle_tm_signal_capability_rsp/_cfm in libbth_gle.a. */
static const uint8_t cmtc_req[] = {0x60, 0, 2, 0, 8, 0, 1, 0,
                                   4,    0, 0xa0, 0, 0, 0};
static void cmtc_unit(void) {
  uint8_t req[14], rsp[18];
  size_t n = 99;
  memcpy(req, cmtc_req, sizeof req);
  CHECK(sle_cmtc_capability_req_pdu(req, sizeof req));
  CHECK(!sle_cmtc_capability_rsp_pdu(req, sizeof req));
  for (unsigned id = 0; id < 256; id += 0x37) {
    req[7] = (uint8_t)id;
    CHECK(sle_cmtc_capability_req_pdu(req, sizeof req));
    CHECK(!sle_cmtc_capability_reply(req + 2, 12, rsp + 2, 16, &n) && n == 16);
    const uint8_t want[] = {2, 0, 12, 0, 2, (uint8_t)id, 8, 0,
                            0xa0, 0, 0, 0, 90, 0, 1, 1};
    CHECK(!memcmp(rsp + 2, want, 16));
    rsp[0] = 0x80;
    rsp[1] = 0;
    CHECK(sle_cmtc_capability_rsp_pdu(rsp, 18));
    CHECK(!sle_cmtc_capability_req_pdu(rsp, 18));
  }
  /* Every single-byte change outside the identifier is rejected. */
  req[7] = 0;
  for (size_t i = 0; i < sizeof req; i++) {
    if (i == 7)
      continue;
    req[i] ^= 1;
    CHECK(!sle_cmtc_capability_req_pdu(req, sizeof req));
    if (i >= 2) {
      n = 99;
      CHECK(sle_cmtc_capability_reply(req + 2, 12, rsp + 2, 16, &n) == -1 &&
            n == 0);
    }
    req[i] ^= 1;
  }
  for (size_t i = 0; i < sizeof rsp; i++) {
    rsp[i] ^= 1;
    /* identifier and the MPS/version values are free; structure is not */
    int free_byte = i == 7 || i >= 14;
    CHECK(sle_cmtc_capability_rsp_pdu(rsp, sizeof rsp) == free_byte);
    rsp[i] ^= 1;
  }
  /* WS63's own response (MPS 672, version 0x0101) parses. */
  {
    const uint8_t ws63[] = {2, 0, 12, 0, 2, 5, 8, 0, 0xa0, 0, 0, 0,
                            0xa0, 2, 1, 1};
    uint8_t id = 0;
    uint16_t mps = 0, ver = 0;
    CHECK(!sle_cmtc_capability_parse_rsp(ws63, 16, &id, &mps, &ver) &&
          id == 5 && mps == 672 && ver == 0x0101);
    CHECK(sle_cmtc_capability_parse_rsp(ws63, 15, &id, &mps, &ver) == -1);
    CHECK(sle_cmtc_capability_parse_rsp(cmtc_req + 2, 12, &id, &mps, &ver) ==
          -1);
    uint8_t q[12];
    size_t qn = 0;
    CHECK(!sle_cmtc_capability_request(9, q, sizeof q, &qn) && qn == 12);
    CHECK(q[5] == 9 && !memcmp(q, cmtc_req + 2, 5) &&
          !memcmp(q + 6, cmtc_req + 8, 6));
    CHECK(sle_cmtc_capability_request(9, q, 11, &qn) == -1 && !qn);
  }
  CHECK(!sle_cmtc_capability_req_pdu(req, 13) &&
        !sle_cmtc_capability_req_pdu(NULL, 14));
  CHECK(sle_cmtc_capability_reply(req + 2, 12, rsp + 2, 15, &n) == -1 && !n);
  CHECK(sle_cmtc_capability_reply(req + 2, 11, rsp + 2, 16, &n) == -1);
  CHECK(sle_cmtc_capability_reply(req + 2, 12, NULL, 16, &n) == -1);
  CHECK(sle_cmtc_capability_reply(req + 2, 12, rsp + 2, 16, NULL) == -1);
}
/* Plaintext G->T request; returns the T plaintext output. */
static void cmtc_g_to_t(dialogue *d, const uint8_t *wire, size_t n) {
  uint8_t plain[64];
  size_t pn;
  int pair = 1;
  uint64_t before = d->t.rx_next;
  CHECK(!sle_t_pair_rx(&d->t, ga, 0, wire, n, d->gsn, 0, ++d->now, plain,
                      sizeof plain, &pn, &pair));
  CHECK(!pair && pn == n && !memcmp(plain, wire, n));
  CHECK(d->t.rx_next == before + 1); /* CMTC DATA counts (0x10009 probe) */
  CHECK(sle_t_pair_rx(&d->t, ga, 0, wire, n, d->gsn, 1, ++d->now, plain,
                     sizeof plain, &pn, &pair) == SLE_PAIR_DUPLICATE);
  CHECK(!pn && d->t.rx_next == before + 1);
  d->gplain_tx++;
  d->gsn ^= 1;
}
static void cmtc_t_to_g(dialogue *d, const uint8_t *req) {
  uint8_t sdu[16], plain[18], wire[64], retry[64];
  size_t n, rn;
  CHECK(!sle_cmtc_capability_reply(req + 2, 12, sdu, sizeof sdu, &n));
  plain[0] = 0x80;
  plain[1] = 0;
  memcpy(plain + 2, sdu, n);
  uint64_t before = d->t.tx_next;
  CHECK(!sle_t_pair_tx(&d->t, 0, plain, 18, d->tsn, 0, wire, sizeof wire, &n));
  CHECK(n == 18 && !memcmp(wire, plain, 18) && d->t.tx_next == before);
  CHECK(!sle_t_pair_tx(&d->t, 0, plain, 18, d->tsn, 1, retry, sizeof retry,
                      &rn));
  CHECK(rn == n && !memcmp(retry, wire, n));
  CHECK(!sle_t_pair_submitted(&d->t, d->tsn) && d->t.tx_next == before + 1);
  d->gplain_rx++;
  d->tsn ^= 1;
}
static void cmtc_dialogue(void) {
  dialogue d;
  /* Request precedes pairing; the reply leaves after the pairing request
   * has already moved T out of READY (1.10.108 does not wait). */
  init(&d);
  cmtc_g_to_t(&d, cmtc_req, sizeof cmtc_req);
  CHECK(d.t.state == SLE_T_PAIR_READY);
  sle_pair_pdu_t pdu;
  CHECK(sle_pair_pop(&d.g, &pdu) == 1);
  g_to_t(&d, &pdu);
  CHECK(d.t.state != SLE_T_PAIR_READY);
  cmtc_t_to_g(&d, cmtc_req);
  /* T's own request (1.10.108 does this on every link) and G's reply. */
  {
    uint8_t q[14] = {0x60, 0}, wire[64], plain[64];
    size_t n, pn;
    int pair;
    CHECK(!sle_cmtc_capability_request(0, q + 2, 12, &n));
    uint64_t before = d.t.tx_next;
    CHECK(!sle_t_pair_tx(&d.t, 0, q, 14, d.tsn, 0, wire, sizeof wire, &n));
    CHECK(!sle_t_pair_submitted(&d.t, d.tsn) && d.t.tx_next == before + 1);
    d.gplain_rx++;
    d.tsn ^= 1;
    const uint8_t rsp[] = {0x80, 0, 2, 0, 12, 0, 2, 0, 8, 0, 0xa0, 0, 0, 0,
                           0xa0, 2, 1, 1};
    before = d.t.rx_next;
    CHECK(!sle_t_pair_rx(&d.t, ga, 0, rsp, sizeof rsp, d.gsn, 0, ++d.now,
                        plain, sizeof plain, &pn, &pair));
    CHECK(!pair && pn == sizeof rsp && d.t.rx_next == before + 1);
    d.gplain_tx++;
    d.gsn ^= 1;
  }
  pair_loop(&d, 7, 9);
  business(&d);
  negative(&d);
  sle_pair_clear(&d.g);
  sle_t_pair_clear(&d.t);

  /* Unknown plaintext DATA is still refused before encryption. */
  init(&d);
  uint8_t other[sizeof cmtc_req], out[64];
  size_t pn;
  int pair;
  memcpy(other, cmtc_req, sizeof other);
  other[10] = 0xa1;
  sle_t_pair t = d.t;
  CHECK(sle_t_pair_rx(&t, ga, 0, other, sizeof other, 0, 0, ++d.now, out,
                     sizeof out, &pn, &pair) == SLE_PAIR_ERR_STATE);
  t = d.t;
  const uint8_t ssap[] = {0x50, 0, 0x0a, 0, 6, 0, 3, 3, 8, 2, 1, 0};
  CHECK(sle_t_pair_rx(&t, ga, 0, ssap, sizeof ssap, 0, 0, ++d.now, out,
                     sizeof out, &pn, &pair) == SLE_PAIR_ERR_STATE);
  t = d.t;
  CHECK(sle_t_pair_rx(&t, ga, 2, cmtc_req, sizeof cmtc_req, 0, 0, ++d.now, out,
                     sizeof out, &pn, &pair) == SLE_PAIR_ERR_STATE);
  /* T may send only its exact CMTC reply in plaintext, never after the
   * security switch has made its transmit direction secure. */
  uint8_t rsp[18] = {0x80, 0}, wire[64];
  size_t n;
  CHECK(!sle_cmtc_capability_reply(cmtc_req + 2, 12, rsp + 2, 16, &n));
  t = d.t;
  CHECK(sle_t_pair_tx(&t, 0, ssap, sizeof ssap, 0, 0, wire, sizeof wire, &n) ==
        SLE_PAIR_ERR_STATE);
  t = d.t;
  CHECK(sle_t_pair_tx(&t, 2, rsp, sizeof rsp, 0, 0, wire, sizeof wire, &n) ==
        SLE_PAIR_ERR_STATE);
  t = d.t;
  t.tx_secure = 1;
  t.state = SLE_T_PAIR_WAIT_START_TX;
  CHECK(sle_t_pair_tx(&t, 0, rsp, sizeof rsp, 0, 0, wire, sizeof wire, &n) ==
        SLE_PAIR_ERR_STATE);
  sle_pair_clear(&d.g);
  sle_t_pair_clear(&d.t);
}
int main(void) {
  dialogue d;
  handshake(&d);
  business(&d);
  runtime_checks(&d);
  negative(&d);
  setup_errors();
  cmtc_unit();
  cmtc_dialogue();
  dialogue official;
  official_capabilities=1;
  handshake(&official);
  business(&official);
  sle_pair_clear(&official.g);
  sle_t_pair_clear(&official.t);
  /* 1.10.108 AES-CMAC session key: G variant 0x200 and T agree. */
  official_capabilities = 0;
  test_variant = SLE_PAIR_V_COUNT_PLAIN;
  dialogue cmac;
  handshake(&cmac);
  {
    CHECK(!memcmp(cmac.t.key, cmac.t.probe_key[SLE_T_KDF_CMAC], 16));
    CHECK(memcmp(cmac.t.probe_key[SLE_T_KDF_ECB], cmac.t.key, 16));
  }
  business(&cmac);
  sle_pair_clear(&cmac.g);
  sle_t_pair_clear(&cmac.t);
  test_variant = SLE_PAIR_PROFILE_WS63;
  sle_pair_clear(&d.g);
  sle_t_pair_clear(&d.t);
  printf("T protocol: %u checks PASS (offline only; no RF claim)\n", checks);
  return 0;
}
