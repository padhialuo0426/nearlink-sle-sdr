#include "sle_t_pair.h"
#include "sle_cmtc.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform_util.h"
#include <string.h>

static void wipe(void *p, size_t n) { mbedtls_platform_zeroize(p, n); }
static int eq(const uint8_t *a, const uint8_t *b, size_t n) {
  unsigned v = 0;
  for (size_t i = 0; i < n; i++)
    v |= a[i] ^ b[i];
  return !v;
}
static void rev(uint8_t *d, const uint8_t *s, size_t n) {
  for (size_t i = 0; i < n; i++)
    d[i] = s[n - i - 1];
}
static int mac(const uint8_t *key, const uint8_t *msg, size_t n,
               uint8_t out[16]) {
  uint8_t k[16], m[128], v[16];
  if (n > sizeof m)
    return SLE_PAIR_ERR_ARGUMENT;
  rev(k, key, 16);
  rev(m, msg, n);
  int e = sle_aes_cmac(k, m, n, v);
  if (!e)
    rev(out, v, 16);
  wipe(k, 16);
  wipe(m, sizeof m);
  wipe(v, 16);
  return e ? SLE_PAIR_ERR_CRYPTO : 0;
}
static void secrets(sle_t_pair *p) {
  wipe(p->private_be, 32);
  wipe(p->dh, 32);
  wipe(p->ra, 16);
  wipe(p->rb, 16);
  wipe(p->lk, 16);
  wipe(p->expected_g, 16);
  wipe(p->t_check, 16);
  wipe(p->giv, 12);
  wipe(p->tiv, 12);
  wipe(p->cookie, 16);
}
static int fail(sle_t_pair *p, int e) {
  if (p->state == SLE_T_PAIR_FAILED)
    return p->error;
  secrets(p);
  wipe(p->key, 16);
  wipe(p->iv, 8);
  wipe(p->queue, sizeof p->queue);
  p->count = 0;
  wipe(p->tx_plain, sizeof p->tx_plain);
  wipe(p->tx_wire, sizeof p->tx_wire);
  wipe(p->rx_wire, sizeof p->rx_wire);
  p->tx_valid = p->rx_valid = 0;
  p->state = SLE_T_PAIR_FAILED;
  p->active = p->rx_secure = p->tx_secure = 0;
  p->error = e;
  return e;
}
static void state(sle_t_pair *p, sle_t_pair_state s) {
  p->state = s;
  p->step_ms = p->now_ms;
}
static int queue(sle_t_pair *p, unsigned op, const uint8_t *d, size_t n) {
  if (p->count == 4 || n + 3 > SLE_PAIR_CTRL_MAX)
    return fail(p, SLE_PAIR_ERR_QUEUE);
  sle_pair_pdu_t *q = &p->queue[(p->head + p->count) % 4];
  memset(q, 0, sizeof *q);
  q->data[0] = (uint8_t)op;
  q->data[1] = (uint8_t)(op >> 8);
  q->data[2] = (uint8_t)n;
  if (n)
    memcpy(q->data + 3, d, n);
  q->len = n + 3;
  q->encrypted = p->tx_secure;
  p->count++;
  return 0;
}
int sle_t_pair_init(sle_t_pair *p, const sle_pair_config_t *cfg) {
  if (!p || !cfg)
    return SLE_PAIR_ERR_ARGUMENT;
  sle_pair_config_t c = *cfg;
  wipe(p, sizeof *p);
  if (!c.rng ||
      (c.variant != SLE_PAIR_PROFILE_WS63 && c.variant != SLE_PAIR_V_COUNT_PLAIN) ||
      eq(c.g_addr, c.t_addr, 6))
    return SLE_PAIR_ERR_ARGUMENT;
  p->cfg = c;
  p->mic_probe = -1;
  if (!p->cfg.step_timeout_ms)
    p->cfg.step_timeout_ms = 5000;
  if (!p->cfg.total_timeout_ms)
    p->cfg.total_timeout_ms = 30000;
  return 0;
}
void sle_t_pair_clear(sle_t_pair *p) {
  if (p)
    wipe(p, sizeof *p);
}
typedef struct {
  sle_crypto_rng_t fn;
  void *ctx;
  int failed;
} rng_state;
static int rng(void *arg, unsigned char *out, size_t n) {
  rng_state *r = arg;
  if (r->failed || r->fn(r->ctx, out, n)) {
    r->failed = 1;
    wipe(out, n);
    return -1;
  }
  return 0;
}
int sle_t_pair_prepare(sle_t_pair *p) {
  if (!p || p->state != SLE_T_PAIR_IDLE || !p->cfg.rng ||
      (p->cfg.variant != SLE_PAIR_PROFILE_WS63 &&
       p->cfg.variant != SLE_PAIR_V_COUNT_PLAIN))
    return SLE_PAIR_ERR_STATE;
  mbedtls_ecp_group g;
  mbedtls_ecp_point q;
  mbedtls_mpi d;
  mbedtls_ecp_group_init(&g);
  mbedtls_ecp_point_init(&q);
  mbedtls_mpi_init(&d);
  rng_state r = {p->cfg.rng, p->cfg.rng_ctx, 0};
  uint8_t sec[65];
  size_t n = 0;
  int e = mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1);
  if (!e)
    e = mbedtls_ecp_gen_keypair(&g, &d, &q, rng, &r);
  if (!e)
    e = mbedtls_mpi_write_binary(&d, p->private_be, 32);
  if (!e)
    e = mbedtls_ecp_point_write_binary(&g, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &n,
                                       sec, sizeof sec);
  if (!e && n != 65)
    e = -1;
  if (!e) {
    rev(p->public_le, sec + 1, 32);
    rev(p->public_le + 32, sec + 33, 32);
    e = rng(&r, p->rb, 16);
    if (!e)
      e = rng(&r, p->tiv, 12);
    if (!e)
      e = rng(&r, p->cookie, 16);
  }
  wipe(sec, sizeof sec);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&q);
  mbedtls_ecp_group_free(&g);
  if (e)
    return fail(p, r.failed ? SLE_PAIR_ERR_RNG : SLE_PAIR_ERR_CRYPTO);
  state(p, SLE_T_PAIR_READY);
  return 0;
}
int sle_t_pair_tick(sle_t_pair *p, uint64_t now) {
  if (!p)
    return SLE_PAIR_ERR_ARGUMENT;
  if (p->state == SLE_T_PAIR_FAILED)
    return p->error;
  if (p->active && now < p->now_ms)
    return fail(p, SLE_PAIR_ERR_CLOCK);
  p->now_ms = now;
  if (p->active && (now - p->step_ms >= p->cfg.step_timeout_ms ||
                    now - p->start_ms >= p->cfg.total_timeout_ms))
    return fail(p, SLE_PAIR_ERR_TIMEOUT);
  return 0;
}
int sle_t_pair_pop(sle_t_pair *p, sle_pair_pdu_t *out) {
  if (!p || !out)
    return SLE_PAIR_ERR_ARGUMENT;
  memset(out, 0, sizeof *out);
  if (!p->count)
    return 0;
  *out = p->queue[p->head];
  wipe(&p->queue[p->head], sizeof *out);
  p->head = (p->head + 1) % 4;
  p->count--;
  return 1;
}
int sle_t_pair_take_work(sle_t_pair *p, sle_pair_work_t *w) {
  if (!p || !w)
    return SLE_PAIR_ERR_ARGUMENT;
  if (p->state != SLE_T_PAIR_WAIT_WORK || p->work_taken)
    return SLE_PAIR_ERR_STATE;
  memset(w, 0, sizeof *w);
  memcpy(w->cookie, p->cookie, 16);
  memcpy(w->private_be, p->private_be, 32);
  memcpy(w->peer_le, p->g_public, 64);
  w->rng = p->cfg.rng;
  w->rng_ctx = p->cfg.rng_ctx;
  w->valid = 1;
  wipe(p->private_be, 32);
  p->work_taken = 1;
  return 0;
}
int sle_t_pair_finish_work(sle_t_pair *p, sle_pair_work_result_t *r,
                          uint64_t now) {
  if (!p || !r)
    return SLE_PAIR_ERR_ARGUMENT;
  int e = sle_t_pair_tick(p, now);
  if (!e && (p->state != SLE_T_PAIR_WAIT_WORK || !p->work_taken || !r->valid ||
             !eq(r->cookie, p->cookie, 16)))
    e = SLE_PAIR_ERR_STATE;
  if (!e && r->error)
    e = fail(p, r->error);
  if (!e) {
    uint8_t m[128], confirm[16];
    memcpy(p->dh, r->shared_le, 32);
    memcpy(m, p->g_public, 64);
    memcpy(m + 64, p->public_le, 64);
    e = mac(p->rb, m, 128, confirm);
    if (!e) {
      state(p, SLE_T_PAIR_WAIT_RA);
      e = queue(p, 0x138, confirm, 16);
    }
    wipe(m, sizeof m);
    wipe(confirm, 16);
    wipe(p->cookie, 16);
  }
  sle_pair_work_result_clear(r);
  return e;
}
static int derive(sle_t_pair *p) {
  uint8_t m[128], dk[16];
  m[0] = 'k';
  m[1] = 'l';
  memcpy(m + 2, p->ra, 16);
  memcpy(m + 18, p->rb, 16);
  memcpy(m + 34, p->cfg.g_addr, 6);
  memcpy(m + 40, p->cfg.t_addr, 6);
  int e = mac(p->dh, m, 46, p->lk);
  m[1] = 'd';
  if (!e)
    e = mac(p->dh, m, 46, dk);
  memset(m, 0, 53);
  memcpy(m, p->ra, 16);
  m[32] = p->g_io;
  m[33] = 3;
  m[34] = 1;
  memset(m + 35, 2, 4);
  memcpy(m + 41, p->cfg.g_addr, 6);
  memcpy(m + 47, p->cfg.t_addr, 6);
  if (!e)
    e = mac(dk, m, 53, p->expected_g);
  memcpy(m, p->rb, 16);
  if (!e)
    e = mac(dk, m, 53, p->t_check);
  wipe(m, sizeof m);
  wipe(dk, 16);
  wipe(p->dh, 32);
  return e;
}
static int session(sle_t_pair *p) {
  uint8_t skd[16], key[16], in[16];
  memcpy(skd, p->giv + 4, 8);
  memcpy(skd + 8, p->tiv + 4, 8);
  rev(key, p->lk, 16);
  rev(in, skd, 16);
  uint8_t (*k)[16] = p->probe_key;
  int e = sle_aes128_encrypt_block(key, in, k[SLE_T_KDF_ECB]);
  /* 1.10.108 T/non-legacy G: AES-CMAC with the same reversals. */
  if (!e)
    e = sle_aes_cmac(key, in, 16, k[SLE_T_KDF_CMAC]);
  if (!e)
    e = sle_aes_cmac(p->lk, skd, 16, k[SLE_T_KDF_CMAC_PLAIN]);
  rev(k[SLE_T_KDF_CMAC_REV], k[SLE_T_KDF_CMAC], 16);
  rev(k[SLE_T_KDF_CMAC_PLAIN_REV], k[SLE_T_KDF_CMAC_PLAIN], 16);
  rev(k[SLE_T_KDF_ECB_REV], k[SLE_T_KDF_ECB], 16);
  memcpy(p->key, k[p->cfg.variant & SLE_PAIR_V_KDF_ECB ? SLE_T_KDF_ECB : SLE_T_KDF_CMAC],
         16);
  memcpy(p->iv, p->giv, 4);
  memcpy(p->iv + 4, p->tiv, 4);
  for (int i = 0; i < 4; i++)
    p->iv[i] ^= (uint8_t)(p->cfg.sync_low32 >> (i * 8));
  wipe(skd, 16);
  wipe(key, 16);
  wipe(in, 16);
  return e ? SLE_PAIR_ERR_CRYPTO : 0;
}
static int pair_op(unsigned op) {
  return (op >= 4 && op <= 9) || (op >= 0x133 && op <= 0x149) || op == 0x1ff;
}
static int dispatch(sle_t_pair *p, unsigned op, const uint8_t *d, size_t n) {
  static const uint8_t response[10] = {3, 0, 5, 16, 0, 2, 2, 2, 2, 0};
  int e = 0;
  if (op == 0x1ff || op == 0x147)
    return fail(p, SLE_PAIR_ERR_REMOTE);
  switch (op) {
  case 0x134:
    if (p->state != SLE_T_PAIR_READY)
      return fail(p, SLE_PAIR_ERR_STATE);
    if (n != 10)
      return fail(p, SLE_PAIR_ERR_LENGTH);
    if (d[0] > 4 || d[1] || d[2] != 5 || d[3] != 16 || d[4] || d[9] ||
        !(d[5] & 2) || !(d[6] & 2) || !(d[7] & 2) || !(d[8] & 2))
      return fail(p, SLE_PAIR_ERR_UNSUPPORTED);
    /* Table171 capability bit1 advertises algorithm2; unlike 0136 these
     * bytes are bitmaps, so official G capabilities 03/03/03/02 are valid. */
    if ((d[5] & 0xf0) || (d[6] & 0xf0) || (d[7] & 0xfc) || (d[8] & 0xfc))
      return fail(p, SLE_PAIR_ERR_PARAMETER);
    p->g_io = d[0];
    p->active = 1;
    p->start_ms = p->now_ms;
    state(p, SLE_T_PAIR_WAIT_PUBLIC);
    return queue(p, 0x135, response, 10);
  case 0x136:
    if (p->state != SLE_T_PAIR_WAIT_PUBLIC)
      return fail(p, SLE_PAIR_ERR_STATE);
    if (n != 70)
      return fail(p, SLE_PAIR_ERR_LENGTH);
    if (d[0] != 16 || d[1] != 1 || d[2] != 2 || d[3] != 2 || d[4] != 2 ||
        d[5] != 2)
      return fail(p, SLE_PAIR_ERR_UNSUPPORTED);
    if (eq(d + 6, p->public_le, 64))
      return fail(p, SLE_PAIR_ERR_PUBLIC_KEY);
    memcpy(p->g_public, d + 6, 64);
    state(p, SLE_T_PAIR_WAIT_WORK);
    return queue(p, 0x137, p->public_le, 64);
  case 0x139:
    if (p->state != SLE_T_PAIR_WAIT_RA)
      return fail(p, SLE_PAIR_ERR_STATE);
    if (n != 16)
      return fail(p, SLE_PAIR_ERR_LENGTH);
    memcpy(p->ra, d, 16);
    e = derive(p);
    if (e)
      return fail(p, e);
    state(p, SLE_T_PAIR_WAIT_DH);
    return queue(p, 0x13a, p->rb, 16);
  case 0x141:
    if (p->state != SLE_T_PAIR_WAIT_DH)
      return fail(p, SLE_PAIR_ERR_STATE);
    if (n != 16)
      return fail(p, SLE_PAIR_ERR_LENGTH);
    if (!eq(d, p->expected_g, 16))
      return fail(p, SLE_PAIR_ERR_DHKEY);
    state(p, SLE_T_PAIR_WAIT_SECURITY);
    return queue(p, 0x142, p->t_check, 16);
  case 4:
    if (p->state != SLE_T_PAIR_WAIT_SECURITY)
      return fail(p, SLE_PAIR_ERR_STATE);
    if (n != 13 || d[12])
      return fail(p, SLE_PAIR_ERR_PARAMETER);
    memcpy(p->giv, d, 12);
    e = session(p);
    if (e)
      return fail(p, e);
    e = queue(p, 5, p->tiv, 12);
    if (!e)
      e = queue(p, 6, NULL, 0);
    secrets(p);
    if (!e)
      state(p, SLE_T_PAIR_WAIT_START);
    return e;
  case 7:
    if (p->state != SLE_T_PAIR_WAIT_START || !p->rx_secure)
      return fail(p, SLE_PAIR_ERR_STATE);
    if (n)
      return fail(p, SLE_PAIR_ERR_LENGTH);
    p->tx_secure = 1;
    state(p, SLE_T_PAIR_WAIT_START_TX);
    return queue(p, 7, NULL, 0);
  default:
    return fail(p, SLE_PAIR_ERR_UNSUPPORTED);
  }
}
static void nonce(sle_t_pair *p, uint64_t count, int tx, uint8_t n[13]) {
  for (int i = 0; i < 5; i++)
    n[i] = (uint8_t)(count >> (8 * i));
  if (!tx)
    n[4] |= 0x80;
  memcpy(n + 5, p->iv, 8);
}
int sle_t_pair_rx(sle_t_pair *p, const uint8_t peer[6], uint8_t type,
                 const uint8_t *wire, size_t len, uint8_t sn, int duplicate,
                 uint64_t now, uint8_t *plain, size_t cap, size_t *out_len,
                 int *is_pair) {
  if (out_len)
    *out_len = 0;
  if (is_pair)
    *is_pair = 0;
  if (!p || !peer || !wire || !plain || !out_len || !is_pair || sn > 1 ||
      duplicate < 0 || duplicate > 1 || (type != 0 && type != 2 && type != 3))
    return SLE_PAIR_ERR_ARGUMENT;
  int e = sle_t_pair_tick(p, now);
  if (e)
    return e;
  if (!eq(peer, p->cfg.g_addr, 6))
    return fail(p, SLE_PAIR_ERR_IDENTITY);
  if (!len || len > SLE_PAIR_WIRE_MAX)
    return fail(p, SLE_PAIR_ERR_LENGTH);
  if (duplicate) {
    if (!p->rx_valid || sn != p->rx_sn || type != p->rx_type ||
        len != p->rx_len || !eq(wire, p->rx_wire, len))
      return fail(p, SLE_PAIR_ERR_SEQUENCE);
    /* Cached bytes were already MIC-verified; exact replay cannot change
     * plaintext. Counter never moves for a verified retransmission. */
    *is_pair = p->rx_pair;
    return SLE_PAIR_DUPLICATE;
  }
  if (p->rx_valid && sn == p->rx_sn)
    return fail(p, SLE_PAIR_ERR_SEQUENCE);
  if (p->rx_next >= SLE_PAIR_COUNTER_LIMIT)
    return fail(p, SLE_PAIR_ERR_COUNTER);
  int secure = p->rx_secure;
  size_t n = len - (secure ? 4u : 0u);
  if (secure && len < 5)
    return fail(p, SLE_PAIR_ERR_LENGTH);
  if (cap < n)
    return SLE_PAIR_ERR_BUFFER;
  uint8_t buf[SLE_PAIR_PLAIN_MAX];
  if (n > sizeof buf)
    return fail(p, SLE_PAIR_ERR_LENGTH);
  if (secure) {
    uint8_t nc[13], aad = 0;
    nonce(p, p->rx_next, 0, nc);
    if (sle_aes_ccm_decrypt(p->key, nc, 13, &aad, 1, wire, n, wire + n, 4, buf)) {
      /* Diagnostic only: which (counter, direction) would verify? Logs the
       * index, never key material; the frame is still rejected. */
      p->mic_probe = -1;
      for (int k = 0; k < SLE_T_KDF_CANDIDATES && p->mic_probe < 0; k++)
        for (int c = 0; c < 64 && p->mic_probe < 0; c++)
          for (int d = 0; d < 2 && p->mic_probe < 0; d++) {
            nonce(p, (uint64_t)c, d, nc);
            if (!sle_aes_ccm_decrypt(p->probe_key[k], nc, 13, &aad, 1, wire,
                                     n, wire + n, 4, buf))
              p->mic_probe = k << 16 | d << 8 | c;
          }
      wipe(buf, sizeof buf);
      return fail(p, SLE_PAIR_ERR_MIC);
    }
  } else
    memcpy(buf, wire, n);
  int pairing = 0;
  if (type == 3) {
    if (n < 3 || n != (size_t)buf[2] + 3) {
      wipe(buf, sizeof buf);
      return fail(p, SLE_PAIR_ERR_LENGTH);
    }
    unsigned op = buf[0] | (unsigned)buf[1] << 8;
    pairing = pair_op(op);
    if (pairing)
      e = dispatch(p, op, buf + 3, n - 3);
  } else if (p->state != SLE_T_PAIR_ENCRYPTED &&
             !(type == 0 && !secure && (sle_cmtc_capability_req_pdu(buf, n) ||
                                        sle_cmtc_capability_rsp_pdu(buf, n))))
    e = fail(p, SLE_PAIR_ERR_STATE);
  if (!e) {
    memcpy(plain, buf, n);
    *out_len = n;
    *is_pair = pairing;
    memcpy(p->rx_wire, wire, len);
    p->rx_len = len;
    p->rx_sn = sn;
    p->rx_type = type;
    p->rx_valid = 1;
    p->rx_cached_secure = secure;
    p->rx_pair = pairing;
    /* Every accepted nonempty plaintext PDU counts, including 1.10.108 CMTC
     * DATA: its first protected 0007 verified only at counter 9 under the
     * CMAC key (logs/e310/cmtc-t-g-cmac-20260928, mic_probe 0x10009). */
    p->rx_next++;
  }
  wipe(buf, sizeof buf);
  return e;
}
int sle_t_pair_tx(sle_t_pair *p, uint8_t type, const uint8_t *plain, size_t len,
                 uint8_t sn, int retx, uint8_t *wire, size_t cap,
                 size_t *out_len) {
  if (out_len)
    *out_len = 0;
  if (!p || !plain || !wire || !out_len || !len || sn > 1 || retx < 0 ||
      retx > 1 || (type != 0 && type != 2 && type != 3))
    return SLE_PAIR_ERR_ARGUMENT;
  if (p->state == SLE_T_PAIR_FAILED)
    return p->error;
  if (len > SLE_PAIR_PLAIN_MAX)
    return SLE_PAIR_ERR_LENGTH;
  if (retx) {
    if (!p->tx_valid || sn != p->tx_sn || type != p->tx_type ||
        len != p->tx_len || !eq(plain, p->tx_plain, len))
      return fail(p, SLE_PAIR_ERR_SEQUENCE);
    if (cap < p->tx_wire_len)
      return SLE_PAIR_ERR_BUFFER;
  } else {
    if (p->tx_valid && (!p->tx_submitted || sn == p->tx_sn))
      return fail(p, SLE_PAIR_ERR_SEQUENCE);
    /* The 1.10.108 peer may start pairing before our CMTC reply leaves;
     * admit that reply in any plaintext state, never after the switch. */
    if (type != 3 && p->state != SLE_T_PAIR_ENCRYPTED &&
        !(type == 0 && !p->tx_secure &&
          (sle_cmtc_capability_rsp_pdu(plain, len) ||
           sle_cmtc_capability_req_pdu(plain, len))))
      return fail(p, SLE_PAIR_ERR_STATE);
    if (p->tx_secure && p->state != SLE_T_PAIR_ENCRYPTED &&
        (p->state != SLE_T_PAIR_WAIT_START_TX || type != 3 || len != 3 ||
         !eq(plain, (const uint8_t *)"\7\0\0", 3)))
      return fail(p, SLE_PAIR_ERR_STATE);
    size_t n = len + (p->tx_secure ? 4u : 0u);
    if (cap < n)
      return SLE_PAIR_ERR_BUFFER;
    if (p->tx_next >= SLE_PAIR_COUNTER_LIMIT)
      return fail(p, SLE_PAIR_ERR_COUNTER);
    if (p->tx_secure) {
      uint8_t nc[13], aad = 0;
      nonce(p, p->tx_next, 1, nc);
      if (sle_aes_ccm_encrypt(p->key, nc, 13, &aad, 1, plain, len, p->tx_wire,
                              p->tx_wire + len, 4))
        return fail(p, SLE_PAIR_ERR_CRYPTO);
      p->tx_next++;
    } else
      memcpy(p->tx_wire, plain, len);
    memcpy(p->tx_plain, plain, len);
    p->tx_len = len;
    p->tx_wire_len = n;
    p->tx_sn = sn;
    p->tx_type = type;
    p->tx_valid = 1;
    p->tx_submitted = 0;
    p->tx_cached_secure = p->tx_secure;
  }
  memcpy(wire, p->tx_wire, p->tx_wire_len);
  *out_len = p->tx_wire_len;
  return 0;
}
int sle_t_pair_submitted(sle_t_pair *p, uint8_t sn) {
  if (!p || sn > 1)
    return SLE_PAIR_ERR_ARGUMENT;
  if (p->state == SLE_T_PAIR_FAILED)
    return p->error;
  if (!p->tx_valid || p->tx_sn != sn)
    return SLE_PAIR_ERR_STATE;
  if (p->tx_submitted)
    return 0;
  if (!p->tx_cached_secure) {
    if (p->tx_next >= SLE_PAIR_COUNTER_LIMIT)
      return fail(p, SLE_PAIR_ERR_COUNTER);
    p->tx_next++;
    if (p->tx_type == 3 && p->tx_len == 3 &&
        eq(p->tx_plain, (const uint8_t *)"\6\0\0", 3)) {
      if (p->state != SLE_T_PAIR_WAIT_START)
        return fail(p, SLE_PAIR_ERR_STATE);
      p->rx_secure = 1;
    }
  } else if (p->state == SLE_T_PAIR_WAIT_START_TX) {
    state(p, SLE_T_PAIR_ENCRYPTED);
    p->active = 0;
  }
  p->tx_submitted = 1;
  return 0;
}
