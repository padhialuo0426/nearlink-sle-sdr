#include "sle_pair.h"

#include <string.h>
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform_util.h"

static const uint8_t request[10] = {3, 0, 5, 16, 0, 2, 2, 2, 2, 0};
static const uint8_t startup[3] = {7, 0, 0};

static void wipe(void *p, size_t n) { mbedtls_platform_zeroize(p, n); }
static int equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    unsigned d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}
static void reverse(uint8_t *out, const uint8_t *in, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = in[n - 1 - i];
}
static int cmac_reverse(const uint8_t key[16], const uint8_t *msg, size_t n,
                         uint8_t out[16])
{
    uint8_t k[16], m[128], tag[16];
    if (n > sizeof m) return SLE_PAIR_ERR_ARGUMENT;
    reverse(k, key, sizeof k);
    reverse(m, msg, n);
    int r = sle_aes_cmac(k, m, n, tag);
    if (!r) reverse(out, tag, 16);
    wipe(k, sizeof k); wipe(m, sizeof m); wipe(tag, sizeof tag);
    return r ? SLE_PAIR_ERR_CRYPTO : 0;
}

/* Per-call RNG, not sle_crypto_set_rng's process-global setting. */
typedef struct { sle_crypto_rng_t fn; void *ctx; int failed; } rng_t;
static int rng_call(void *arg, unsigned char *out, size_t n)
{
    rng_t *r = arg;
    if (r->failed || r->fn(r->ctx, out, n)) {
        r->failed = 1;
        wipe(out, n);
        return -1;
    }
    return 0;
}

static int keygen(sle_pair_t *p)
{
    mbedtls_ecp_group g;
    mbedtls_ecp_point q;
    mbedtls_mpi d;
    uint8_t sec1[65];
    size_t n = 0;
    rng_t rng = {p->cfg.rng, p->cfg.rng_ctx, 0};
    mbedtls_ecp_group_init(&g); mbedtls_ecp_point_init(&q); mbedtls_mpi_init(&d);
    int r = mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1);
    if (!r) r = mbedtls_ecp_gen_keypair(&g, &d, &q, rng_call, &rng);
    if (!r) r = mbedtls_mpi_write_binary(&d, p->private_be, 32);
    if (!r) r = mbedtls_ecp_point_write_binary(&g, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                              &n, sec1, sizeof sec1);
    if (!r && n != sizeof sec1) r = -1;
    if (!r) {
        reverse(p->public_le, sec1 + 1, 32);
        reverse(p->public_le + 32, sec1 + 33, 32);
        r = rng_call(&rng, p->ra, 16);
        if (!r) r = rng_call(&rng, p->giv_skd, 12);
        if (!r) r = rng_call(&rng, p->cookie, 16);
    }
    wipe(sec1, sizeof sec1);
    mbedtls_mpi_free(&d); mbedtls_ecp_point_free(&q); mbedtls_ecp_group_free(&g);
    return rng.failed ? SLE_PAIR_ERR_RNG : (r ? SLE_PAIR_ERR_CRYPTO : 0);
}

static void erase_pair_keys(sle_pair_t *p)
{
    wipe(p->private_be, sizeof p->private_be);
    wipe(p->dh_le, sizeof p->dh_le); wipe(p->link_key, sizeof p->link_key);
    wipe(p->expected_dh, sizeof p->expected_dh);
    wipe(p->ra, sizeof p->ra); wipe(p->rb, sizeof p->rb);
    wipe(p->giv_skd, sizeof p->giv_skd); wipe(p->cookie, sizeof p->cookie);
    wipe(p->t_confirm, sizeof p->t_confirm);
}

static uint8_t reason_for(int error)
{
    switch (error) {
    case SLE_PAIR_ERR_DHKEY: return 8;
    case SLE_PAIR_ERR_UNSUPPORTED: return 2;
    case SLE_PAIR_ERR_IDENTITY: case SLE_PAIR_ERR_LENGTH:
    case SLE_PAIR_ERR_PARAMETER: case SLE_PAIR_ERR_PUBLIC_KEY: return 9;
    default: return 10;
    }
}
static int fail(sle_pair_t *p, int error)
{
    if (p->state == SLE_PAIR_FAILED) return p->error;
    int notify = p->active && !p->secure && error != SLE_PAIR_ERR_REMOTE;
    p->error = error; p->failure_reason = reason_for(error);
    p->state = SLE_PAIR_FAILED; p->active = 0; p->secure = 0;
    p->pending = 0; p->start_sent = 0;
    erase_pair_keys(p);
    wipe(&p->cipher, sizeof p->cipher);
    wipe(&p->outgoing, sizeof p->outgoing);
    if (notify) {
        p->outgoing.data[0] = 0xff; p->outgoing.data[1] = 1;
        p->outgoing.data[2] = 1; p->outgoing.data[3] = p->failure_reason;
        p->outgoing.len = 4; p->pending = 1;
    }
    return error;
}
static void transition(sle_pair_t *p, sle_pair_state_t s, uint64_t now)
{
    p->state = s; p->step_ms = now;
}
static int queue(sle_pair_t *p, uint16_t opcode, const uint8_t *data, size_t n)
{
    if (p->pending) return fail(p, SLE_PAIR_ERR_QUEUE);
    if (n + 3 > sizeof p->outgoing.data) return fail(p, SLE_PAIR_ERR_LENGTH);
    memset(&p->outgoing, 0, sizeof p->outgoing);
    p->outgoing.data[0] = (uint8_t)opcode;
    p->outgoing.data[1] = (uint8_t)(opcode >> 8);
    p->outgoing.data[2] = (uint8_t)n;
    if (n) memcpy(p->outgoing.data + 3, data, n);
    p->outgoing.len = n + 3; p->outgoing.encrypted = p->secure;
    p->pending = 1;
    return 0;
}

int sle_pair_init(sle_pair_t *p, const sle_pair_config_t *cfg)
{
    if (!p || !cfg) return SLE_PAIR_ERR_ARGUMENT;
    sle_pair_config_t copy = *cfg;
    wipe(p, sizeof *p);
    if (!copy.rng || equal(copy.g_addr, copy.t_addr, 6) || (copy.variant & ~SLE_PAIR_V_MASK) ||
        ((copy.variant & SLE_PAIR_V_COUNT_PLAIN) && (copy.variant & SLE_PAIR_V_CTR1)))
        return SLE_PAIR_ERR_ARGUMENT;
    p->cfg = copy;
    if (!p->cfg.step_timeout_ms) p->cfg.step_timeout_ms = 5000;
    if (!p->cfg.total_timeout_ms) p->cfg.total_timeout_ms = 30000;
    p->state = SLE_PAIR_IDLE; p->confirm_matches = -1;
    return 0;
}
void sle_pair_clear(sle_pair_t *p) { if (p) wipe(p, sizeof *p); }
int sle_pair_prepare(sle_pair_t *p)
{
    if (!p) return SLE_PAIR_ERR_ARGUMENT;
    if (p->state != SLE_PAIR_IDLE) return SLE_PAIR_ERR_STATE;
    int r = keygen(p);
    if (r) return fail(p, r);
    p->state = SLE_PAIR_READY;
    return 0;
}
int sle_pair_start(sle_pair_t *p, uint64_t now)
{
    if (!p) return SLE_PAIR_ERR_ARGUMENT;
    if (p->state != SLE_PAIR_READY) return SLE_PAIR_ERR_STATE;
    p->active = 1; p->start_ms = now; p->last_ms = now;
    transition(p, SLE_PAIR_WAIT_RESPONSE, now);
    return queue(p, 0x0134, request, sizeof request);
}
int sle_pair_tick(sle_pair_t *p, uint64_t now)
{
    if (!p) return SLE_PAIR_ERR_ARGUMENT;
    if (p->state == SLE_PAIR_FAILED) return p->error;
    if (!p->active) return 0;
    if (now < p->last_ms) return fail(p, SLE_PAIR_ERR_CLOCK);
    p->last_ms = now;
    if (now - p->step_ms >= p->cfg.step_timeout_ms ||
        now - p->start_ms >= p->cfg.total_timeout_ms)
        return fail(p, SLE_PAIR_ERR_TIMEOUT);
    return 0;
}
int sle_pair_pop(sle_pair_t *p, sle_pair_pdu_t *out)
{
    if (!p || !out) return SLE_PAIR_ERR_ARGUMENT;
    if (!p->pending) { memset(out, 0, sizeof *out); return 0; }
    *out = p->outgoing;
    wipe(&p->outgoing, sizeof p->outgoing);
    p->pending = 0;
    return 1;
}
void sle_pair_status(const sle_pair_t *p, sle_pair_status_t *out)
{
    if (!p || !out) return;
    out->state = p->state; out->error = p->error; out->secure = p->secure;
    out->confirm_matches = p->confirm_matches;
    out->failure_reason = p->failure_reason; out->remote_reason = p->remote_reason;
    out->tx_next = p->cipher.tx_next; out->rx_next = p->cipher.rx_next;
}

void sle_pair_work_clear(sle_pair_work_t *w) { if (w) wipe(w, sizeof *w); }
void sle_pair_work_result_clear(sle_pair_work_result_t *r) { if (r) wipe(r, sizeof *r); }
int sle_pair_take_work(sle_pair_t *p, sle_pair_work_t *w)
{
    if (!p || !w) return SLE_PAIR_ERR_ARGUMENT;
    if (p->state != SLE_PAIR_WAIT_ECDH || p->work_taken) return SLE_PAIR_ERR_STATE;
    memset(w, 0, sizeof *w);
    memcpy(w->cookie, p->cookie, 16); memcpy(w->private_be, p->private_be, 32);
    memcpy(w->peer_le, p->peer_le, 64);
    w->rng = p->cfg.rng; w->rng_ctx = p->cfg.rng_ctx; w->valid = 1;
    wipe(p->private_be, sizeof p->private_be); p->work_taken = 1;
    return 0;
}
int sle_pair_run_work(sle_pair_work_t *w, sle_pair_work_result_t *out)
{
    if (!w || !out) return SLE_PAIR_ERR_ARGUMENT;
    memset(out, 0, sizeof *out);
    if (!w->valid || !w->rng) { sle_pair_work_clear(w); return SLE_PAIR_ERR_ARGUMENT; }
    memcpy(out->cookie, w->cookie, 16); out->valid = 1;
    mbedtls_ecp_group g;
    mbedtls_ecp_point q;
    mbedtls_mpi d, z;
    uint8_t sec1[65], be[32];
    rng_t rng = {w->rng, w->rng_ctx, 0};
    mbedtls_ecp_group_init(&g); mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&z);
    int r = mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1);
    if (r) out->error = SLE_PAIR_ERR_CRYPTO;
    sec1[0] = 4;
    reverse(sec1 + 1, w->peer_le, 32); reverse(sec1 + 33, w->peer_le + 32, 32);
    if (!r) {
        r = mbedtls_ecp_point_read_binary(&g, &q, sec1, sizeof sec1);
        if (!r) r = mbedtls_ecp_check_pubkey(&g, &q);
        if (r) out->error = SLE_PAIR_ERR_PUBLIC_KEY;
    }
    if (!r) r = mbedtls_mpi_read_binary(&d, w->private_be, 32);
    if (!r) r = mbedtls_ecp_check_privkey(&g, &d);
    if (!r) r = mbedtls_ecdh_compute_shared(&g, &z, &q, &d, rng_call, &rng);
    if (!r) r = mbedtls_mpi_write_binary(&z, be, 32);
    if (!r) reverse(out->shared_le, be, 32);
    if (rng.failed) out->error = SLE_PAIR_ERR_RNG;
    else if (r && !out->error) out->error = SLE_PAIR_ERR_CRYPTO;
    mbedtls_mpi_free(&z); mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q); mbedtls_ecp_group_free(&g);
    wipe(sec1, sizeof sec1); wipe(be, sizeof be); sle_pair_work_clear(w);
    return out->error;
}
static int send_ra(sle_pair_t *p, uint64_t now)
{
    transition(p, SLE_PAIR_WAIT_RB, now);
    return queue(p, 0x0139, p->ra, 16);
}
int sle_pair_finish_work(sle_pair_t *p, sle_pair_work_result_t *r, uint64_t now)
{
    if (!p || !r) return SLE_PAIR_ERR_ARGUMENT;
    int err = sle_pair_tick(p, now);
    if (!err && (p->state != SLE_PAIR_WAIT_ECDH || !p->work_taken || !r->valid ||
                 !equal(r->cookie, p->cookie, 16))) err = SLE_PAIR_ERR_STATE;
    if (!err && r->error) err = fail(p, r->error);
    if (!err) {
        memcpy(p->dh_le, r->shared_le, 32);
        wipe(p->cookie, sizeof p->cookie);
        if (p->have_confirm) err = send_ra(p, now);
        else transition(p, SLE_PAIR_WAIT_CONFIRM, now);
    }
    sle_pair_work_result_clear(r);
    return err;
}

static int negotiate(sle_pair_t *p, const uint8_t *d)
{
    if (d[0] > 4 || d[1] > 1 || (d[2] & 0xf0) || (d[2] & 3) > 1 ||
        (d[4] & 0xfc) || (d[5] & 0xf0) || (d[6] & 0xf0) ||
        (d[7] & 0xfc) || (d[8] & 0xfc) || d[9] > 1)
        return SLE_PAIR_ERR_PARAMETER;
    if (d[3] < 16) return SLE_PAIR_ERR_PARAMETER;
    if (d[1] || d[4] || d[9] || (d[2] & 8)) return SLE_PAIR_ERR_UNSUPPORTED;
    for (int i = 5; i <= 8; i++) if (!(d[i] & 2)) return SLE_PAIR_ERR_UNSUPPORTED;
    p->peer_io = d[0]; /* G IO=3: table 179 chooses JW for all valid T IOs. */
    return 0;
}
static int derive_pair_keys(sle_pair_t *p, uint8_t g_check[16])
{
    uint8_t m[128], dk[16];
    memcpy(m, p->public_le, 64); memcpy(m + 64, p->peer_le, 64);
    int r = cmac_reverse(p->rb, m, 128, dk);
    if (!r) p->confirm_matches = equal(dk, p->t_confirm, 16);
    m[0] = 'k'; m[1] = 'l';
    memcpy(m + 2, p->ra, 16); memcpy(m + 18, p->rb, 16);
    memcpy(m + 34, p->cfg.g_addr, 6); memcpy(m + 40, p->cfg.t_addr, 6);
    if (!r) r = cmac_reverse(p->dh_le, m, 46, p->link_key);
    m[1] = 'd';
    if (!r) r = cmac_reverse(p->dh_le, m, 46, dk);
    memset(m, 0, 53); memcpy(m, p->ra, 16);
    m[32] = 3; m[33] = p->peer_io; m[34] = 1;
    memset(m + 35, 2, 4);
    memcpy(m + 41, p->cfg.g_addr, 6); memcpy(m + 47, p->cfg.t_addr, 6);
    if (!r) r = cmac_reverse(dk, m, 53, g_check);
    memcpy(m, p->rb, 16);
    if (!r) r = cmac_reverse(dk, m, 53, p->expected_dh);
    wipe(m, sizeof m); wipe(dk, sizeof dk); wipe(p->dh_le, sizeof p->dh_le);
    return r;
}
static int session(sle_pair_t *p, const uint8_t *d)
{
    uint8_t skd[16], sk_le[16];
    unsigned v = p->cfg.variant;
    int tg = (v & SLE_PAIR_V_SKD_TG) != 0;
    memcpy(skd, tg ? d + 4 : p->giv_skd + 4, 8); memcpy(skd + 8, tg ? p->giv_skd + 4 : d + 4, 8);
    int r;
    if (v & SLE_PAIR_V_KDF_ECB) {
        uint8_t k[16], m[16], o[16];
        reverse(k, p->link_key, 16); reverse(m, skd, 16);
        r = sle_aes128_encrypt_block(k, m, o) ? SLE_PAIR_ERR_CRYPTO : 0;
        if (!r) reverse(sk_le, o, 16);
        wipe(k, sizeof k); wipe(m, sizeof m); wipe(o, sizeof o);
    } else r = v & SLE_PAIR_V_KDF_PLAIN ? (sle_aes_cmac(p->link_key, skd, 16, sk_le) ? SLE_PAIR_ERR_CRYPTO : 0) :
        cmac_reverse(p->link_key, skd, 16, sk_le);
    if (!r) {
        if (v & SLE_PAIR_V_KEY_NOREV) memcpy(p->cipher.key, sk_le, 16);
        else reverse(p->cipher.key, sk_le, 16);
        tg = (v & SLE_PAIR_V_IV_TG) != 0;
        memcpy(p->cipher.iv, tg ? d : p->giv_skd, 4); memcpy(p->cipher.iv + 4, tg ? p->giv_skd : d, 4);
        for (int i = 0; i < 4; i++)
            p->cipher.iv[i] ^= (uint8_t)(p->cfg.sync_low32 >> (8 * (v & SLE_PAIR_V_SYNC_BE ? 3 - i : i)));
        if (v & SLE_PAIR_V_CTR1) p->cipher.tx_next = p->cipher.rx_next = 1;
    }
    wipe(skd, sizeof skd); wipe(sk_le, sizeof sk_le); erase_pair_keys(p);
    return r;
}

static void nonce(const sle_pair_t *p, uint64_t counter, int tx, uint8_t n[13])
{
    for (int i = 0; i < 5; i++) n[i] = (uint8_t)(counter >> (8 * i));
    n[4] |= (uint8_t)(tx ? 0x80 : 0);
    memcpy(n + 5, p->cipher.iv, 8);
    if (p->cfg.variant & SLE_PAIR_V_NONCE_REV) { uint8_t t[13]; reverse(t, n, 13); memcpy(n, t, 13); }
}
static void mic_order(const sle_pair_t *p, uint8_t mic[4])
{
    if (!(p->cfg.variant & SLE_PAIR_V_MIC_REV)) return;
    uint8_t t[4]; reverse(t, mic, 4); memcpy(mic, t, 4);
}
int sle_pair_seed_plain_counters(sle_pair_t *p, uint64_t tx, uint64_t rx)
{
    if (!p) return SLE_PAIR_ERR_ARGUMENT;
    if (!(p->cfg.variant & SLE_PAIR_V_COUNT_PLAIN) ||
        (p->cfg.variant & SLE_PAIR_V_CTR1) ||
        p->state != SLE_PAIR_WAIT_SECURITY_ACK || !p->secure || p->start_sent ||
        p->cipher.counters_seeded || p->cipher.tx_valid || p->cipher.rx_valid ||
        p->cipher.tx_next || p->cipher.rx_next)
        return SLE_PAIR_ERR_STATE;
    if (tx >= SLE_PAIR_COUNTER_LIMIT || rx >= SLE_PAIR_COUNTER_LIMIT)
        return SLE_PAIR_ERR_COUNTER;
    p->cipher.tx_next = tx; p->cipher.rx_next = rx;
    p->cipher.counters_seeded = 1;
    return 0;
}

int sle_pair_protect(sle_pair_t *p, const uint8_t *plain, size_t len,
                      uint8_t sn, int retx, uint8_t *wire, size_t cap, size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (!p || !out_len || (len && (!plain || !wire)) || sn > 1 || (retx != 0 && retx != 1))
        return SLE_PAIR_ERR_ARGUMENT;
    if (p->state == SLE_PAIR_FAILED) return p->error;
    if (!p->secure) return SLE_PAIR_ERR_STATE;
    if (len > SLE_PAIR_PLAIN_MAX) return SLE_PAIR_ERR_LENGTH;
    if (!len) return 0;
    if (cap < len + 4) return SLE_PAIR_ERR_BUFFER;
    if (p->state != SLE_PAIR_ENCRYPTED &&
        (p->state != SLE_PAIR_WAIT_SECURITY_ACK || len != 3 || !equal(plain, startup, 3) ||
         p->pending || (p->start_sent && !retx))) return fail(p, SLE_PAIR_ERR_STATE);
    sle_pair_cipher_t *c = &p->cipher;
    if ((p->cfg.variant & SLE_PAIR_V_COUNT_PLAIN) && !c->counters_seeded)
        return SLE_PAIR_ERR_STATE;
    if (retx) {
        if (!c->tx_valid || sn != c->tx_sn || len != c->tx_len || !equal(plain, c->tx_plain, len))
            return fail(p, SLE_PAIR_ERR_SEQUENCE);
    } else {
        if (c->tx_valid && c->tx_sn == sn) return fail(p, SLE_PAIR_ERR_SEQUENCE);
        if (c->tx_next >= SLE_PAIR_COUNTER_LIMIT) return fail(p, SLE_PAIR_ERR_COUNTER);
        uint8_t n[13], aad = 0;
        nonce(p, c->tx_next, 1, n);
        memcpy(c->tx_plain, plain, len);
        if (sle_aes_ccm_encrypt(c->key, n, 13, &aad, 1, c->tx_plain, len,
                                c->tx_wire, c->tx_wire + len, 4))
            return fail(p, SLE_PAIR_ERR_CRYPTO);
        mic_order(p, c->tx_wire + len);
        c->tx_len = len; c->tx_sn = sn; c->tx_valid = 1; c->tx_next++;
        if (p->state == SLE_PAIR_WAIT_SECURITY_ACK) p->start_sent = 1;
    }
    memmove(wire, c->tx_wire, len + 4); *out_len = len + 4;
    return 0;
}
static int decrypt(sle_pair_t *p, const uint8_t *wire, size_t len, uint8_t sn,
                    int duplicate, int control, uint8_t *plain, size_t cap, size_t *out_len)
{
    *out_len = 0;
    if (!len) return 0;
    if (len < 5 || len > SLE_PAIR_WIRE_MAX) return fail(p, SLE_PAIR_ERR_LENGTH);
    if (cap < len - 4) return SLE_PAIR_ERR_BUFFER;
    sle_pair_cipher_t *c = &p->cipher;
    if ((p->cfg.variant & SLE_PAIR_V_COUNT_PLAIN) && !c->counters_seeded)
        return SLE_PAIR_ERR_STATE;
    if ((duplicate && (!c->rx_valid || sn != c->rx_sn)) ||
        (!duplicate && c->rx_valid && sn == c->rx_sn)) return fail(p, SLE_PAIR_ERR_SEQUENCE);
    if (!duplicate && c->rx_next >= SLE_PAIR_COUNTER_LIMIT) return fail(p, SLE_PAIR_ERR_COUNTER);
    uint8_t n[13], aad = 0, scratch[SLE_PAIR_PLAIN_MAX];
    nonce(p, duplicate ? c->rx_next - 1 : c->rx_next, 0, n);
    uint8_t mic[4]; memcpy(mic, wire + len - 4, 4); mic_order(p, mic);
    int r = sle_aes_ccm_decrypt(c->key, n, 13, &aad, 1, wire, len - 4,
                                mic, 4, scratch);
    if (r) { wipe(scratch, sizeof scratch); return fail(p, SLE_PAIR_ERR_MIC); }
    if (duplicate) {
        r = control == c->rx_control && len == c->rx_len && equal(wire, c->rx_wire, len) ?
            SLE_PAIR_DUPLICATE : SLE_PAIR_ERR_SEQUENCE;
    } else {
        memcpy(c->rx_wire, wire, len); c->rx_len = len; c->rx_sn = sn;
        c->rx_valid = 1; c->rx_next++;
        c->rx_control = control; c->rx_is_pair = 0;
        wipe(p->plain_rx, sizeof p->plain_rx); p->plain_rx_len = 0;
        memmove(plain, scratch, len - 4); *out_len = len - 4;
        r = 0;
    }
    wipe(scratch, sizeof scratch);
    return r < 0 ? fail(p, r) : r;
}
int sle_pair_unprotect(sle_pair_t *p, const uint8_t *wire, size_t len,
                        uint8_t sn, int duplicate, uint8_t *plain, size_t cap, size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (!p || !out_len || (len && (!wire || !plain)) || sn > 1 || (duplicate != 0 && duplicate != 1))
        return SLE_PAIR_ERR_ARGUMENT;
    if (p->state == SLE_PAIR_FAILED) return p->error;
    if (p->state != SLE_PAIR_ENCRYPTED) return SLE_PAIR_ERR_STATE;
    return decrypt(p, wire, len, sn, duplicate, 0, plain, cap, out_len);
}

static int dispatch(sle_pair_t *p, uint16_t op, const uint8_t *d, size_t n, uint64_t now)
{
    if (op == 0x01ff || op == 0x0147) {
        if (n != 1) return fail(p, SLE_PAIR_ERR_LENGTH);
        if (!d[0] || d[0] > 11) return fail(p, SLE_PAIR_ERR_PARAMETER);
        p->remote_reason = d[0];
        return fail(p, SLE_PAIR_ERR_REMOTE);
    }
    if (p->pending) return fail(p, SLE_PAIR_ERR_STATE);
    int r = 0;
    uint8_t buf[70];
    switch (op) {
    case 0x0133:
        if (n != 1) return fail(p, SLE_PAIR_ERR_LENGTH);
        if ((d[0] & 0xf0) || (d[0] & 3) > 1) return fail(p, SLE_PAIR_ERR_PARAMETER);
        if (d[0] & 8) return fail(p, SLE_PAIR_ERR_UNSUPPORTED);
        if (p->state != SLE_PAIR_READY) return fail(p, SLE_PAIR_ERR_STATE);
        return sle_pair_start(p, now);
    case 0x0135:
        if (n != 10) return fail(p, SLE_PAIR_ERR_LENGTH);
        if (p->state != SLE_PAIR_WAIT_RESPONSE) return fail(p, SLE_PAIR_ERR_STATE);
        r = negotiate(p, d);
        if (r) return fail(p, r);
        buf[0] = 16; buf[1] = 1; memset(buf + 2, 2, 4);
        memcpy(buf + 6, p->public_le, 64);
        transition(p, SLE_PAIR_WAIT_PUBLIC_KEY, now);
        return queue(p, 0x0136, buf, 70);
    case 0x0137:
        if (n != 64) return fail(p, SLE_PAIR_ERR_LENGTH);
        if (p->state != SLE_PAIR_WAIT_PUBLIC_KEY) return fail(p, SLE_PAIR_ERR_STATE);
        if (equal(d, p->public_le, 64)) return fail(p, SLE_PAIR_ERR_PUBLIC_KEY);
        memcpy(p->peer_le, d, 64);
        transition(p, SLE_PAIR_WAIT_ECDH, now);
        return 0;
    case 0x0138:
        if (n != 16) return fail(p, SLE_PAIR_ERR_LENGTH);
        if ((p->state != SLE_PAIR_WAIT_ECDH && p->state != SLE_PAIR_WAIT_CONFIRM) || p->have_confirm)
            return fail(p, SLE_PAIR_ERR_STATE);
        memcpy(p->t_confirm, d, 16); p->have_confirm = 1;
        /* Early confirm does not extend the ECDH work timeout. */
        return p->state == SLE_PAIR_WAIT_ECDH ? 0 : send_ra(p, now);
    case 0x013a:
        if (n != 16) return fail(p, SLE_PAIR_ERR_LENGTH);
        if (p->state != SLE_PAIR_WAIT_RB) return fail(p, SLE_PAIR_ERR_STATE);
        memcpy(p->rb, d, 16);
        r = derive_pair_keys(p, buf);
        if (!r) { transition(p, SLE_PAIR_WAIT_DHKEY, now); r = queue(p, 0x0141, buf, 16); }
        wipe(buf, sizeof buf);
        return r ? fail(p, r) : 0;
    case 0x0142:
        if (n != 16) return fail(p, SLE_PAIR_ERR_LENGTH);
        if (p->state != SLE_PAIR_WAIT_DHKEY) return fail(p, SLE_PAIR_ERR_STATE);
        if (!equal(d, p->expected_dh, 16)) return fail(p, SLE_PAIR_ERR_DHKEY);
        memcpy(buf, p->giv_skd, 12); buf[12] = 0;
        transition(p, SLE_PAIR_WAIT_SECURITY_RESPONSE, now);
        r = queue(p, 4, buf, 13); wipe(buf, sizeof buf);
        return r;
    case 5:
        if (n != 12) return fail(p, SLE_PAIR_ERR_LENGTH);
        if (p->state != SLE_PAIR_WAIT_SECURITY_RESPONSE) return fail(p, SLE_PAIR_ERR_STATE);
        r = session(p, d);
        if (r) return fail(p, r);
        transition(p, SLE_PAIR_WAIT_SECURITY_START, now);
        return 0;
    case 6:
        if (n) return fail(p, SLE_PAIR_ERR_LENGTH);
        if (p->state != SLE_PAIR_WAIT_SECURITY_START) return fail(p, SLE_PAIR_ERR_STATE);
        p->secure = 1;
        transition(p, SLE_PAIR_WAIT_SECURITY_ACK, now);
        return queue(p, 7, NULL, 0);
    case 7:
        if (n) return fail(p, SLE_PAIR_ERR_LENGTH);
        if (p->state != SLE_PAIR_WAIT_SECURITY_ACK || !p->secure || !p->start_sent)
            return fail(p, SLE_PAIR_ERR_STATE);
        transition(p, SLE_PAIR_ENCRYPTED, now); p->active = 0;
        return 0;
    default:
        return fail(p, SLE_PAIR_ERR_UNSUPPORTED);
    }
}
static int pair_opcode(uint16_t op)
{
    return (op >= 4 && op <= 9) || (op >= 0x0133 && op <= 0x0149) || op == 0x01ff;
}

int sle_pair_on_control_ex(sle_pair_t *p, const uint8_t peer[6], const uint8_t *wire,
                           size_t len, uint8_t sn, int duplicate, uint64_t now,
                           uint8_t *plain, size_t cap, size_t *out_len, int *is_pair)
{
    if (out_len) *out_len = 0;
    if (is_pair) *is_pair = 0;
    if (!p || !peer || !wire || !out_len || !is_pair || (!plain && cap) ||
        sn > 1 || (duplicate != 0 && duplicate != 1))
        return SLE_PAIR_ERR_ARGUMENT;
    int r = sle_pair_tick(p, now);
    if (r) return r;
    if (!equal(peer, p->cfg.t_addr, 6)) return fail(p, SLE_PAIR_ERR_IDENTITY);
    if (p->state < SLE_PAIR_READY ||
        (p->secure && p->state != SLE_PAIR_WAIT_SECURITY_ACK && p->state != SLE_PAIR_ENCRYPTED))
        return fail(p, SLE_PAIR_ERR_STATE);
    /* Permit exactly the preceding plaintext 0006 retransmission at the
     * switch boundary, before ANY authenticated control/data was accepted. */
    if (duplicate && p->secure && p->state == SLE_PAIR_WAIT_SECURITY_ACK &&
        !p->cipher.rx_valid && p->plain_rx_len == 3 && p->plain_rx_is_pair &&
        len == 3 && sn == p->plain_rx_sn && wire[0] == 6 && !wire[1] && !wire[2] &&
        equal(wire, p->plain_rx, len)) {
        *is_pair = 1;
        return SLE_PAIR_DUPLICATE;
    }
    uint8_t decoded[SLE_PAIR_CTRL_INPUT_MAX];
    int secure = p->secure;
    if (secure) {
        if (len < 7 || len > sizeof decoded + 4) return fail(p, SLE_PAIR_ERR_LENGTH);
        if (!duplicate && cap < len - 4) return SLE_PAIR_ERR_BUFFER;
        size_t n = 0;
        r = decrypt(p, wire, len, sn, duplicate, 1, decoded, sizeof decoded, &n);
        if (r) {
            if (r == SLE_PAIR_DUPLICATE) *is_pair = p->cipher.rx_is_pair;
            wipe(decoded, sizeof decoded);
            return r;
        }
        wire = decoded; len = n;
    }
    if (len < 3 || len > sizeof decoded || len != (size_t)wire[2] + 3)
        r = fail(p, SLE_PAIR_ERR_LENGTH);
    else {
        uint16_t op = (uint16_t)(wire[0] | (uint16_t)wire[1] << 8);
        int pairing = pair_opcode(op);
        if (!secure && duplicate) {
            if (len != p->plain_rx_len || sn != p->plain_rx_sn ||
                !equal(wire, p->plain_rx, len)) r = fail(p, SLE_PAIR_ERR_SEQUENCE);
            else { *is_pair = p->plain_rx_is_pair; r = SLE_PAIR_DUPLICATE; }
        } else if (cap < len) r = SLE_PAIR_ERR_BUFFER;
        else if (pairing) r = dispatch(p, op, wire + 3, len - 3, now);
        if (!r) {
            if (pairing) {
                /* dispatch accepted only the bounded pairing formats. */
                memcpy(p->last_ctrl, wire, len); p->last_ctrl_len = len; p->last_ctrl_sn = sn;
            }
            if (secure) p->cipher.rx_is_pair = pairing;
            else {
                memcpy(p->plain_rx, wire, len); p->plain_rx_len = len;
                p->plain_rx_sn = sn; p->plain_rx_is_pair = pairing;
            }
            memmove(plain, wire, len); *out_len = len; *is_pair = pairing;
        }
    }
    wipe(decoded, sizeof decoded);
    return r;
}

int sle_pair_on_control(sle_pair_t *p, const uint8_t peer[6], const uint8_t *wire,
                        size_t len, uint8_t sn, int duplicate, uint64_t now)
{
    uint8_t plain[SLE_PAIR_CTRL_INPUT_MAX];
    size_t len_out;
    int is_pair;
    int r = sle_pair_on_control_ex(p, peer, wire, len, sn, duplicate, now,
                                   plain, sizeof plain, &len_out, &is_pair);
    wipe(plain, sizeof plain);
    return r;
}

const char *sle_pair_error_string(int e)
{
    switch (e) {
    case 0: return "ok";
    case SLE_PAIR_DUPLICATE: return "verified duplicate";
    case SLE_PAIR_ERR_ARGUMENT: return "invalid API argument";
    case SLE_PAIR_ERR_STATE: return "illegal pairing state";
    case SLE_PAIR_ERR_TIMEOUT: return "pairing timeout";
    case SLE_PAIR_ERR_IDENTITY: return "peer identity mismatch";
    case SLE_PAIR_ERR_LENGTH: return "invalid PDU length";
    case SLE_PAIR_ERR_PARAMETER: return "invalid parameter or reserved bits";
    case SLE_PAIR_ERR_UNSUPPORTED: return "unsupported pairing feature";
    case SLE_PAIR_ERR_PUBLIC_KEY: return "invalid peer public key";
    case SLE_PAIR_ERR_RNG: return "random source failed";
    case SLE_PAIR_ERR_CRYPTO: return "Mbed TLS operation failed";
    case SLE_PAIR_ERR_DHKEY: return "DHKey verification failed";
    case SLE_PAIR_ERR_REMOTE: return "peer rejected pairing";
    case SLE_PAIR_ERR_QUEUE: return "outgoing PDU not consumed";
    case SLE_PAIR_ERR_MIC: return "CCM MIC verification failed";
    case SLE_PAIR_ERR_COUNTER: return "CCM counter exhausted";
    case SLE_PAIR_ERR_SEQUENCE: return "ARQ sequence or retry mismatch";
    case SLE_PAIR_ERR_BUFFER: return "output buffer too small";
    case SLE_PAIR_ERR_CLOCK: return "monotonic clock moved backwards";
    default: return "unknown pairing error";
    }
}
