/* Offline regression; build and coverage notes: ../docs/e310-source.md. */
#define _POSIX_C_SOURCE 200809L
#include "sle_pair.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Synthetic Python cryptography/OpenSSL oracle: gen_pair_vectors.py.
 * Test snapshots/private keys and deterministic RNG MUST NOT enter radio code. */
static const char v_gpub[] = "edd48202b8e566df6c6ddf2b152c4f3aa2699e99968f27283944b6f017e6170294576e30657c89f252965958c75ff4565a76a85aa83cda2d2d7197cbeb7d4a19";
static const char v_tpub[] = "f39c58483add05d5eaba04735760165f469ea757ff5218081b3daa7c97935ad68512c9e9fc33c5c307d55bf05567dbfd73e45775133aea2162df7253895e1850";
static const char v_dh[] = "f69aa72c62086944908043484dbc29eef0c6ba3ba5d44aca983c19581f26fccc";
static const char v_lk[] = "039c597a1cf22920d5c4492ac668e194";
static const char v_gcheck[] = "38453c9e54e3e40680c5018c1ad3ad78";
static const char v_tcheck[] = "0776af29a71915549cf2c58f18239539";
static const char v_confirm[] = "6b2895d3e6b45e5fae0e5df53697e6a0";
static const char v_sk[] = "ebce21ca914c52d6c36f8754dbd34636";
static const char v_iv[] = "2acd2c7f70717273";
static const char v_gstart[] = "222f391167ee69";
static const char v_tstart[] = "da3f41246d72a1";
static const char v_gdata[] = "d30b7cb66bd0729df689b687de";
static const char v_tdata[] = "935c34a1b28d6b92ba8ace90e1";
static const char v_glast[] = "48ebfba982086de2ed8bd55dca";
static const char v_tlast[] = "1650c352ac14ab47ecb47fa8ef";

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)

static const uint8_t ga[6] = {0xee, 0xef, 0x33, 0x9b, 0x8d, 0x5c};
static const uint8_t ta[6] = {1, 2, 3, 4, 5, 6};
static const uint8_t response[10] = {3, 0, 5, 16, 0, 2, 2, 2, 2, 0};
static int rng_bad;
static int fixed_rng(void *ctx, unsigned char *b, size_t n)
{
    (void)ctx;
    if (rng_bad) { memset(b, 0xa5, n / 2); return -1; }
    for (size_t i = 0; i < n; i++) b[i] = n == 32 ? 0x11 : (uint8_t)((n == 12 ? 0x60 : 0x20) + i);
    return 0;
}
static int reject_rng(void *ctx, unsigned char *b, size_t n)
{
    (void)ctx; (void)b; (void)n;
    return -1;
}
static int reject_nonce_rng(void *ctx, unsigned char *b, size_t n)
{
    return n == 16 ? -1 : fixed_rng(ctx, b, n);
}
static int os_rng(void *ctx, unsigned char *b, size_t n)
{
    (void)ctx;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(b, 1, n, f);
    int r = fclose(f);
    return got == n && !r ? 0 : -1;
}
static double ms(void)
{
    struct timespec t;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1000000.0;
}
static sle_pair_config_t config(void)
{
    sle_pair_config_t c = {0};
    memcpy(c.g_addr, ga, 6); memcpy(c.t_addr, ta, 6);
    c.sync_low32 = 0x1c4eac4a; c.rng = fixed_rng;
    c.variant = 0; /* explicit historical CMAC/zero-counter oracle */
    return c;
}
static size_t hex(const char *s, uint8_t *out)
{
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        CHECK(sscanf(s + 2 * i, "%2x", &v) == 1); out[i] = (uint8_t)v;
    }
    return n;
}
static void is_hex(const uint8_t *b, size_t n, const char *s)
{
    uint8_t want[128];
    CHECK(hex(s, want) == n); CHECK(memcmp(b, want, n) == 0);
}
static int zero(const void *v, size_t n)
{
    const uint8_t *b = v;
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}
static int feed(sle_pair_t *p, unsigned op, const uint8_t *d, size_t n, unsigned sn, uint64_t now)
{
    uint8_t b[258];
    CHECK(n <= 255);
    b[0] = (uint8_t)op; b[1] = (uint8_t)(op >> 8); b[2] = (uint8_t)n;
    if (n) memcpy(b + 3, d, n);
    return sle_pair_on_control(p, ta, b, n + 3, (uint8_t)sn, 0, now);
}
static sle_pair_pdu_t pop(sle_pair_t *p, unsigned op, size_t n, int secure)
{
    sle_pair_pdu_t b;
    CHECK(sle_pair_pop(p, &b) == 1);
    CHECK(b.len == n + 3 && b.data[0] == (op & 255) && b.data[1] == (op >> 8));
    CHECK(b.data[2] == n && b.encrypted == secure);
    return b;
}
static void failed(sle_pair_t *p, int err, int notify)
{
    sle_pair_status_t s;
    sle_pair_status(p, &s);
    CHECK(s.state == SLE_PAIR_FAILED && s.error == err && !s.secure);
    CHECK(zero(p->private_be, 32) && zero(p->dh_le, 32) && zero(p->link_key, 16));
    CHECK(zero(p->expected_dh, 16) && zero(&p->cipher, sizeof p->cipher));
    if (notify) {
        sle_pair_pdu_t b = pop(p, 0x01ff, 1, 0);
        CHECK(b.data[3] == s.failure_reason);
    }
    sle_pair_pdu_t b;
    CHECK(sle_pair_pop(p, &b) == 0);
    CHECK(sle_pair_tick(p, 999999) == err);
    CHECK(strcmp(sle_pair_error_string(err), "unknown pairing error") != 0);
}

static struct {
    sle_pair_t ready, response, public_key, ecdh, confirm, rb, dh,
        security_response, start, ack, encrypted;
} f;

static void happy_path(void)
{
    sle_pair_t p;
    sle_pair_config_t cfg = config();
    CHECK(sle_pair_init(&p, &cfg) == 0);
    double before = ms();
    CHECK(sle_pair_prepare(&p) == 0);
    double key_ms = ms() - before;
    is_hex(p.public_le, 64, v_gpub);
    f.ready = p;
    CHECK(sle_pair_start(&p, 100) == 0);
    sle_pair_pdu_t b = pop(&p, 0x0134, 10, 0);
    CHECK(memcmp(b.data + 3, response, 10) == 0);
    f.response = p;
    CHECK(feed(&p, 0x0135, response, 10, 0, 101) == 0);
    b = pop(&p, 0x0136, 70, 0);
    CHECK(memcmp(b.data + 3, "\x10\x01\x02\x02\x02\x02", 6) == 0);
    is_hex(b.data + 9, 64, v_gpub);
    f.public_key = p;
    uint8_t d[128];
    hex(v_tpub, d);
    CHECK(feed(&p, 0x0137, d, 64, 1, 102) == 0);
    CHECK(p.state == SLE_PAIR_WAIT_ECDH);
    f.ecdh = p;
    sle_pair_work_t w; sle_pair_work_result_t r;
    CHECK(sle_pair_take_work(&p, &w) == 0);
    CHECK(zero(p.private_be, 32));
    before = ms();
    CHECK(sle_pair_run_work(&w, &r) == 0);
    double dh_ms = ms() - before;
    CHECK(zero(&w, sizeof w)); is_hex(r.shared_le, 32, v_dh);
    CHECK(sle_pair_finish_work(&p, &r, 103) == 0 && zero(&r, sizeof r));
    CHECK(p.state == SLE_PAIR_WAIT_CONFIRM); f.confirm = p;
    hex(v_confirm, d);
    CHECK(feed(&p, 0x0138, d, 16, 0, 104) == 0);
    b = pop(&p, 0x0139, 16, 0);
    for (int i = 0; i < 16; i++) CHECK(b.data[3 + i] == 0x20 + i);
    f.rb = p;
    for (int i = 0; i < 16; i++) d[i] = (uint8_t)(0x40 + i);
    CHECK(feed(&p, 0x013a, d, 16, 1, 105) == 0);
    b = pop(&p, 0x0141, 16, 0); is_hex(b.data + 3, 16, v_gcheck);
    is_hex(p.link_key, 16, v_lk); is_hex(p.expected_dh, 16, v_tcheck);
    CHECK(p.confirm_matches == 1); f.dh = p;
    hex(v_tcheck, d);
    CHECK(feed(&p, 0x0142, d, 16, 0, 106) == 0);
    b = pop(&p, 4, 13, 0);
    for (int i = 0; i < 12; i++) CHECK(b.data[3 + i] == 0x60 + i);
    CHECK(b.data[15] == 0); f.security_response = p;
    for (int i = 0; i < 12; i++) d[i] = (uint8_t)(0x70 + i);
    CHECK(feed(&p, 5, d, 12, 1, 107) == 0);
    is_hex(p.cipher.key, 16, v_sk); is_hex(p.cipher.iv, 8, v_iv);
    CHECK(zero(p.link_key, 16) && !p.secure); f.start = p;
    CHECK(feed(&p, 6, NULL, 0, 0, 108) == 0);
    CHECK(p.state == SLE_PAIR_WAIT_SECURITY_ACK && p.secure);
    b = pop(&p, 7, 0, 1); f.ack = p;
    size_t n = 0;
    CHECK(sle_pair_protect(&p, b.data, b.len, 0, 0, d, sizeof d, &n) == 0);
    is_hex(d, n, v_gstart);
    CHECK(p.state == SLE_PAIR_WAIT_SECURITY_ACK && p.cipher.tx_next == 1);
    n = hex(v_tstart, d);
    CHECK(sle_pair_on_control(&p, ta, d, n, 1, 0, 109) == 0);
    CHECK(p.state == SLE_PAIR_ENCRYPTED && p.cipher.rx_next == 1);
    f.encrypted = p;
    CHECK(sle_pair_on_control(&p, ta, d, n, 1, 1, 110) == SLE_PAIR_DUPLICATE);
    CHECK(p.cipher.rx_next == 1);
    CHECK(sle_pair_tick(&p, 9999999) == 0);
    sle_pair_clear(&p); CHECK(zero(&p, sizeof p));
    printf("pair vector handshake: PASS; prepare %.3f ms, worker ECDH %.3f ms (this runner only)\n", key_ms, dh_ms);
}

static void validation(void)
{
    static const struct { unsigned offset, value; int error; } bad[] = {
        {0,5,SLE_PAIR_ERR_PARAMETER}, {0,255,SLE_PAIR_ERR_PARAMETER},
        {1,2,SLE_PAIR_ERR_PARAMETER}, {1,1,SLE_PAIR_ERR_UNSUPPORTED},
        {2,0x85,SLE_PAIR_ERR_PARAMETER}, {2,2,SLE_PAIR_ERR_PARAMETER},
        {2,3,SLE_PAIR_ERR_PARAMETER}, {2,13,SLE_PAIR_ERR_UNSUPPORTED},
        {3,0,SLE_PAIR_ERR_PARAMETER}, {3,15,SLE_PAIR_ERR_PARAMETER},
        {4,1,SLE_PAIR_ERR_UNSUPPORTED}, {4,2,SLE_PAIR_ERR_UNSUPPORTED},
        {4,3,SLE_PAIR_ERR_UNSUPPORTED}, {4,4,SLE_PAIR_ERR_PARAMETER},
        {5,0x12,SLE_PAIR_ERR_PARAMETER}, {6,0x12,SLE_PAIR_ERR_PARAMETER},
        {7,6,SLE_PAIR_ERR_PARAMETER}, {8,6,SLE_PAIR_ERR_PARAMETER},
        {5,1,SLE_PAIR_ERR_UNSUPPORTED}, {6,1,SLE_PAIR_ERR_UNSUPPORTED},
        {7,1,SLE_PAIR_ERR_UNSUPPORTED}, {8,1,SLE_PAIR_ERR_UNSUPPORTED},
        {5,0,SLE_PAIR_ERR_UNSUPPORTED}, {6,4,SLE_PAIR_ERR_UNSUPPORTED},
        {9,1,SLE_PAIR_ERR_UNSUPPORTED}, {9,2,SLE_PAIR_ERR_PARAMETER}
    };
    sle_pair_t p;
    uint8_t d[128];
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        p = f.response; memcpy(d, response, 10); d[bad[i].offset] = (uint8_t)bad[i].value;
        CHECK(feed(&p, 0x0135, d, 10, 0, 101) == bad[i].error);
        failed(&p, bad[i].error, 1);
    }
    /* Capability intersection and table 179: accept valid IOs / larger max
     * key length but still select exactly 16 and AC2/HA2/KE2. */
    for (int io = 0; io <= 4; io++) {
        p = f.response; memcpy(d, response, 10); d[0] = (uint8_t)io;
        d[2] = 0; d[3] = 32; d[5] = d[6] = 15; d[7] = d[8] = 3;
        CHECK(feed(&p, 0x0135, d, 10, 0, 101) == 0);
        sle_pair_pdu_t b = pop(&p, 0x0136, 70, 0);
        CHECK(memcmp(b.data + 3, "\x10\x01\x02\x02\x02\x02", 6) == 0);
    }
    struct { sle_pair_t *snapshot; unsigned op, n; } lengths[] = {
        {&f.response,0x0135,10}, {&f.public_key,0x0137,64},
        {&f.confirm,0x0138,16}, {&f.rb,0x013a,16}, {&f.dh,0x0142,16},
        {&f.security_response,5,12}, {&f.start,6,0}, {&f.response,0x01ff,1}
    };
    memset(d, 0, sizeof d);
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; i++) {
        p = *lengths[i].snapshot;
        CHECK(feed(&p, lengths[i].op, d, lengths[i].n + 1, 0, 200) == SLE_PAIR_ERR_LENGTH);
        failed(&p, SLE_PAIR_ERR_LENGTH, 1);
        if (lengths[i].n) {
            p = *lengths[i].snapshot;
            CHECK(feed(&p, lengths[i].op, d, lengths[i].n - 1, 0, 200) == SLE_PAIR_ERR_LENGTH);
            failed(&p, SLE_PAIR_ERR_LENGTH, 1);
        }
    }
    for (size_t n = 0; n < 3; n++) {
        p = f.response;
        CHECK(sle_pair_on_control(&p, ta, d, n, 0, 0, 101) == SLE_PAIR_ERR_LENGTH);
    }
    p = f.response;
    uint8_t malformed[14] = {0x35,1,9}; memcpy(malformed + 3, response, 10);
    CHECK(sle_pair_on_control(&p, ta, malformed, 13, 0, 0, 101) == SLE_PAIR_ERR_LENGTH);
    p = f.response; malformed[2] = 10;
    CHECK(sle_pair_on_control(&p, ta, malformed, 14, 0, 0, 101) == SLE_PAIR_ERR_LENGTH);
    p = f.response;
    CHECK(sle_pair_on_control(&p, ga, malformed, 13, 0, 0, 101) == SLE_PAIR_ERR_IDENTITY);
    failed(&p, SLE_PAIR_ERR_IDENTITY, 1);
    unsigned unsupported[] = {0x0134,0x013c,0x013d,0x0143,0x0144,0x0145,0x0146,0x0148,0x0149,8,9};
    for (size_t i = 0; i < sizeof unsupported / sizeof unsupported[0]; i++) {
        p = f.response;
        CHECK(feed(&p, unsupported[i], NULL, 0, 0, 101) == SLE_PAIR_ERR_UNSUPPORTED);
        failed(&p, SLE_PAIR_ERR_UNSUPPORTED, 1);
    }
    /* Legal lengths, illegal transitions. */
    for (size_t i = 1; i + 1 < sizeof lengths / sizeof lengths[0]; i++) {
        p = f.response;
        CHECK(feed(&p, lengths[i].op, d, lengths[i].n, 0, 101) == SLE_PAIR_ERR_STATE);
        failed(&p, SLE_PAIR_ERR_STATE, 1);
    }
    p = f.ready; CHECK(sle_pair_start(&p, 100) == 0);
    CHECK(feed(&p, 0x0135, response, 10, 0, 101) == SLE_PAIR_ERR_STATE);
    failed(&p, SLE_PAIR_ERR_STATE, 1); /* request never popped */
    p = f.ready; d[0] = 5;
    CHECK(feed(&p, 0x0133, d, 1, 0, 100) == 0);
    pop(&p, 0x0134, 10, 0);
    CHECK(feed(&p, 0x0133, d, 1, 1, 101) == SLE_PAIR_ERR_STATE);
    for (int i = 0; i < 2; i++) {
        p = f.dh; d[0] = 8;
        CHECK(feed(&p, i ? 0x0147 : 0x01ff, d, 1, 0, 200) == SLE_PAIR_ERR_REMOTE);
        CHECK(p.remote_reason == 8); failed(&p, SLE_PAIR_ERR_REMOTE, 0);
    }
    p = f.dh; d[0] = 0;
    CHECK(feed(&p, 0x01ff, d, 1, 0, 200) == SLE_PAIR_ERR_PARAMETER);
    p = f.dh; hex(v_tcheck, d); d[7] ^= 1;
    CHECK(feed(&p, 0x0142, d, 16, 0, 106) == SLE_PAIR_ERR_DHKEY);
    CHECK(p.failure_reason == 8); failed(&p, SLE_PAIR_ERR_DHKEY, 1);
    /* Optional JW confirm diagnostic never replaces mandatory DH check. */
    p = f.confirm; memset(d, 0, 16);
    CHECK(feed(&p, 0x0138, d, 16, 0, 104) == 0); pop(&p, 0x0139, 16, 0);
    for (int i = 0; i < 16; i++) d[i] = (uint8_t)(0x40 + i);
    CHECK(feed(&p, 0x013a, d, 16, 1, 105) == 0); pop(&p, 0x0141, 16, 0);
    CHECK(p.confirm_matches == 0);
    hex(v_tcheck, d); CHECK(feed(&p, 0x0142, d, 16, 0, 106) == 0);
    pop(&p, 4, 13, 0);
    /* Bind DH authentication to configured address and negotiated IO. */
    p = f.rb; p.cfg.g_addr[0] ^= 1;
    for (int i = 0; i < 16; i++) d[i] = (uint8_t)(0x40 + i);
    CHECK(feed(&p, 0x013a, d, 16, 1, 105) == 0); pop(&p, 0x0141, 16, 0);
    hex(v_tcheck, d); CHECK(feed(&p, 0x0142, d, 16, 0, 106) == SLE_PAIR_ERR_DHKEY);
    p = f.rb; p.peer_io = 1;
    for (int i = 0; i < 16; i++) d[i] = (uint8_t)(0x40 + i);
    CHECK(feed(&p, 0x013a, d, 16, 1, 105) == 0); pop(&p, 0x0141, 16, 0);
    hex(v_tcheck, d); CHECK(feed(&p, 0x0142, d, 16, 0, 106) == SLE_PAIR_ERR_DHKEY);
    puts("peer/feature/format/state/DH verification: PASS");
}

static void worker_and_timeout(void)
{
    sle_pair_t p; sle_pair_work_t w; sle_pair_work_result_t r;
    uint8_t d[80];
    for (int i = 0; i < 2; i++) {
        p = f.public_key; memset(d, i ? 0xff : 0, 64);
        CHECK(feed(&p, 0x0137, d, 64, 1, 102) == 0);
        CHECK(sle_pair_take_work(&p, &w) == 0);
        CHECK(sle_pair_run_work(&w, &r) == SLE_PAIR_ERR_PUBLIC_KEY);
        CHECK(sle_pair_finish_work(&p, &r, 103) == SLE_PAIR_ERR_PUBLIC_KEY);
        CHECK(zero(&r, sizeof r) && zero(&w, sizeof w));
        failed(&p, SLE_PAIR_ERR_PUBLIC_KEY, 1);
    }
    p = f.public_key; memcpy(d, p.public_le, 64);
    CHECK(feed(&p, 0x0137, d, 64, 1, 102) == SLE_PAIR_ERR_PUBLIC_KEY);
    /* Early 0138 is buffered; curve validation/ECDH still mandatory. */
    p = f.ecdh; CHECK(sle_pair_take_work(&p, &w) == 0);
    hex(v_confirm, d); CHECK(feed(&p, 0x0138, d, 16, 0, 103) == 0);
    sle_pair_pdu_t b; CHECK(sle_pair_pop(&p, &b) == 0);
    CHECK(sle_pair_take_work(&p, &(sle_pair_work_t){0}) == SLE_PAIR_ERR_STATE);
    CHECK(sle_pair_run_work(&w, &r) == 0);
    CHECK(sle_pair_finish_work(&p, &r, 104) == 0);
    pop(&p, 0x0139, 16, 0); CHECK(p.state == SLE_PAIR_WAIT_RB);
    p = f.ecdh; CHECK(sle_pair_take_work(&p, &w) == 0);
    CHECK(sle_pair_run_work(&w, &r) == 0); r.cookie[0] ^= 1;
    CHECK(sle_pair_finish_work(&p, &r, 103) == SLE_PAIR_ERR_STATE);
    CHECK(zero(&r, sizeof r) && p.state == SLE_PAIR_WAIT_ECDH);
    CHECK(sle_pair_tick(&p, 5102) == SLE_PAIR_ERR_TIMEOUT);
    failed(&p, SLE_PAIR_ERR_TIMEOUT, 1);
    p = f.ecdh; CHECK(sle_pair_take_work(&p, &w) == 0);
    CHECK(sle_pair_run_work(&w, &r) == 0);
    CHECK(sle_pair_finish_work(&p, &r, 5102) == SLE_PAIR_ERR_TIMEOUT);
    CHECK(zero(&r, sizeof r)); failed(&p, SLE_PAIR_ERR_TIMEOUT, 1);
    p = f.ecdh; CHECK(sle_pair_take_work(&p, &w) == 0);
    rng_bad = 1; CHECK(sle_pair_run_work(&w, &r) == SLE_PAIR_ERR_RNG); rng_bad = 0;
    CHECK(sle_pair_finish_work(&p, &r, 103) == SLE_PAIR_ERR_RNG);
    failed(&p, SLE_PAIR_ERR_RNG, 1);
    sle_pair_config_t cfg = config();
    CHECK(sle_pair_init(&p, &cfg) == 0);
    rng_bad = 1; CHECK(sle_pair_prepare(&p) == SLE_PAIR_ERR_RNG); rng_bad = 0;
    failed(&p, SLE_PAIR_ERR_RNG, 0);
    cfg.rng = NULL; CHECK(sle_pair_init(&p, &cfg) == SLE_PAIR_ERR_ARGUMENT);
    cfg = config(); memcpy(cfg.t_addr, cfg.g_addr, 6);
    CHECK(sle_pair_init(&p, &cfg) == SLE_PAIR_ERR_ARGUMENT);
    cfg = config(); cfg.rng = reject_nonce_rng;
    CHECK(sle_pair_init(&p, &cfg) == 0);
    CHECK(sle_pair_prepare(&p) == SLE_PAIR_ERR_RNG);
    failed(&p, SLE_PAIR_ERR_RNG, 0);
    /* A different user of sle_crypto's global RNG cannot hijack pair RNG. */
    sle_crypto_set_rng(reject_rng, NULL);
    cfg = config(); CHECK(sle_pair_init(&p, &cfg) == 0 && sle_pair_prepare(&p) == 0);
    p = f.ecdh; CHECK(sle_pair_take_work(&p, &w) == 0);
    CHECK(sle_pair_run_work(&w, &r) == 0);
    CHECK(sle_pair_finish_work(&p, &r, 103) == 0);
    sle_crypto_set_rng(NULL, NULL);
    p = f.response; CHECK(sle_pair_tick(&p, 5099) == 0);
    CHECK(sle_pair_tick(&p, 5100) == SLE_PAIR_ERR_TIMEOUT); failed(&p, SLE_PAIR_ERR_TIMEOUT, 1);
    p = f.response; CHECK(sle_pair_tick(&p, 99) == SLE_PAIR_ERR_CLOCK); failed(&p, SLE_PAIR_ERR_CLOCK, 1);
    p = f.dh; p.cfg.total_timeout_ms = 6;
    CHECK(sle_pair_tick(&p, 106) == SLE_PAIR_ERR_TIMEOUT);
    p = f.ack; CHECK(sle_pair_tick(&p, 5108) == SLE_PAIR_ERR_TIMEOUT); failed(&p, SLE_PAIR_ERR_TIMEOUT, 0);
    p = f.ready; CHECK(sle_pair_start(&p, UINT64_MAX - 5000) == 0); pop(&p, 0x0134, 10, 0);
    CHECK(sle_pair_tick(&p, UINT64_MAX) == SLE_PAIR_ERR_TIMEOUT);
    sle_pair_t *waiting[] = {&f.response, &f.public_key, &f.ecdh, &f.confirm,
        &f.rb, &f.dh, &f.security_response, &f.start, &f.ack};
    for (size_t i = 0; i < sizeof waiting / sizeof waiting[0]; i++) {
        p = *waiting[i];
        CHECK(sle_pair_tick(&p, p.step_ms + 5000) == SLE_PAIR_ERR_TIMEOUT);
        failed(&p, SLE_PAIR_ERR_TIMEOUT, i != 8);
    }
    /* Plaintext retries do not enqueue again or restart timers. */
    p = f.rb; d[0] = 0x38; d[1] = 1; d[2] = 16; hex(v_confirm, d + 3);
    CHECK(sle_pair_on_control(&p, ta, d, 19, 0, 1, 105) == SLE_PAIR_DUPLICATE);
    CHECK(sle_pair_pop(&p, &b) == 0 && p.step_ms == 104);
    d[3] ^= 1;
    CHECK(sle_pair_on_control(&p, ta, d, 19, 0, 1, 106) == SLE_PAIR_ERR_SEQUENCE);
    cfg = config(); cfg.rng = os_rng;
    sle_pair_t p2;
    CHECK(sle_pair_init(&p, &cfg) == 0 && sle_pair_prepare(&p) == 0);
    CHECK(sle_pair_init(&p2, &cfg) == 0 && sle_pair_prepare(&p2) == 0);
    CHECK(memcmp(p.public_le, p2.public_le, 64) != 0 && memcmp(p.ra, p2.ra, 16) != 0);
    sle_pair_clear(&p); sle_pair_clear(&p2);
    puts("worker isolation/invalid curves/RNG/timeout: PASS");
}

static size_t peer_encrypt(const sle_pair_t *p, const uint8_t *plain, size_t len,
                            uint64_t counter, uint8_t *out)
{
    uint8_t n[13], aad = 0;
    for (int i = 0; i < 5; i++) n[i] = (uint8_t)(counter >> (8 * i));
    memcpy(n + 5, p->cipher.iv, 8);
    CHECK(sle_aes_ccm_encrypt(p->cipher.key, n, 13, &aad, 1, plain, len, out, out + len, 4) == 0);
    return len + 4;
}
static void security_start(void)
{
    sle_pair_t p;
    uint8_t d[80], out[80]; size_t n;
    p = f.start;
    CHECK(feed(&p, 7, NULL, 0, 0, 108) == SLE_PAIR_ERR_STATE); failed(&p, SLE_PAIR_ERR_STATE, 1);
    p = f.ack;
    CHECK(feed(&p, 7, NULL, 0, 1, 109) == SLE_PAIR_ERR_LENGTH); failed(&p, SLE_PAIR_ERR_LENGTH, 0);
    p = f.ack; /* Peer cannot complete startup before G has protected 0007. */
    n = hex(v_tstart, d);
    CHECK(sle_pair_on_control(&p, ta, d, n, 1, 0, 109) == SLE_PAIR_ERR_STATE);
    failed(&p, SLE_PAIR_ERR_STATE, 0);
    p = f.ack;
    CHECK(sle_pair_protect(&p, (const uint8_t *)"app", 3, 0, 0, out, sizeof out, &n) == SLE_PAIR_ERR_STATE);
    failed(&p, SLE_PAIR_ERR_STATE, 0);
    p = f.ack; n = hex(v_tdata, d);
    CHECK(sle_pair_unprotect(&p, d, n, 1, 0, out, sizeof out, &n) == SLE_PAIR_ERR_STATE);
    CHECK(p.state == SLE_PAIR_WAIT_SECURITY_ACK);
    /* Exact plaintext 0006 retry at the boundary is safe, with no counters. */
    p = f.ack; d[0] = 6; d[1] = d[2] = 0;
    CHECK(sle_pair_on_control(&p, ta, d, 3, 0, 1, 109) == SLE_PAIR_DUPLICATE);
    CHECK(p.cipher.rx_next == 0 && p.step_ms == 108);
    CHECK(sle_pair_protect(&p, (const uint8_t *)"\x07\0\0", 3, 0, 0, out, sizeof out, &n) == 0);
    n = hex(v_tstart, d); d[6] ^= 1;
    CHECK(sle_pair_on_control(&p, ta, d, n, 1, 0, 110) == SLE_PAIR_ERR_MIC); failed(&p, SLE_PAIR_ERR_MIC, 0);
    p = f.ack;
    CHECK(sle_pair_protect(&p, (const uint8_t *)"\x07\0\0", 3, 0, 0, out, sizeof out, &n) == 0);
    n = peer_encrypt(&p, (const uint8_t *)"\x07\0\x01\0", 4, 0, d);
    CHECK(sle_pair_on_control(&p, ta, d, n, 1, 0, 109) == SLE_PAIR_ERR_LENGTH);
    /* Wrong session key/IV candidate fails visibly at encrypted 0007. */
    p = f.ack; p.cipher.iv[0] ^= 1;
    CHECK(sle_pair_protect(&p, (const uint8_t *)"\x07\0\0", 3, 0, 0, out, sizeof out, &n) == 0);
    n = hex(v_tstart, d);
    CHECK(sle_pair_on_control(&p, ta, d, n, 1, 0, 109) == SLE_PAIR_ERR_MIC);
    puts("plaintext/CCM switch and authenticated 0007: PASS");
}

static void data_channel(void)
{
    sle_pair_t p = f.encrypted;
    const uint8_t msg[] = "hello SLE";
    uint8_t wire[SLE_PAIR_WIRE_MAX], out[SLE_PAIR_WIRE_MAX], previous[32];
    size_t n = 123, got;
    CHECK(sle_pair_protect(&p, msg, 9, 1, 0, wire, 12, &n) == SLE_PAIR_ERR_BUFFER);
    CHECK(n == 0 && p.cipher.tx_next == 1);
    CHECK(sle_pair_protect(&p, msg, 9, 1, 0, wire, sizeof wire, &n) == 0);
    is_hex(wire, n, v_gdata); memcpy(previous, wire, n);
    CHECK(p.cipher.tx_next == 2);
    CHECK(sle_pair_protect(&p, NULL, 0, 0, 0, NULL, 0, &got) == 0 && got == 0);
    CHECK(sle_pair_protect(&p, msg, 9, 1, 1, wire, sizeof wire, &n) == 0);
    CHECK(memcmp(wire, previous, n) == 0 && p.cipher.tx_next == 2);
    got = hex(v_tdata, wire);
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 0, out, 8, &n) == SLE_PAIR_ERR_BUFFER);
    CHECK(n == 0 && p.cipher.rx_next == 1);
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 0, out, sizeof out, &n) == 0);
    CHECK(n == 9 && memcmp(out, msg, n) == 0 && p.cipher.rx_next == 2);
    CHECK(sle_pair_unprotect(&p, NULL, 0, 0, 1, NULL, 0, &n) == 0 && n == 0);
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 1, out, sizeof out, &n) == SLE_PAIR_DUPLICATE);
    CHECK(n == 0 && p.cipher.rx_next == 2);
    sle_pair_t saved = p;
    memset(out, 0xa5, sizeof out); wire[got - 1] ^= 1;
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 1, out, sizeof out, &n) == SLE_PAIR_ERR_MIC);
    CHECK(n == 0 && out[0] == 0xa5); failed(&p, SLE_PAIR_ERR_MIC, 0);
    /* Even a different valid ciphertext at the previous counter is NOT a
     * retransmission of the delivered payload. */
    p = saved;
    got = peer_encrypt(&p, (const uint8_t *)"other SLE", 9, 1, wire);
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 1, out, sizeof out, &n) == SLE_PAIR_ERR_SEQUENCE);
    failed(&p, SLE_PAIR_ERR_SEQUENCE, 0);
    p = saved;
    CHECK(sle_pair_protect(&p, (const uint8_t *)"other SLE", 9, 1, 1, wire, sizeof wire, &n) == SLE_PAIR_ERR_SEQUENCE);
    p = f.encrypted;
    CHECK(sle_pair_protect(&p, msg, 9, 0, 0, wire, sizeof wire, &n) == SLE_PAIR_ERR_SEQUENCE);
    p = f.encrypted;
    got = hex(v_tdata, wire);
    CHECK(sle_pair_unprotect(&p, wire, got, 1, 0, out, sizeof out, &n) == SLE_PAIR_ERR_SEQUENCE);
    p = f.encrypted;
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 1, out, sizeof out, &n) == SLE_PAIR_ERR_SEQUENCE);
    /* Old startup ciphertext replay with next SN/counter cannot authenticate. */
    p = f.encrypted; got = hex(v_tstart, wire);
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 0, out, sizeof out, &n) == SLE_PAIR_ERR_MIC);
    /* AAD=zero bytes is a DIFFERENT CCM construction from AAD={0x00}. */
    p = f.encrypted;
    uint8_t nonce[13] = {1,0,0,0,0}; memcpy(nonce + 5, p.cipher.iv, 8);
    CHECK(sle_aes_ccm_encrypt(p.cipher.key, nonce, 13, NULL, 0, msg, 9, wire, wire + 9, 4) == 0);
    CHECK(sle_pair_unprotect(&p, wire, 13, 0, 0, out, sizeof out, &n) == SLE_PAIR_ERR_MIC);
    for (size_t i = 1; i <= 4; i++) {
        p = f.encrypted;
        CHECK(sle_pair_unprotect(&p, wire, i, 0, 0, out, sizeof out, &n) == SLE_PAIR_ERR_LENGTH);
    }
    /* Exact maximum 39-bit nonce and exhaustion, including final retry. */
    p = f.encrypted; p.cipher.tx_next = SLE_PAIR_COUNTER_LIMIT - 1;
    CHECK(sle_pair_protect(&p, msg, 9, 1, 0, wire, sizeof wire, &n) == 0);
    is_hex(wire, n, v_glast);
    CHECK(sle_pair_protect(&p, msg, 9, 1, 1, wire, sizeof wire, &n) == 0);
    is_hex(wire, n, v_glast); CHECK(p.cipher.tx_next == SLE_PAIR_COUNTER_LIMIT);
    CHECK(sle_pair_protect(&p, msg, 9, 0, 0, wire, sizeof wire, &n) == SLE_PAIR_ERR_COUNTER);
    failed(&p, SLE_PAIR_ERR_COUNTER, 0);
    p = f.encrypted; p.cipher.rx_next = SLE_PAIR_COUNTER_LIMIT - 1;
    got = hex(v_tlast, wire);
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 0, out, sizeof out, &n) == 0);
    CHECK(n == 9 && memcmp(out, msg, 9) == 0);
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 1, out, sizeof out, &n) == SLE_PAIR_DUPLICATE);
    CHECK(p.cipher.rx_next == SLE_PAIR_COUNTER_LIMIT);
    CHECK(sle_pair_unprotect(&p, wire, got, 1, 0, out, sizeof out, &n) == SLE_PAIR_ERR_COUNTER);
    failed(&p, SLE_PAIR_ERR_COUNTER, 0);
    /* Overlap and maximum PHY length; no unauthenticated output on failure. */
    p = f.encrypted; memcpy(wire, msg, 9);
    CHECK(sle_pair_protect(&p, wire, 9, 1, 0, wire, sizeof wire, &n) == 0);
    is_hex(wire, n, v_gdata);
    got = hex(v_tdata, wire);
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 0, wire, sizeof wire, &n) == 0);
    CHECK(n == 9 && memcmp(wire, msg, 9) == 0);
    p = f.encrypted; memset(out, 0x55, sizeof out);
    CHECK(sle_pair_protect(&p, out, SLE_PAIR_PLAIN_MAX + 1, 1, 0, wire, sizeof wire, &n) == SLE_PAIR_ERR_LENGTH);
    CHECK(p.cipher.tx_next == 1);
    CHECK(sle_pair_protect(&p, out, SLE_PAIR_PLAIN_MAX, 1, 0, wire, sizeof wire, &n) == 0);
    CHECK(n == SLE_PAIR_WIRE_MAX);
    got = peer_encrypt(&p, out, SLE_PAIR_PLAIN_MAX, 1, wire);
    CHECK(sle_pair_unprotect(&p, wire, got, 0, 0, out, sizeof out, &n) == 0);
    CHECK(n == SLE_PAIR_PLAIN_MAX && out[0] == 0x55 && out[n - 1] == 0x55);
    puts("CCM vectors/MIC/retry/duplicate/empty/counter/length: PASS");
}

static void unified_control(void)
{
    const uint8_t ordinary[] = {0x20,0,0};
    const uint8_t disconnect[] = {0x1e,0,4,0x75,0xa2,0x66,0x13};
    const uint8_t ack[] = {7,0,0}, start[] = {6,0,0};
    uint8_t wire[262], out[258], saved_ctrl[SLE_PAIR_CTRL_MAX];
    size_t n, got = 999;
    int is_pair = 99;
    sle_pair_t p = f.rb;
    size_t last_len = p.last_ctrl_len;
    memcpy(saved_ctrl, p.last_ctrl, sizeof saved_ctrl);
    uint64_t step = p.step_ms;
    CHECK(sle_pair_on_control_ex(&p, ta, ordinary, sizeof ordinary, 1, 0, 105,
                                 out, sizeof out, &got, &is_pair) == 0);
    CHECK(!is_pair && got == 3 && !memcmp(out, ordinary, 3));
    CHECK(p.state == SLE_PAIR_WAIT_RB && p.step_ms == step && p.last_ctrl_len == last_len);
    CHECK(!memcmp(saved_ctrl, p.last_ctrl, sizeof saved_ctrl) && !p.cipher.rx_next);
    CHECK(sle_pair_on_control_ex(&p, ta, ordinary, 3, 1, 1, 106,
                                 NULL, 0, &got, &is_pair) == SLE_PAIR_DUPLICATE);
    CHECK(!got && !is_pair);
    /* The earlier pair control is no longer the last RX, even though its
     * separate transcript remains intact. It cannot be replayed as a dup. */
    CHECK(sle_pair_on_control_ex(&p, ta, saved_ctrl, last_len, 0, 1, 107,
                                 out, sizeof out, &got, &is_pair) == SLE_PAIR_ERR_SEQUENCE);
    CHECK(!got && !is_pair); failed(&p, SLE_PAIR_ERR_SEQUENCE, 1);

    p = f.response;
    wire[0] = 0x35; wire[1] = 1; wire[2] = 10; memcpy(wire + 3, response, 10);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, 13, 0, 0, 101,
                                 out, 12, &got, &is_pair) == SLE_PAIR_ERR_BUFFER);
    CHECK(!got && !is_pair && p.state == SLE_PAIR_WAIT_RESPONSE && !p.pending);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, 13, 0, 0, 101,
                                 out, sizeof out, &got, &is_pair) == 0);
    CHECK(is_pair == 1 && got == 13 && !memcmp(wire, out, got));
    CHECK(p.state == SLE_PAIR_WAIT_PUBLIC_KEY && p.pending);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, 13, 0, 1, 102,
                                 NULL, 0, &got, &is_pair) == SLE_PAIR_DUPLICATE);
    CHECK(!got && is_pair == 1 && p.pending);
    CHECK(sle_pair_on_control_ex(&p, ta, ordinary, 3, 1, 0, 103,
                                 out, sizeof out, &got, &is_pair) == 0);
    CHECK(!is_pair && p.pending && p.state == SLE_PAIR_WAIT_PUBLIC_KEY);

    /* Valid generic controls during startup are authenticated and delivered
     * even when our startup response is still pending. No implicit advance. */
    p = f.start;
    CHECK(feed(&p, 6, NULL, 0, 0, 108) == 0 && p.pending);
    n = peer_encrypt(&p, disconnect, sizeof disconnect, 0, wire);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 1, 0, 109,
                                 out, sizeof out, &got, &is_pair) == 0);
    CHECK(got == sizeof disconnect && !memcmp(out, disconnect, got) && !is_pair);
    CHECK(p.state == SLE_PAIR_WAIT_SECURITY_ACK && p.pending && !p.start_sent && p.step_ms == 108);
    CHECK(p.cipher.rx_next == 1 && p.cipher.tx_next == 0);
    sle_pair_t after_generic = p;
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 1, 1, 110,
                                 out, sizeof out, &got, &is_pair) == SLE_PAIR_DUPLICATE);
    CHECK(!got && !is_pair && p.cipher.rx_next == 1);
    CHECK(sle_pair_on_control_ex(&p, ta, start, 3, 0, 1, 111,
                                 out, sizeof out, &got, &is_pair) == SLE_PAIR_ERR_LENGTH);
    CHECK(!got && !is_pair); /* plaintext exception retired by authenticated RX */
    p = after_generic;
    pop(&p, 7, 0, 1);
    CHECK(sle_pair_protect(&p, ack, 3, 0, 0, out, sizeof out, &got) == 0);
    n = peer_encrypt(&p, ack, 3, 1, wire);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 0, 111,
                                 out, sizeof out, &got, &is_pair) == 0);
    CHECK(is_pair == 1 && got == 3 && !memcmp(out, ack, got));
    CHECK(p.state == SLE_PAIR_ENCRYPTED && p.cipher.rx_next == 2 && p.cipher.tx_next == 1);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 1, 112,
                                 out, sizeof out, &got, &is_pair) == SLE_PAIR_DUPLICATE);
    CHECK(is_pair == 1 && !got && p.cipher.rx_next == 2);

    /* One CCM counter/ciphertext cache spans control -> data -> control.
     * Reinterpreting a duplicate's class is rejected after MIC validation. */
    p = f.encrypted;
    n = peer_encrypt(&p, ordinary, 3, 1, wire);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 0, 110,
                                 out, sizeof out, &got, &is_pair) == 0);
    CHECK(!is_pair && got == 3 && p.cipher.rx_next == 2);
    sle_pair_t cached_control = p;
    CHECK(sle_pair_unprotect(&p, wire, n, 0, 1, out, sizeof out, &got) == SLE_PAIR_ERR_SEQUENCE);
    p = cached_control;
    n = peer_encrypt(&p, (const uint8_t *)"data", 4, 2, wire);
    CHECK(sle_pair_unprotect(&p, wire, n, 1, 0, out, sizeof out, &got) == 0);
    CHECK(got == 4 && p.cipher.rx_next == 3);
    CHECK(sle_pair_unprotect(&p, wire, n, 1, 1, out, sizeof out, &got) == SLE_PAIR_DUPLICATE);
    CHECK(!got && p.cipher.rx_next == 3);
    sle_pair_t cached_data = p;
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 1, 1, 111,
                                 out, sizeof out, &got, &is_pair) == SLE_PAIR_ERR_SEQUENCE);
    CHECK(!got && !is_pair);
    p = cached_data;
    n = peer_encrypt(&p, ordinary, 3, 3, wire);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 0, 112,
                                 out, sizeof out, &got, &is_pair) == 0);
    CHECK(p.cipher.rx_next == 4 && !is_pair && got == 3);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 1, 113,
                                 NULL, 0, &got, &is_pair) == SLE_PAIR_DUPLICATE);
    CHECK(p.cipher.rx_next == 4 && !got && !is_pair);
    /* Same SN two PDUs later does not make an older control a valid dup. */
    n = peer_encrypt(&p, ordinary, 3, 1, wire);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 1, 114,
                                 out, sizeof out, &got, &is_pair) == SLE_PAIR_ERR_MIC);
    CHECK(!got && !is_pair); failed(&p, SLE_PAIR_ERR_MIC, 0);

    /* Any failed MIC or state/format check returns no deliverable plaintext,
     * so the caller must exit before ARQ (covered also by test_sle_g_runtime). */
    for (int startup_phase = 0; startup_phase < 2; startup_phase++) {
        for (int dup = 0; dup < 2; dup++) {
            p = startup_phase ? f.ack : f.encrypted;
            uint8_t sn = startup_phase ? 1 : 0;
            n = peer_encrypt(&p, disconnect, sizeof disconnect, p.cipher.rx_next, wire);
            if (dup) CHECK(sle_pair_on_control_ex(&p, ta, wire, n, sn, 0, 110,
                                                 out, sizeof out, &got, &is_pair) == 0);
            wire[n - 1] ^= 1;
            memset(out, 0xa5, sizeof out);
            CHECK(sle_pair_on_control_ex(&p, ta, wire, n, sn, dup, 111,
                                         out, sizeof out, &got, &is_pair) == SLE_PAIR_ERR_MIC);
            CHECK(!got && !is_pair);
            for (size_t i = 0; i < sizeof out; i++) CHECK(out[i] == 0xa5);
            failed(&p, SLE_PAIR_ERR_MIC, 0);
        }
    }
    for (int encrypted = 0; encrypted < 2; encrypted++) {
        for (unsigned op = 8; op <= 9; op++) {
            p = encrypted ? f.encrypted : f.response;
            uint8_t refresh[] = {(uint8_t)op,0,0};
            if (encrypted) n = peer_encrypt(&p, refresh, 3, 1, wire);
            else { memcpy(wire, refresh, 3); n = 3; }
            CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 0, 110,
                                         out, sizeof out, &got, &is_pair) == SLE_PAIR_ERR_UNSUPPORTED);
            CHECK(!got && !is_pair); failed(&p, SLE_PAIR_ERR_UNSUPPORTED, !encrypted);
        }
        p = encrypted ? f.encrypted : f.response;
        uint8_t malformed[] = {0x20,0,1};
        if (encrypted) n = peer_encrypt(&p, malformed, 3, 1, wire);
        else { memcpy(wire, malformed, 3); n = 3; }
        CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 0, 110,
                                     out, sizeof out, &got, &is_pair) == SLE_PAIR_ERR_LENGTH);
        CHECK(!got && !is_pair); failed(&p, SLE_PAIR_ERR_LENGTH, !encrypted);
    }
    p = f.encrypted;
    n = peer_encrypt(&p, ack, 3, 1, wire); /* a second startup, authenticated but illegal */
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 0, 110,
                                 out, sizeof out, &got, &is_pair) == SLE_PAIR_ERR_STATE);
    CHECK(!got && !is_pair); failed(&p, SLE_PAIR_ERR_STATE, 0);

    /* Full generic payload length is 255, not the pair generator's 70. */
    p = f.encrypted;
    memset(out, 0x55, sizeof out); out[0] = 0xfe; out[1] = 0x7f; out[2] = 255;
    n = peer_encrypt(&p, out, sizeof out, 1, wire);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 0, 110,
                                 out, 257, &got, &is_pair) == SLE_PAIR_ERR_BUFFER);
    CHECK(!got && !is_pair && p.cipher.rx_next == 1);
    CHECK(sle_pair_on_control_ex(&p, ta, wire, n, 0, 0, 110,
                                 wire, sizeof wire, &got, &is_pair) == 0);
    CHECK(!is_pair && got == 258 && !memcmp(wire, out, got) && p.cipher.rx_next == 2);
    p = f.encrypted;
    n = peer_encrypt(&p, ordinary, 3, 1, wire);
    CHECK(sle_pair_on_control(&p, ta, wire, n, 0, 0, 110) == 0); /* compatible wrapper */
    CHECK(p.cipher.rx_next == 2);
    puts("single-pass control routing/generic startup/ctrl-data cache/no failed-MIC output: PASS");
}

static void plain_counter_api(void)
{
    sle_pair_t p; sle_pair_config_t c=config();
    c.variant=SLE_PAIR_V_COUNT_PLAIN|SLE_PAIR_V_CTR1;
    CHECK(sle_pair_init(&p,&c)==SLE_PAIR_ERR_ARGUMENT);
    c.variant=0x400u;
    CHECK(sle_pair_init(&p,&c)==SLE_PAIR_ERR_ARGUMENT);
    c.variant=SLE_PAIR_V_COUNT_PLAIN|SLE_PAIR_V_KDF_ECB;
    CHECK(!sle_pair_init(&p,&c));
    CHECK(sle_pair_seed_plain_counters(&p,5,7)==SLE_PAIR_ERR_STATE);
    p.state=SLE_PAIR_WAIT_SECURITY_ACK; p.secure=1;
    CHECK(sle_pair_seed_plain_counters(&p,5,SLE_PAIR_COUNTER_LIMIT)==SLE_PAIR_ERR_COUNTER);
    CHECK(!p.cipher.counters_seeded && !p.cipher.tx_next && !p.cipher.rx_next);
    CHECK(!sle_pair_seed_plain_counters(&p,5,7));
    CHECK(p.cipher.tx_next==5 && p.cipher.rx_next==7);
    CHECK(sle_pair_seed_plain_counters(&p,0,0)==SLE_PAIR_ERR_STATE);
    CHECK(p.cipher.tx_next==5 && p.cipher.rx_next==7);
    sle_pair_clear(&p);
    for (unsigned v=0;v<=SLE_PAIR_V_KDF_ECB;v+=SLE_PAIR_V_KDF_ECB) {
        c.variant=v; CHECK(!sle_pair_init(&p,&c));
        p.state=SLE_PAIR_WAIT_SECURITY_ACK; p.secure=1;
        CHECK(sle_pair_seed_plain_counters(&p,5,7)==SLE_PAIR_ERR_STATE);
        CHECK(!p.cipher.tx_next && !p.cipher.rx_next);
    }
    sle_pair_clear(&p);
}

int main(void)
{
    happy_path(); validation(); worker_and_timeout(); security_start(); data_channel();
    unified_control(); plain_counter_api();
    printf("test_sle_pair: %u checks PASS\n", checks);
    return 0;
}
