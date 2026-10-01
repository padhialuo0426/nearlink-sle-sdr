/* sle_crypto.c - thin wrappers over upstream Mbed TLS 3.6.7; see sle_crypto.h. */
#include "sle_crypto.h"

#include <stdio.h>
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform_util.h"

static int urandom_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return n == len ? 0 : -1;
}

static sle_crypto_rng_t g_rng = urandom_rng;
static void *g_rng_ctx;

void sle_crypto_set_rng(sle_crypto_rng_t rng, void *ctx)
{
    g_rng = rng ? rng : urandom_rng;
    g_rng_ctx = rng ? ctx : NULL;
}

int sle_aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int r = mbedtls_aes_setkey_enc(&aes, key, 128);
    if (!r) r = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&aes);
    return r ? -1 : 0;
}

int sle_aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t tag[16])
{
    const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (!info) return -1;
    return mbedtls_cipher_cmac(info, key, 128, msg, len, tag) ? -1 : 0;
}

int sle_aes_ccm_encrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t len,
                        uint8_t *ct, uint8_t *tag, size_t tag_len)
{
    mbedtls_ccm_context ccm;
    mbedtls_ccm_init(&ccm);
    int r = mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (!r) r = mbedtls_ccm_encrypt_and_tag(&ccm, len, nonce, nonce_len, aad, aad_len,
                                            pt, ct, tag, tag_len);
    mbedtls_ccm_free(&ccm);
    return r ? -1 : 0;
}

int sle_aes_ccm_decrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t len,
                        const uint8_t *tag, size_t tag_len, uint8_t *pt)
{
    mbedtls_ccm_context ccm;
    mbedtls_ccm_init(&ccm);
    int r = mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (!r) r = mbedtls_ccm_auth_decrypt(&ccm, len, nonce, nonce_len, aad, aad_len,
                                         ct, pt, tag, tag_len);
    mbedtls_ccm_free(&ccm);
    return r ? -1 : 0;
}

static int load_group(mbedtls_ecp_group *grp)
{
    mbedtls_ecp_group_init(grp);
    return mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
}

static int load_point(const mbedtls_ecp_group *grp, mbedtls_ecp_point *q,
                      const uint8_t x[32], const uint8_t y[32])
{
    uint8_t buf[65];
    buf[0] = 0x04;                      /* SEC1 uncompressed */
    memcpy(buf + 1, x, 32);
    memcpy(buf + 33, y, 32);
    int r = mbedtls_ecp_point_read_binary(grp, q, buf, sizeof buf);
    if (!r) r = mbedtls_ecp_check_pubkey(grp, q);
    return r;
}

static int store_point(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *q,
                       uint8_t x[32], uint8_t y[32])
{
    uint8_t buf[65];
    size_t n = 0;
    int r = mbedtls_ecp_point_write_binary(grp, q, MBEDTLS_ECP_PF_UNCOMPRESSED, &n, buf, sizeof buf);
    if (r || n != 65) return -1;
    memcpy(x, buf + 1, 32);
    memcpy(y, buf + 33, 32);
    return 0;
}

int sle_p256_public_key(const uint8_t priv[32], uint8_t x[32], uint8_t y[32])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);
    int r = load_group(&grp);
    if (!r) r = mbedtls_mpi_read_binary(&d, priv, 32);
    if (!r) r = mbedtls_ecp_check_privkey(&grp, &d);
    if (!r) r = mbedtls_ecp_mul(&grp, &q, &d, &grp.G, g_rng, g_rng_ctx);
    if (!r) r = store_point(&grp, &q, x, y);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return r ? -1 : 0;
}

int sle_p256_keygen(uint8_t priv[32], uint8_t x[32], uint8_t y[32])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);
    int r = load_group(&grp);
    if (!r) r = mbedtls_ecp_gen_keypair(&grp, &d, &q, g_rng, g_rng_ctx);
    if (!r) r = mbedtls_mpi_write_binary(&d, priv, 32);
    if (!r) r = store_point(&grp, &q, x, y);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return r ? -1 : 0;
}

int sle_p256_valid_point(const uint8_t x[32], const uint8_t y[32])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_ecp_point_init(&q);
    int r = load_group(&grp);
    if (!r) r = load_point(&grp, &q, x, y);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return r == 0;
}

int sle_p256_ecdh(const uint8_t priv[32], const uint8_t px[32], const uint8_t py[32],
                  uint8_t shared_x[32])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point q;
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&q);
    int r = load_group(&grp);
    if (!r) r = mbedtls_mpi_read_binary(&d, priv, 32);
    if (!r) r = mbedtls_ecp_check_privkey(&grp, &d);
    if (!r) r = load_point(&grp, &q, px, py);
    if (!r) r = mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, g_rng, g_rng_ctx);
    if (!r) r = mbedtls_mpi_write_binary(&z, shared_x, 32);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return r ? -1 : 0;
}

int sle_crypto_selftest(int verbose)
{
    int fails = 0;
    fails += mbedtls_aes_self_test(verbose) != 0;
    fails += mbedtls_cmac_self_test(verbose) != 0;
    fails += mbedtls_ccm_self_test(verbose) != 0;
    fails += mbedtls_ecp_self_test(verbose) != 0;
    return fails;
}
