/* sle_crypto.h - primitives of GB/T 46803.2-2025 ch. 7 suite AC2/HA2/KE2
 * (AES-CCM, AES-CMAC, ECDH P-256) as thin wrappers over unmodified upstream
 * Mbed TLS 3.6.7 (../deps/,  configuration sle_mbedtls_config.h). No
 * cryptographic algorithm is implemented in this project.
 *
 * Byte strings keep the convention of each specification (RFC 4493 message
 * order, SP 800-38C CCM, SEC1 big-endian P-256 coordinates). SLE-specific
 * byte ordering is applied by the protocol layer, never here.
 */
#ifndef SLE_CRYPTO_H
#define SLE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Random source used for ECC blinding and key generation: fill buf with len
 * random bytes, return 0 on success. Default: /dev/urandom. */
typedef int (*sle_crypto_rng_t)(void *ctx, unsigned char *buf, size_t len);
void sle_crypto_set_rng(sle_crypto_rng_t rng, void *ctx);

/* AES-128 single block, AES-CMAC (16-byte tag). Return 0 or -1. */
int sle_aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
int sle_aes_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t tag[16]);

/* AES-CCM with tag_len 4..16 (even) and nonce_len 7..13. Decrypt returns 0
 * when the tag verifies, -1 otherwise (output cleared). */
int sle_aes_ccm_encrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t len,
                        uint8_t *ct, uint8_t *tag, size_t tag_len);
int sle_aes_ccm_decrypt(const uint8_t key[16], const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t len,
                        const uint8_t *tag, size_t tag_len, uint8_t *pt);

/* ECDH P-256, 32-byte big-endian scalars and coordinates. */
int sle_p256_keygen(uint8_t priv[32], uint8_t x[32], uint8_t y[32]);
int sle_p256_public_key(const uint8_t priv[32], uint8_t x[32], uint8_t y[32]);
int sle_p256_valid_point(const uint8_t x[32], const uint8_t y[32]);
int sle_p256_ecdh(const uint8_t priv[32], const uint8_t px[32], const uint8_t py[32],
                  uint8_t shared_x[32]);

/* Run the Mbed TLS self-tests of the enabled modules (AES, CMAC, CCM, ECP).
 * Returns 0 when all pass. */
int sle_crypto_selftest(int verbose);

#ifdef __cplusplus
}
#endif
#endif /* SLE_CRYPTO_H */
