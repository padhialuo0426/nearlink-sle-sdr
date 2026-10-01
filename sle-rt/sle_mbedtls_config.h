/* sle_mbedtls_config.h - minimal Mbed TLS 3.6.7 configuration for sle_crypto.
 *
 * Upstream: deps/mbedtls-3.6.7, pinned in deps/dependencies.json.
 * The upstream source is compiled unmodified with
 * -DMBEDTLS_CONFIG_FILE='"sle_mbedtls_config.h"'. Only what GB/T 46803.2
 * ch. 7 suite AC2/HA2/KE2 needs: AES-128, AES-CMAC, AES-CCM, ECDH P-256.
 * No TLS, no X.509, no PSA, no platform entropy (the caller supplies an RNG).
 */
#ifndef SLE_MBEDTLS_CONFIG_H
#define SLE_MBEDTLS_CONFIG_H

#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C          /* required by CMAC */
#define MBEDTLS_CMAC_C
#define MBEDTLS_CCM_C

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDH_C

#define MBEDTLS_SELF_TEST         /* library self-tests with its own NIST/RFC vectors */

#endif /* SLE_MBEDTLS_CONFIG_H */
