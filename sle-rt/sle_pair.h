/* G-role WS63 Just Works / AC2-AC2-HA2-KE2, frame types 1/2 only.
 * Evidence: logs/p2-20260925/gbt46803-2/part-I-ch7-security.md, §§6,9.
 *
 * WS63 interoperable profile (G pairing RF validation, 2026-09-27):
 * - P-256 X/Y, DH x and MAC addresses use little-endian wire byte strings.
 * - CMAC_reverse(K,M) = reverse(CMAC(reverse(K),reverse(M))). Link/DK
 *   messages start with memory bytes "kl"/"kd" (SDK disassembly).
 * - Session SK_le = reverse(AES(reverse(LinkKey_le), reverse(GSKD||TSKD)));
 *   CCM AES key = reverse(SK_le). IV = GIV||TIV with its first four bytes
 *   XOR sync_low32 in LE. This WS63 profile is not a claim about all SLE suites.
 * - CCM: MIC4, nonce13, AAD ONE byte 0x00 (not zero bytes of AAD); counter
 *   LE39 + direction in bit39 (G TX=1), then IV. Counters inherit this
 *   connection's accepted nonempty plaintext PDU counts before switching.
 * - Physical empty frames have no MIC/counter/SN and preserve retry caches;
 *   a 3-byte control 07 00 00 IS NOT empty. Cached retries do not advance counts.
 * - SLE_PAIR_PROFILE_WS63 selects this profile. Explicit variant 0 retains
 *   the historical CMAC session derivation/zero-counter hypothesis for replay.
 *
 * No bonding persistence, IRK/address distribution, PSK, OOB, SM suites or
 * refresh. AuthReq=0x05 follows the recorded SDK default; despite its MITM
 * bit this profile is Just Works and provides NO MITM authentication.
 *
 * Integration (all p calls serialized on the connection owner thread):
 *   cfg.variant = SLE_PAIR_PROFILE_WS63;
 *   sle_pair_init(&p, &cfg); sle_pair_prepare(&p); // before starting radio
 *   sle_pair_start(&p, now_ms);
 *   while (sle_pair_pop(&p, &owned) == 1) { ... }
 * pop copies plaintext into caller-owned storage. Keep it alive through ARQ
 * acknowledgement; for owned.encrypted, call protect at the FIRST actual
 * transmission (SN known), then retx=1 for retries. Copy/retain the returned
 * wire bytes as needed by sle_link_push; do not encrypt them twice.
 * For COUNT_PLAIN, count unique submitted plaintext TX and accepted plaintext
 * RX (including 0006), then seed_plain_counters after accepted 0006 and before
 * any protected PDU. The sle_g_runtime adapter owns this accounting.
 *
 * Route received control WIRE bytes (including MIC if RX is secure) to
 * on_control_ex, data wire bytes to unprotect. Do NOT pre-decrypt controls.
 * Derive duplicate from the pre-update ARQ state, authenticate BEFORE
 * advancing RX NESN/delivering. Duplicates still require MIC verification.
 * After 0137: take_work on owner, run_work on a worker, finish_work on owner.
 * 0138 may be buffered while the worker runs. Worker must not touch p.
 * Physical empty frames bypass on_control (it requires a control PDU).
 * Tick using monotonic milliseconds even while idle in radio events. No
 * time reads, I/O, logging, or ARQ retries occur here. Mbed TLS allocates
 * during crypto calls; prepare and run_work can take milliseconds on ARM.
 *
 * RNG is REQUIRED: caller supplies fresh OS randomness, returns 0 iff the
 * entire request is filled. Its context must outlive outstanding work.
 * Never use deterministic test RNGs in production. Join/cancel and clear
 * work/results before freeing RNG state/reinitializing. All structs contain
 * secrets: never log/dump/copy them except the documented work transfer.
 */
#ifndef SLE_PAIR_H
#define SLE_PAIR_H

#include <stddef.h>
#include <stdint.h>
#include "sle_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLE_PAIR_CTRL_MAX 73u
#define SLE_PAIR_CTRL_INPUT_MAX 258u /* any control: opcode2 + length1 + data255 */
#define SLE_PAIR_WIRE_MAX 2047u
#define SLE_PAIR_PLAIN_MAX (SLE_PAIR_WIRE_MAX - 4u)
#define SLE_PAIR_COUNTER_LIMIT (UINT64_C(1) << 39)

typedef enum {
    SLE_PAIR_UNINITIALIZED, SLE_PAIR_IDLE, SLE_PAIR_READY,
    SLE_PAIR_WAIT_RESPONSE, SLE_PAIR_WAIT_PUBLIC_KEY, SLE_PAIR_WAIT_ECDH,
    SLE_PAIR_WAIT_CONFIRM, SLE_PAIR_WAIT_RB, SLE_PAIR_WAIT_DHKEY,
    SLE_PAIR_WAIT_SECURITY_RESPONSE, SLE_PAIR_WAIT_SECURITY_START,
    SLE_PAIR_WAIT_SECURITY_ACK, SLE_PAIR_ENCRYPTED, SLE_PAIR_FAILED
} sle_pair_state_t;

enum {
    SLE_PAIR_OK = 0, SLE_PAIR_DUPLICATE = 1,
    SLE_PAIR_ERR_ARGUMENT = -1, SLE_PAIR_ERR_STATE = -2,
    SLE_PAIR_ERR_TIMEOUT = -3, SLE_PAIR_ERR_IDENTITY = -4,
    SLE_PAIR_ERR_LENGTH = -5, SLE_PAIR_ERR_PARAMETER = -6,
    SLE_PAIR_ERR_UNSUPPORTED = -7, SLE_PAIR_ERR_PUBLIC_KEY = -8,
    SLE_PAIR_ERR_RNG = -9, SLE_PAIR_ERR_CRYPTO = -10,
    SLE_PAIR_ERR_DHKEY = -11, SLE_PAIR_ERR_REMOTE = -12,
    SLE_PAIR_ERR_QUEUE = -13, SLE_PAIR_ERR_MIC = -14,
    SLE_PAIR_ERR_COUNTER = -15, SLE_PAIR_ERR_SEQUENCE = -16,
    SLE_PAIR_ERR_BUFFER = -17, SLE_PAIR_ERR_CLOCK = -18
};

typedef struct {
    uint8_t g_addr[6], t_addr[6]; /* exact bytes used in access PDUs */
    uint32_t sync_low32;        /* full sync low32, NOT truncated 24-bit LID */
    sle_crypto_rng_t rng;
    void *rng_ctx;
    uint64_t step_timeout_ms;   /* 0 => policy default 5000 */
    uint64_t total_timeout_ms;  /* 0 => policy default 30000 */
    unsigned variant;           /* explicit SLE_PAIR_V_* mask; use SLE_PAIR_PROFILE_WS63 for WS63 */
} sle_pair_config_t;

/* Historical diagnostic masks remain available for trace reproduction.
 * The named WS63 profile below passed protected 0007 and bidirectional SSAP;
 * other combinations are experiments, never automatic security fallbacks. */
#define SLE_PAIR_V_KEY_NOREV  0x01u /* AES key = SK_le as-is */
#define SLE_PAIR_V_SKD_TG     0x02u /* SKD = TSKD||GSKD */
#define SLE_PAIR_V_KDF_PLAIN  0x04u /* SK_le = CMAC(LinkKey_le, SKD), no reversal */
#define SLE_PAIR_V_SYNC_BE    0x08u /* IV[0..3] ^= sync_low32 big-endian */
#define SLE_PAIR_V_IV_TG      0x10u /* IV = TIV||GIV */
#define SLE_PAIR_V_MIC_REV    0x20u /* MIC bytes reversed on air */
#define SLE_PAIR_V_NONCE_REV  0x40u /* whole 13-byte nonce reversed */
#define SLE_PAIR_V_CTR1       0x80u /* first payload counter = 1 */
/* WS63 ROM g_encrypt_key_deriv_tab[1] runs ONE hardware AES block (not CMAC)
 * on the LE LinkKey/SKD buffers, the same path as BLE SK = e(LTK, SKD):
 * SK_le = reverse(AES(reverse(LinkKey_le), reverse(SKD))). */
#define SLE_PAIR_V_KDF_ECB    0x100u
#define SLE_PAIR_V_COUNT_PLAIN 0x200u /* inherit this connection's plaintext PDU counts */
#define SLE_PAIR_V_MASK       0x3ffu
#define SLE_PAIR_PROFILE_WS63 (SLE_PAIR_V_KDF_ECB | SLE_PAIR_V_COUNT_PLAIN)

typedef struct {
    uint8_t data[SLE_PAIR_CTRL_MAX]; /* owns bytes: 2B opcode LE + 1B len */
    size_t len;
    int encrypted;                 /* protect before handing to PHY */
} sle_pair_pdu_t;

typedef struct {
    uint8_t cookie[16], private_be[32], peer_le[64];
    sle_crypto_rng_t rng;
    void *rng_ctx;
    int valid;
} sle_pair_work_t;

typedef struct {
    uint8_t cookie[16], shared_le[32];
    int error, valid;
} sle_pair_work_result_t;

typedef struct {
    uint8_t key[16], iv[8];
    uint64_t tx_next, rx_next;
    uint8_t tx_sn, rx_sn;
    int tx_valid, rx_valid;
    int counters_seeded;
    int rx_control, rx_is_pair; /* classification of the shared RX cache */
    size_t tx_len, rx_len;
    uint8_t tx_plain[SLE_PAIR_PLAIN_MAX];
    uint8_t tx_wire[SLE_PAIR_WIRE_MAX], rx_wire[SLE_PAIR_WIRE_MAX];
} sle_pair_cipher_t;

/* Public layout for stack allocation only. Treat every member as private;
 * use status to inspect. Init/clear do not own or free cfg.rng_ctx. */
typedef struct {
    sle_pair_config_t cfg;
    sle_pair_state_t state;
    int error;
    uint8_t failure_reason, remote_reason;
    uint64_t start_ms, step_ms, last_ms;
    int active, secure, start_sent, pending, work_taken, have_confirm;
    int confirm_matches; /* -1 unknown; 0 mismatch; 1 match; diagnostic ONLY */
    uint8_t peer_io;
    uint8_t private_be[32], public_le[64], peer_le[64], cookie[16];
    uint8_t dh_le[32], ra[16], rb[16], t_confirm[16];
    uint8_t link_key[16], expected_dh[16], giv_skd[12];
    sle_pair_pdu_t outgoing;
    uint8_t last_ctrl[SLE_PAIR_CTRL_MAX], last_ctrl_sn;
    size_t last_ctrl_len;
    /* Separate plaintext ARQ cache: generic controls must not replace the
     * pairing transcript above. Invalidated by the first authenticated RX. */
    uint8_t plain_rx[SLE_PAIR_CTRL_INPUT_MAX], plain_rx_sn;
    size_t plain_rx_len;
    int plain_rx_is_pair;
    sle_pair_cipher_t cipher;
} sle_pair_t;

typedef struct {
    sle_pair_state_t state;
    int error, secure, confirm_matches;
    uint8_t failure_reason, remote_reason;
    uint64_t tx_next, rx_next;
} sle_pair_status_t;

int sle_pair_init(sle_pair_t *p, const sle_pair_config_t *cfg);
void sle_pair_clear(sle_pair_t *p);
int sle_pair_prepare(sle_pair_t *p); /* blocking keygen; only from IDLE */
int sle_pair_start(sle_pair_t *p, uint64_t now_ms);
int sle_pair_tick(sle_pair_t *p, uint64_t now_ms);
int sle_pair_pop(sle_pair_t *p, sle_pair_pdu_t *out); /* 1 copied, 0 empty */
void sle_pair_status(const sle_pair_t *p, sle_pair_status_t *out);
const char *sle_pair_error_string(int error); /* contains no secrets */

int sle_pair_take_work(sle_pair_t *p, sle_pair_work_t *work);
int sle_pair_run_work(sle_pair_work_t *work, sle_pair_work_result_t *result);
/* Consumes/zeros result. A stale/invalid work cookie returns ERR_STATE without
 * destroying a different live pairing. Crypto failure/timeout is terminal. */
int sle_pair_finish_work(sle_pair_t *p, sle_pair_work_result_t *result,
                         uint64_t now_ms);
void sle_pair_work_clear(sle_pair_work_t *work);
void sle_pair_work_result_clear(sle_pair_work_result_t *result);

/* peer_addr is the identity of the established link, NOT a field carried in
 * these controls. It must match cfg.t_addr; DH verification binds both MACs.
 * Unified control RX: authenticate ONCE, check exact 2B opcode LE + 1B len,
 * then route 0004..0009, 0133..0149 and 01FF to the pairing state machine.
 * Unsupported pairing opcodes (including security refresh 0008/0009) fail
 * terminally. Other opcodes return is_pair=0 for sle_link/upper-layer parsing;
 * their opcode-specific length/fields and effects are the caller's job.
 * Generic controls, including authenticated disconnect during WAIT_SECURITY_ACK,
 * never advance the pairing state, extend its step timer, consume pending TX,
 * or replace last_ctrl. They still occupy the shared RX ARQ/counter position.
 * On success: return OK, copy the complete plaintext control into plain,
 * set out_len and is_pair (1 for pairing/security, 0 otherwise).
 * On verified duplicate: return DUPLICATE, out_len=0, is_pair identifies the
 * original control, and plain is untouched. Duplicate detection/CCM counters
 * span both control and data; a duplicate cannot change its control/data class.
 * Plain duplicates must exactly match the immediately preceding control and
 * SN. Only the last plaintext 0006 retry is allowed during WAIT_SECURITY_ACK,
 * and only BEFORE any encrypted peer PDU has been accepted.
 * BUFFER/ARGUMENT errors do not consume a counter or dispatch a message.
 * On every error out_len=0 and is_pair=0, plain is untouched; no plaintext is
 * exposed from failed MIC, malformed control, or illegal pairing state.
 * Buffers may overlap each other but must not alias p. plain may be NULL only
 * with cap=0 (useful for duplicates; new controls return ERR_BUFFER).
 * A verified encrypted 0007, following our protected 0007, completes startup.
 * Negative protocol/crypto errors are terminal; first error is retained.
 * Pre-CCM failures queue WS63 01FF; post-switch errors require disconnect
 * (MIC error => link reason 27). Caller must discard its pending ARQ data
 * on failure and wipe owned plaintext/key/work storage at teardown.
 */
int sle_pair_on_control_ex(sle_pair_t *p, const uint8_t peer_addr[6],
                           const uint8_t *wire, size_t len, uint8_t sn,
                           int duplicate, uint64_t now_ms,
                           uint8_t *plain, size_t cap, size_t *out_len,
                           int *is_pair);
/* Compatibility wrapper: same single-pass authentication/routing, discards
 * returned plaintext/classification. Use _ex to deliver generic controls. */
int sle_pair_on_control(sle_pair_t *p, const uint8_t peer_addr[6],
                        const uint8_t *wire, size_t len, uint8_t sn,
                        int duplicate, uint64_t now_ms);

/* Only safe after CCM switch; application DATA is allowed after ENCRYPTED.
 * protect in WAIT_SECURITY_ACK permits only the startup 07 00 00 control.
 * Nonempty new TX must toggle SN after the first; retx must match both SN
 * and plaintext and returns the cached ciphertext (no counter advance).
 * unprotect is for DATA after ENCRYPTED; controls use on_control instead.
 * duplicate=1 verifies using rx_next-1 AND exact cached ciphertext, returns
 * DUPLICATE with *out_len=0. MIC failure is fatal, never treated as a dup.
 * Empty frames (len=0) ignore SN, retx/duplicate and preserve counters.
 * BUFFER/ARGUMENT errors do not consume counters. Outputs must not alias p;
 * input/output buffers may overlap. On errors *out_len=0; no unauthenticated
 * plaintext is exposed (decrypt uses private scratch). No clock checks in
 * protect/unprotect: owner must call tick each event.
 */
/* COUNT_PLAIN only: once, immediately after accepted plaintext 0006 and
 * before any protected TX/RX. Counts must be below the 39-bit limit.
 * State/range errors leave cipher state unchanged. CTR1 is incompatible. */
int sle_pair_seed_plain_counters(sle_pair_t *p, uint64_t tx, uint64_t rx);

int sle_pair_protect(sle_pair_t *p, const uint8_t *plain, size_t len,
                      uint8_t sn, int retx, uint8_t *wire, size_t cap,
                      size_t *out_len);
int sle_pair_unprotect(sle_pair_t *p, const uint8_t *wire, size_t len,
                        uint8_t sn, int duplicate, uint8_t *plain, size_t cap,
                        size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif
