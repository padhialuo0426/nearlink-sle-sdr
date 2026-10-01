/* Experimental T-side WS63 Just Works profile. Offline verified, not RF
 * verified. Serialized owner API; key generation before radio, ECDH through
 * work API. No I/O, threads or time source. Each new connection needs
 * init+prepare. Caller derives duplicate/retx from ARQ BEFORE changing it. rx
 * authenticates first; only success/verified duplicate may affect ARQ. Empty
 * frames bypass these APIs and never affect counters. Plain controls also share
 * ARQ counts.
 */
#ifndef SLE_T_PAIR_H
#define SLE_T_PAIR_H
#include "sle_pair.h"
typedef enum {
  SLE_T_PAIR_IDLE,
  SLE_T_PAIR_READY,
  SLE_T_PAIR_WAIT_PUBLIC,
  SLE_T_PAIR_WAIT_WORK,
  SLE_T_PAIR_WAIT_RA,
  SLE_T_PAIR_WAIT_DH,
  SLE_T_PAIR_WAIT_SECURITY,
  SLE_T_PAIR_WAIT_START,
  SLE_T_PAIR_WAIT_START_TX,
  SLE_T_PAIR_ENCRYPTED,
  SLE_T_PAIR_FAILED
} sle_t_pair_state;
typedef struct {
  /* variant: SLE_PAIR_PROFILE_WS63 (1.10.102 single-block AES session key)
   * or SLE_PAIR_V_COUNT_PLAIN alone (1.10.108 AES-CMAC session key). */
  sle_pair_config_t cfg;
  sle_t_pair_state state;
  int error, active, work_taken, rx_secure, tx_secure;
  uint64_t start_ms, step_ms, now_ms, tx_next, rx_next;
  uint8_t private_be[32], public_le[64], g_public[64], dh[32];
  uint8_t ra[16], rb[16], lk[16], expected_g[16], t_check[16];
  uint8_t giv[12], tiv[12], cookie[16], key[16], iv[8];
  sle_pair_pdu_t queue[4];
  unsigned head, count;
  uint8_t tx_plain[SLE_PAIR_PLAIN_MAX], tx_wire[SLE_PAIR_WIRE_MAX];
  size_t tx_len, tx_wire_len;
  uint8_t tx_sn, tx_type;
  int tx_valid, tx_submitted, tx_cached_secure;
  uint8_t rx_wire[SLE_PAIR_WIRE_MAX];
  size_t rx_len;
  uint8_t rx_sn, rx_type;
  int rx_valid, rx_cached_secure, rx_pair;
  /* Diagnostic: last MIC failure -> candidate<<16 | dir<<8 | counter that
   * verifies, -1 none. Candidates are SLE_T_KDF_* below; indices only. */
  int mic_probe;
  uint8_t probe_key[6][16];
  uint8_t g_io;
} sle_t_pair;
enum { SLE_T_KDF_ECB, SLE_T_KDF_CMAC, SLE_T_KDF_CMAC_REV, SLE_T_KDF_CMAC_PLAIN,
       SLE_T_KDF_CMAC_PLAIN_REV, SLE_T_KDF_ECB_REV, SLE_T_KDF_CANDIDATES };
int sle_t_pair_init(sle_t_pair *p, const sle_pair_config_t *cfg);
int sle_t_pair_prepare(sle_t_pair *p);
void sle_t_pair_clear(sle_t_pair *p);
int sle_t_pair_tick(sle_t_pair *p, uint64_t now_ms);
int sle_t_pair_pop(sle_t_pair *p, sle_pair_pdu_t *out);
int sle_t_pair_take_work(sle_t_pair *p, sle_pair_work_t *out);
/* Run sle_pair_run_work(out,result) on worker, then finish on owner. */
int sle_t_pair_finish_work(sle_t_pair *p, sle_pair_work_result_t *result,
                          uint64_t now_ms);
/* ptype: 3=control, 0/2=data. Pair controls consumed: is_pair=1, plain output
 * still supplied for diagnostics; duplicates return1 and length0. Generic
 * controls return is_pair=0. Never dispatch duplicate plaintext twice.
 * Counter includes every successfully received nonempty plain PDU.
 */
int sle_t_pair_rx(sle_t_pair *p, const uint8_t peer[6], uint8_t ptype,
                 const uint8_t *wire, size_t len, uint8_t sn, int duplicate,
                 uint64_t now_ms, uint8_t *plain, size_t cap, size_t *out_len,
                 int *is_pair);
/* Precompute once before first transmission, retx=1 returns exact cached wire.
 * Caller must not replace current plaintext until ARQ ACK. Buffers must not
 * alias p. Call submitted ONLY once radio accepted actual nonempty submission;
 * repeated submitted calls on a cached retry are harmless. This call counts
 * plaintext TX and switches RX to CCM after plaintext0006 was submitted.
 */
int sle_t_pair_tx(sle_t_pair *p, uint8_t ptype, const uint8_t *plain, size_t len,
                 uint8_t sn, int retx, uint8_t *wire, size_t cap,
                 size_t *out_len);
int sle_t_pair_submitted(sle_t_pair *p, uint8_t sn);
#endif
