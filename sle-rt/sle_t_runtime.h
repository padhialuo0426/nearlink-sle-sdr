/* Owner-thread T adapter. Radio must stop before destroy; worker is joined,
 * never cancelled. Each connection needs a fresh init/bind/destroy lifecycle.
 */
#ifndef SLE_T_RUNTIME_H
#define SLE_T_RUNTIME_H
#include "sle_g_runtime.h"
#include "sle_t_pair.h"
typedef struct {
  sle_t_pair pair;
  sle_rt_worker worker;
  int rng_fd, initialized, error, bound;
  uint8_t peer[6], wire[SLE_RT_TX_MAX];
  int tx_cached, tx_secure, tx_business, tx_submitted;
  uint64_t protected_tx_acked, protected_rx, mic_ok, mic_failed, encrypted_ms;
} sle_t_runtime;
/* Blocking key generation before radio starts; worker is SCHED_OTHER on cpu. */
int sle_t_runtime_init(sle_t_runtime *r, const uint8_t t[6], int cpu);
/* variant: SLE_PAIR_PROFILE_WS63 or SLE_PAIR_V_COUNT_PLAIN (see sle_t_pair.h) */
int sle_t_runtime_init_variant(sle_t_runtime *r, const uint8_t t[6], int cpu,
                            unsigned variant);
/* Bind once after access; permitted only in READY before any RX/TX PDU. */
int sle_t_runtime_bind(sle_t_runtime *r, const uint8_t g[6], uint32_t sync_low32);
int sle_t_runtime_destroy(sle_t_runtime *r);
int sle_t_runtime_poll(sle_t_runtime *r, uint64_t now_ms);
int sle_t_runtime_queue(sle_t_runtime *r, sle_rt_tx_store *s, sle_link_t *l);
int sle_t_runtime_tx(sle_t_runtime *r, sle_link_tx_t *tx);
int sle_t_runtime_submitted(sle_t_runtime *r, const sle_link_tx_t *tx);
/* Authentication before ARQ; generic controls (e.g. 000A) go to sle_link.
 * Return 0 accepted, 1 ignored CRC/no-event, negative terminal error. */
int sle_t_runtime_rx(sle_t_runtime *r, sle_link_t *l, const sle_link_rx_t *wire,
                  sle_link_rx_out_t *out, sle_rt_rx *scratch, uint64_t now_ms);
int sle_t_runtime_encrypted(const sle_t_runtime *r);
#endif
