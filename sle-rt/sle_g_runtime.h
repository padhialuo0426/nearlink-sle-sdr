/* G pairing owner-thread adapter. No radio I/O; only the isolated ECDH mailbox is
 * shared with the SCHED_OTHER worker. Destroy AFTER stopping radio, BEFORE
 * releasing the runtime/RNG storage. All other calls are owner-only. */
#ifndef SLE_G_RUNTIME_H
#define SLE_G_RUNTIME_H
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include "sle_pair.h"
#include "sle_link.h"

#define SLE_RT_TX_MAX 96u /* includes MIC */
#define SLE_RT_TX_SLOTS 8u
typedef struct {
    uint8_t data[SLE_RT_TX_SLOTS][SLE_RT_TX_MAX];
    unsigned used[SLE_RT_TX_SLOTS];
} sle_rt_tx_store;
/* Copies input. Slots are recycled only when no live link PDU references them. */
/* Returns -2 when every slot is still referenced by the link (retry later),
 * -1 on any other error. */
int sle_rt_queue(sle_rt_tx_store *s, sle_link_t *l, uint8_t type, const uint8_t *p, size_t n);
/* Slots sle_rt_queue could use now (free or no longer referenced); no change. */
unsigned sle_rt_free_slots(const sle_rt_tx_store *s, const sle_link_t *l);
void sle_rt_wipe(void *p, size_t n);

typedef struct {
    pthread_t thread;
    sem_t wake;
    atomic_int job, stop; /* job: 0 idle, 1 owner-published, 2 worker-done */
    sle_pair_work_t work;
    sle_pair_work_result_t result;
    int started, sem_ready;
} sle_rt_worker;
typedef struct {
    sle_pair_t pair;             /* NEVER passed to worker */
    sle_rt_worker worker;
    int rng_fd, initialized, error;
    uint8_t peer[6];
    uint8_t wire[SLE_RT_TX_MAX];
    int tx_cached, tx_secure, tx_business, tx_submitted;
    /* Unique nonempty plaintext PDU counts for the WS63 profile. */
    uint64_t plain_tx, plain_rx;
    uint64_t protected_tx_acked, protected_rx;
    uint64_t mic_ok, mic_failed;
    uint64_t encrypted_ms;
} sle_g_runtime;
typedef struct {
    uint8_t plain[SLE_PAIR_WIRE_MAX];
    int pair_control, protected_frame, duplicate, mic; /* mic: 0 N/A, 1 OK, -1 bad */
    uint16_t opcode;
} sle_rt_rx;

/* WS63 profile, fresh OS RNG + blocking ephemeral prepare, before radio start. cpu is the
 * control CPU; explicit SCHED_OTHER keeps the worker below FIFO control/DMA. */
int sle_g_runtime_init(sle_g_runtime *r, const uint8_t g[6], const uint8_t t[6],
                    uint32_t sync_low32, int cpu);
/* Explicit SLE_PAIR_V_* mask (0 retains the historical hypothesis). */
int sle_g_runtime_init_variant(sle_g_runtime *r, const uint8_t g[6], const uint8_t t[6],
                            uint32_t sync_low32, int cpu, unsigned variant);
/* Joins, never cancels crypto mid-allocation. On join error storage remains
 * live and must not be freed. Radio cleanup must not depend on this result. */
int sle_g_runtime_destroy(sle_g_runtime *r);
int sle_g_runtime_poll(sle_g_runtime *r, uint64_t now_ms);
int sle_g_runtime_start(sle_g_runtime *r, uint64_t now_ms);
int sle_g_runtime_queue(sle_g_runtime *r, sle_rt_tx_store *s, sle_link_t *l);
int sle_g_runtime_tx(sle_g_runtime *r, sle_link_tx_t *tx);
void sle_g_runtime_submitted(sle_g_runtime *r, const sle_link_tx_t *tx);
/* Authentication precedes EVERY call to link_on_rx for a protected body.
 * Returns 0 accepted, 1 ignored CRC body failure, negative terminal error.
 * out->data points to scratch until the next call using that scratch. */
int sle_g_runtime_rx(sle_g_runtime *r, sle_link_t *l, const sle_link_rx_t *wire,
                  sle_link_rx_out_t *out, sle_rt_rx *scratch, uint64_t now_ms);
int sle_g_runtime_encrypted(const sle_g_runtime *r);
int sle_g_runtime_accepted(const sle_g_runtime *r, int ssap_requested,
                        int ssap_validated, int write_requested, int write_verified);
#endif
