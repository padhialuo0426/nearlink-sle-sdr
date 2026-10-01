/* GB/T 46803.2-2025 6.3.3, tables 146-148: non-multiplexed (ptype 0)
 * link SDU reassembly. Call ONLY after CRC/MIC validation and link ARQ
 * deduplication, in delivered order, for one connection/direction.
 * This layer has no sequence number and cannot detect omitted/reordered
 * middle fragments itself. Control/empty/duplicate frames must not be fed.
 */
#ifndef SLE_SDU_H
#define SLE_SDU_H
#include <stddef.h>
#include <stdint.h>

/* Local receive bound: the application's maximum advertised SSAP MTU 1024
 * plus its 4-byte DTAP header. Not a standard maximum SDU length. */
#define SLE_SDU_MAX 1028u
typedef struct {
    uint8_t data[SLE_SDU_MAX];
    size_t len, limit;
    unsigned fragments;
    int pending;
} sle_sdu_rx;
enum {
    SLE_SDU_OK=0, SLE_SDU_INVALID=-1, SLE_SDU_SEQUENCE=-2,
    SLE_SDU_OVERFLOW=-3
};
/* Callback bytes are valid only during the call. Do not reenter the receiver.
 * A PDU can deliver several SDUs. fragments=1 means an unsegmented SDU. */
typedef void (*sle_sdu_deliver)(void *ctx, const uint8_t *data, size_t len,
                               unsigned fragments);
/* init/reset at every new connection and after disconnect. Invalid limit
 * leaves the object disabled; feed then returns INVALID. */
void sle_sdu_rx_init(sle_sdu_rx *r, size_t limit);
/* Reserved header bits are ignored on receive. All records' lengths and
 * state transitions are prechecked before publishing any SDU from the PDU.
 * Malformed/truncated, orphan, interrupted or oversized sequences drop the
 * pending SDU and return an error, with no callbacks for this PDU. This is
 * a local recovery policy; a later COMPLETE/FIRST can start a new SDU.
 * An empty fragment/record is rejected (local progress requirement).
 */
int sle_sdu_rx_feed(sle_sdu_rx *r, const uint8_t *p, size_t n,
                    sle_sdu_deliver deliver, void *ctx);
/* Transmit side, same record format (seg 0 complete, 1 first, 2 middle,
 * 3 last; size in 11 bits). Writes the record for sdu[*off..] carrying at
 * most max_data bytes, advances *off and returns the record length (2 +
 * data), or 0 on invalid input / insufficient cap / nothing left. An SDU
 * that fits in max_data is sent as one complete record. WS63 1.10.x sends
 * 24-byte fragments (logs/e310/g_runtime-sdu-long-d-20260927). */
size_t sle_sdu_tx_fragment(const uint8_t *sdu, size_t n, size_t *off,
                           size_t max_data, uint8_t *out, size_t cap);
#endif
