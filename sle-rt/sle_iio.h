/* sle_iio.h - minimal raw kernel IIO access for the E310 (AD9361 + ADI DMA),
 * without libiio: sysfs attributes with save/restore, and the ADI mmap block
 * interface (IIO_BLOCK_ALLOC/QUERY/ENQUEUE/DEQUEUE, the interface libiio
 * 0.25's local backend uses).
 *
 * Lessons from timing validation (docs/experiments/p3a-e310-timing-2026-09-26.md):
 *  - the plain read()/write() fileio path drops ~16 % of RX samples at 4 MS/s;
 *  - DMA blocks are mapped uncached: memcpy a block before per-sample work;
 *  - never let TX pacing block RX processing.
 * Linux-only; not part of the portable sle-rt library.
 */
#ifndef SLE_IIO_H
#define SLE_IIO_H

#include <stddef.h>
#include <stdint.h>

#define SLE_IIO_PHY "/sys/bus/iio/devices/iio:device0/"
#define SLE_IIO_TXD "/sys/bus/iio/devices/iio:device2/"
#define SLE_IIO_RXD "/sys/bus/iio/devices/iio:device3/"
#define SLE_IIO_TXDEV "/dev/iio:device2"
#define SLE_IIO_RXDEV "/dev/iio:device3"

/* Attributes: sle_iio_set() saves the first-seen value of each path, and
 * sle_iio_restore_all() writes them back in reverse order. */
int sle_iio_read(const char *path, char *buf, size_t n);
int sle_iio_write(const char *path, const char *val);
int sle_iio_set(const char *path, const char *val);
void sle_iio_restore_all(void);

#define SLE_IIO_MAXBLK 32
#define SLE_IIO_BLK_CYCLIC 2u

struct sle_iio_blk { uint32_t id, size, bytes_used, type, flags, offset; uint64_t timestamp; };

typedef struct {
    int fd, n, tx;
    uint32_t bytes;
    void *addr[SLE_IIO_MAXBLK];
    struct sle_iio_blk b[SLE_IIO_MAXBLK];
} sle_iio_queue_t;

/* Allocate and map n blocks of `bytes` each. RX blocks are enqueued at once;
 * TX blocks start owned by user space (fill, then sle_iio_put). Returns the
 * number of blocks, or -1. */
int sle_iio_open(sle_iio_queue_t *q, const char *dev, int tx, int n, uint32_t bytes);
/* Wait up to timeout_ms (-1 forever) and dequeue; returns block id, -1 on
 * error/timeout, -2 when timeout_ms == 0 and nothing is ready. */
int sle_iio_get(sle_iio_queue_t *q, struct sle_iio_blk *out, int timeout_ms);
int sle_iio_put(sle_iio_queue_t *q, int id);
void sle_iio_close(sle_iio_queue_t *q);

/* Common RX setup: sample rate, LO, RF bandwidth, manual gain (gain_db
 * < -100: keep AGC), RX1 I/Q channels, block length. Saved for restore. */
int sle_iio_rx_setup(long long fs, long long lo_hz, long long bw_hz, double gain_db, int block);

/* Pin the calling thread to cpu (>= 0) and make it SCHED_FIFO prio (> 0),
 * with mlockall. Returns 0 or -1. */
int sle_iio_realtime(int cpu, int prio);

int64_t sle_iio_now_ns(void);

#endif /* SLE_IIO_H */
