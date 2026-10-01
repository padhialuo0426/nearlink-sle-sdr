/* sle_iio.c - see sle_iio.h. */
#define _GNU_SOURCE
#include "sle_iio.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

struct sle_iio_alloc_req { uint32_t type, size, count, id; };
#define BLK_ALLOC   _IOWR('i', 0xa0, struct sle_iio_alloc_req)
#define BLK_FREE    _IO('i', 0xa1)
#define BLK_QUERY   _IOWR('i', 0xa2, struct sle_iio_blk)
#define BLK_ENQUEUE _IOWR('i', 0xa3, struct sle_iio_blk)
#define BLK_DEQUEUE _IOWR('i', 0xa4, struct sle_iio_blk)

#define MAX_SAVE 48
static struct { char path[160]; char val[96]; } saved[MAX_SAVE];
static int nsaved;

int sle_iio_read(const char *path, char *buf, size_t n)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, (int)n, f)) buf[0] = 0;
    fclose(f);
    char *nl = strchr(buf, '\n');
    if (nl) *nl = 0;
    return 0;
}

int sle_iio_write(const char *path, const char *val)
{
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return -1; }
    int r = fputs(val, f) < 0 ? -1 : 0;
    if (fclose(f)) r = -1;
    if (r) fprintf(stderr, "write %s=%s: %s\n", path, val, strerror(errno));
    return r;
}

int sle_iio_set(const char *path, const char *val)
{
    int i;
    for (i = 0; i < nsaved; i++) if (!strcmp(saved[i].path, path)) break;
    if (i == nsaved && nsaved < MAX_SAVE) {
        snprintf(saved[i].path, sizeof saved[i].path, "%s", path);
        if (sle_iio_read(path, saved[i].val, sizeof saved[i].val) == 0) {
            char *sp = strchr(saved[i].val, ' ');   /* "71.000000 dB" */
            if (sp) *sp = 0;
            nsaved++;
        }
    }
    return sle_iio_write(path, val);
}

void sle_iio_restore_all(void)
{
    for (int i = nsaved - 1; i >= 0; i--) sle_iio_write(saved[i].path, saved[i].val);
    nsaved = 0;
}

static int xioctl(int fd, unsigned long req, void *arg)
{
    int r;
    do r = ioctl(fd, req, arg); while (r < 0 && errno == EINTR);
    return r;
}

int sle_iio_open(sle_iio_queue_t *q, const char *dev, int tx, int n, uint32_t bytes)
{
    memset(q, 0, sizeof(*q));
    q->fd = -1;
    q->tx = tx;
    q->bytes = bytes;
    if (n < 1 || n > SLE_IIO_MAXBLK) return -1;
    q->fd = open(dev, O_RDWR);
    if (q->fd < 0) { perror(dev); return -1; }
    struct sle_iio_alloc_req req = { 0, bytes, (uint32_t)n, 0 };
    if (xioctl(q->fd, BLK_ALLOC, &req)) { perror("IIO_BLOCK_ALLOC"); return -1; }
    q->n = (int)req.count;
    for (int i = 0; i < q->n; i++) {
        q->b[i].id = (uint32_t)i;
        if (xioctl(q->fd, BLK_QUERY, &q->b[i])) { perror("IIO_BLOCK_QUERY"); return -1; }
        q->addr[i] = mmap(NULL, q->b[i].size, PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, q->b[i].offset);
        if (q->addr[i] == MAP_FAILED) { q->addr[i] = NULL; perror("mmap"); return -1; }
        if (!tx) {
            q->b[i].bytes_used = bytes;
            if (xioctl(q->fd, BLK_ENQUEUE, &q->b[i])) { perror("IIO_BLOCK_ENQUEUE"); return -1; }
        }
    }
    return q->n;
}

int sle_iio_get(sle_iio_queue_t *q, struct sle_iio_blk *out, int timeout_ms)
{
    for (;;) {
        struct pollfd pfd = { q->fd, q->tx ? POLLOUT : POLLIN, 0 };
        int r = poll(&pfd, 1, timeout_ms);
        if (r == 0) return timeout_ms == 0 ? -2 : -1;
        if (r < 0) { if (errno == EINTR) continue; perror("poll"); return -1; }
        memset(out, 0, sizeof(*out));
        if (xioctl(q->fd, BLK_DEQUEUE, out) == 0) return (int)out->id;
        if (errno != EAGAIN) { perror("IIO_BLOCK_DEQUEUE"); return -1; }
        if (timeout_ms == 0) return -2;
    }
}

int sle_iio_put(sle_iio_queue_t *q, int id)
{
    q->b[id].bytes_used = q->bytes;
    return xioctl(q->fd, BLK_ENQUEUE, &q->b[id]);
}

void sle_iio_close(sle_iio_queue_t *q)
{
    for (int i = 0; i < q->n; i++) if (q->addr[i]) munmap(q->addr[i], q->b[i].size);
    if (q->fd >= 0) { xioctl(q->fd, BLK_FREE, NULL); close(q->fd); }
    q->fd = -1;
    q->n = 0;
}

int sle_iio_rx_setup(long long fs, long long lo_hz, long long bw_hz, double gain_db, int block)
{
    char v[64];
    snprintf(v, sizeof v, "%lld", fs);
    if (sle_iio_set(SLE_IIO_PHY "in_voltage_sampling_frequency", v)) return -1;
    snprintf(v, sizeof v, "%lld", lo_hz);
    if (sle_iio_set(SLE_IIO_PHY "out_altvoltage0_RX_LO_frequency", v)) return -1;
    if (bw_hz > 0) {
        snprintf(v, sizeof v, "%lld", bw_hz);
        if (sle_iio_set(SLE_IIO_PHY "in_voltage_rf_bandwidth", v)) return -1;
    }
    if (gain_db >= -100) {
        if (sle_iio_set(SLE_IIO_PHY "in_voltage0_gain_control_mode", "manual")) return -1;
        snprintf(v, sizeof v, "%.0f", gain_db);
        if (sle_iio_set(SLE_IIO_PHY "in_voltage0_hardwaregain", v)) return -1;
    }
    sle_iio_set(SLE_IIO_RXD "scan_elements/in_voltage0_en", "1");
    sle_iio_set(SLE_IIO_RXD "scan_elements/in_voltage1_en", "1");
    sle_iio_set(SLE_IIO_RXD "scan_elements/in_voltage2_en", "0");
    sle_iio_set(SLE_IIO_RXD "scan_elements/in_voltage3_en", "0");
    snprintf(v, sizeof v, "%d", block);
    return sle_iio_set(SLE_IIO_RXD "buffer/length", v);
}

int sle_iio_realtime(int cpu, int prio)
{
    if (cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof set, &set)) { perror("sched_setaffinity"); return -1; }
    }
    if (prio > 0) {
        struct sched_param sp = { .sched_priority = prio };
        if (sched_setscheduler(0, SCHED_FIFO, &sp)) { perror("sched_setscheduler"); return -1; }
        if (mlockall(MCL_CURRENT | MCL_FUTURE)) { perror("mlockall"); return -1; }
    }
    return 0;
}

int64_t sle_iio_now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}
