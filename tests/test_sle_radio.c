/* Device-free lifecycle/fault tests for the actual CPU1 loop and IIO adapter.
 * Link instead of sle_iio.c, with --wrap=ioctl,pthread_create,pthread_join
 * (one linker --wrap option per symbol). No RF data, fake
 * peer or hardware access: /dev/null only supplies valid disposable fds.
 * Keep separate from the production --selftest to prevent backend confusion.
 */
#define _GNU_SOURCE
#include "sle_radio.h"
#include "sle_hwstat.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; \
    fprintf(stderr,"Radio failure line %d: %s\n",__LINE__,#x); } } while (0)
enum { IDLE, BAD_RX_ID, SHORT_RX, BAD_TX_ID, DRAIN_TX, TX_PUT_FAIL, RX_LAG };
static atomic_int fault, tx_fd, rx_fd, ready_tx, tx_dequeues;
static atomic_int rx_lag_steps;
static atomic_int hold_rx, held_rx;
static int open_fail, rt_fail, open_calls, allocations, closes, write_fail;
static int create_fail, join_fail;
static atomic_int rt_signal_mask_ok;
static int buffers_off(void);
static volatile sig_atomic_t caught_signal;
static int rt_raise_signal;
static void catch_signal(int s) { caught_signal=s; }
int __real_pthread_create(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *);
int __real_pthread_join(pthread_t,void **);
int __wrap_pthread_create(pthread_t *t,const pthread_attr_t *at,void *(*fn)(void *),void *arg)
{
    return create_fail ? EAGAIN : __real_pthread_create(t,at,fn,arg);
}
int __wrap_pthread_join(pthread_t t,void **out)
{
    CHECK(buffers_off()); /* future queued TX is stopped before join */
    return join_fail ? EINVAL : __real_pthread_join(t,out);
}
static struct { char path[160], val[96], original[96]; } store[32];
static unsigned stored;
static int attr(const char *path)
{
    for (unsigned i=0;i<stored;i++) if (!strcmp(path,store[i].path)) return (int)i;
    if (stored==32) abort();
    unsigned i=stored++;
    snprintf(store[i].path,sizeof store[i].path,"%s",path);
    const char *v="0";
    if (strstr(path,"sampling_frequency")) v="30720000";
    else if (strstr(path,"rf_bandwidth")) v="28000000";
    else if (strstr(path,"_LO_frequency")) v="2481000000";
    else if (strstr(path,"gain_control_mode")) v="manual";
    else if (strstr(path,"out_voltage0_hardwaregain")) v="-60.000000";
    else if (strstr(path,"hardwaregain")) v="20";
    else if (strstr(path,"buffer/length")) v="8192";
    snprintf(store[i].val,sizeof store[i].val,"%s",v);
    snprintf(store[i].original,sizeof store[i].original,"%s",v);
    return (int)i;
}
static int buffers_off(void)
{
    return !strcmp(store[attr(SLE_IIO_TXD "buffer/enable")].val,"0") &&
        !strcmp(store[attr(SLE_IIO_RXD "buffer/enable")].val,"0");
}
int sle_iio_read(const char *path,char *out,size_t n)
{
    snprintf(out,n,"%s",store[attr(path)].val); return 0;
}
int sle_iio_write(const char *path,const char *val)
{
    int i=attr(path);
    if (write_fail && strstr(path,"TX_LO_frequency")) return -1;
    snprintf(store[i].val,sizeof store[i].val,"%s",val); return 0;
}
int sle_iio_set(const char *p,const char *v) { return sle_iio_write(p,v); }
void sle_iio_restore_all(void) { /* own transaction must also restore side effects */ }
int sle_iio_realtime(int cpu,int prio)
{
    (void)cpu; (void)prio;
    sigset_t current;
    int e=pthread_sigmask(SIG_SETMASK,NULL,&current);
    atomic_store(&rt_signal_mask_ok,!e && sigismember(&current,SIGINT) && sigismember(&current,SIGTERM) &&
        sigismember(&current,SIGHUP) && sigismember(&current,SIGPIPE));
    if (rt_raise_signal && kill(getpid(),rt_raise_signal)) return -1;
    return rt_fail ? -1 : 0;
}
int64_t sle_iio_now_ns(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return (int64_t)t.tv_sec*1000000000+t.tv_nsec;
}
int sle_iio_open(sle_iio_queue_t *q,const char *dev,int tx,int n,uint32_t bytes)
{
    (void)dev;
    memset(q,0,sizeof *q); q->fd=open("/dev/null",O_RDWR); q->tx=tx; q->bytes=bytes;
    if (q->fd<0) return -1;
    atomic_store(tx ? &tx_fd : &rx_fd,q->fd);
    open_calls++;
    for (int i=0;i<n;i++) {
        q->n=i+1; q->b[i].id=(unsigned)i; q->b[i].size=bytes;
        q->addr[i]=calloc(1,bytes); if (!q->addr[i]) return -1;
        allocations++;
        if (open_calls==open_fail && i==2) return -1; /* partial mmap allocation */
    }
    return n;
}
int sle_iio_put(sle_iio_queue_t *q,int id) { (void)q; (void)id; return 0; }
void sle_iio_close(sle_iio_queue_t *q)
{
    for (int i=0;i<q->n;i++) if (q->addr[i]) { free(q->addr[i]); q->addr[i]=NULL; allocations--; }
    if (q->fd>=0) { close(q->fd); closes++; }
    q->fd=-1; q->n=0;
}
int __wrap_ioctl(int fd,unsigned long request,...)
{
    va_list ap; va_start(ap,request); struct sle_iio_blk *b=va_arg(ap,struct sle_iio_blk *); va_end(ap);
    int f=atomic_load(&fault), tx=fd==atomic_load(&tx_fd);
    if (!tx && atomic_load(&hold_rx)) {
        atomic_store(&held_rx,1);
        while (atomic_load(&hold_rx)) sched_yield();
        atomic_store(&held_rx,0);
    }
    if (request==_IOWR('i',0xa3,struct sle_iio_blk)) {
        if (tx && f==TX_PUT_FAIL) { errno=EIO; return -1; }
        return 0;
    }
    if (request!=_IOWR('i',0xa4,struct sle_iio_blk)) { errno=EINVAL; return -1; }
    if (tx) {
        if (f==BAD_TX_ID) { b->id=32; return 0; }
        if (f==DRAIN_TX && atomic_load(&tx_dequeues)<SLE_RT_ACCESS_DEPTH) {
            b->id=(unsigned)atomic_fetch_add(&tx_dequeues,1); return 0;
        }
        if (f==TX_PUT_FAIL && !atomic_exchange(&ready_tx,1)) { b->id=0; return 0; }
    } else {
        if (f==BAD_RX_ID) { b->id=32; b->bytes_used=SLE_RT_BLOCK*4; return 0; }
        if (f==SHORT_RX) { b->id=0; b->bytes_used=SLE_RT_BLOCK*4-4; return 0; }
        if (f==RX_LAG) {
            if (atomic_fetch_add(&rx_lag_steps,1)>0) {
                struct timespec delay={0,4000000}; nanosleep(&delay,NULL);
            }
            b->id=0; b->bytes_used=SLE_RT_BLOCK*4; return 0;
        }
    }
    errno=EAGAIN; return -1;
}
static void reset_backend(void)
{
    atomic_store(&fault,IDLE); atomic_store(&ready_tx,0); atomic_store(&tx_dequeues,0);
    atomic_store(&rx_lag_steps,0);
    atomic_store(&hold_rx,0); atomic_store(&held_rx,0);
    atomic_store(&rt_signal_mask_ok,0);
    open_fail=rt_fail=open_calls=closes=create_fail=join_fail=0;
    rt_raise_signal=0;
}
static void wait_error(sle_rt_radio *r,int expected)
{
    int64_t until=sle_iio_now_ns()+1000000000;
    struct timespec nap={0,100000};
    while (!atomic_load(&r->error) && sle_iio_now_ns()<until) nanosleep(&nap,NULL);
    CHECK(atomic_load(&r->error)==expected);
    if (expected==SLE_RT_IO_RX_LAG) CHECK(r->rx_stats[SLE_RT_RX_WINDOW].max_lag_ns>3000000);
    CHECK(!sle_rt_radio_stop(r));
    CHECK(!r->started && !r->renderer.active && !atomic_load(&r->pending));
    CHECK(!allocations && r->rxq.fd==-1 && r->txq.fd==-1);
}
typedef struct { sle_rt_frame_ring q; atomic_int failed; } stress;
static void *produce(void *arg)
{
    stress *s=arg; sle_rt_received f={0};
    for (unsigned i=0;i<100000;i++) {
        f.seq=i; f.f.sample_index=(uint64_t)i*1234567; f.f.frame.payload_len=2;
        f.f.frame.payload[0]=(uint8_t)i; f.f.frame.payload[1]=(uint8_t)(i>>8);
        while (sle_rt_ring_push(&s->q,&f)) sched_yield();
    }
    return NULL;
}
static void concurrent_ring(void)
{
    stress *s=calloc(1,sizeof *s); CHECK(s!=NULL); if (!s) return;
    sle_rt_ring_init(&s->q); atomic_init(&s->failed,0);
    pthread_t t; int e=pthread_create(&t,NULL,produce,s); CHECK(!e);
    if (e) { free(s); return; }
    for (unsigned i=0;i<100000;i++) {
        sle_rt_received f;
        while (sle_rt_ring_pop(&s->q,&f)) sched_yield();
        if (f.seq!=i || f.f.sample_index!=(uint64_t)i*1234567 ||
            f.f.frame.payload[0]!=(uint8_t)i || f.f.frame.payload[1]!=(uint8_t)(i>>8))
            atomic_store(&s->failed,1);
    }
    CHECK(!pthread_join(t,NULL)); CHECK(!atomic_load(&s->failed)); free(s);
}
static void timing_diagnostics(sle_rt_radio *r)
{
    const char *sources[]={"submit_rx_expired","consumer_rx_expired","renderer_start_late"};
    for (int source=SLE_RT_LATE_SUBMIT_RX;source<=SLE_RT_LATE_RENDER_START;source++) {
        reset_backend(); atomic_store(&hold_rx,1);
        CHECK(!sle_rt_radio_start(r,1,80));
        int64_t deadline=sle_iio_now_ns()+20000000;
        while (!atomic_load(&held_rx) && sle_iio_now_ns()<deadline) sched_yield();
        CHECK(atomic_load(&held_rx));
        int64_t tx_head=atomic_load(&r->tx_head), before=sle_iio_now_ns();
        sle_rt_command c={.seq=17,.mhz=2424,.seed=77,.rx_start=10,.rx_end=40,
                      .tx_start=tx_head-1};
        c.wave.n=8;
        unsigned repeats=source==SLE_RT_LATE_SUBMIT_RX ? SLE_RT_TIMING_RING+2 : 1;
        if (source==SLE_RT_LATE_SUBMIT_RX) atomic_store(&r->rx_head,c.rx_end);
        for (unsigned i=0;i<repeats;i++) {
            c.seq=17+i;
            CHECK(sle_rt_radio_submit(r,&c)==(source==SLE_RT_LATE_SUBMIT_RX ? SLE_RT_LATE:SLE_RT_OK));
        }
        if (source==SLE_RT_LATE_CONSUMER_RX) atomic_store(&r->rx_head,c.rx_end);
        char *text=NULL; size_t bytes=0;
        FILE *out=open_memstream(&text,&bytes); CHECK(out!=NULL);
        if (out) CHECK(sle_rt_radio_timing_write(r,out,7)==-1); /* no live reads */
        atomic_store(&hold_rx,0);
        if (source!=SLE_RT_LATE_SUBMIT_RX) {
            deadline=sle_iio_now_ns()+20000000;
            while (atomic_load(&r->ack_seq)!=c.seq && sle_iio_now_ns()<deadline) sched_yield();
            CHECK(atomic_load(&r->ack_seq)==c.seq && atomic_load(&r->ack_result)==SLE_RT_LATE);
        }
        CHECK(!sle_rt_radio_stop(r));
        const sle_rt_timing_log *log=source==SLE_RT_LATE_SUBMIT_RX ? &r->submit_timing:&r->consumer_timing;
        CHECK(log->total==repeats);
        const sle_rt_timing_fault *d=&log->entry[(log->total-1)%SLE_RT_TIMING_RING];
        CHECK(d->source==(enum sle_rt_late_source)source && d->seq==c.seq);
        CHECK(d->mono_ns>=before && d->mono_ns<=sle_iio_now_ns());
        CHECK(d->tx_head==tx_head && d->rx_head==(source==SLE_RT_LATE_RENDER_START ? 0:40));
        CHECK(d->tx_start==c.tx_start && d->wave_samples==8 && d->rx_start==10 && d->rx_end==40);
        CHECK(d->queue_depth==SLE_RT_ACCESS_DEPTH);
        CHECK(d->tx_queued==(source==SLE_RT_LATE_SUBMIT_RX ? -1:SLE_RT_ACCESS_DEPTH));
        CHECK(!r->renderer.active && !atomic_load(&r->pending) && !allocations);
        if (out) {
            CHECK(!sle_rt_radio_timing_write(r,out,7)); CHECK(!fclose(out));
            CHECK(bytes && strstr(text,sources[source]) && strstr(text,"\"attempt\":7"));
            char expected[64]; snprintf(expected,sizeof expected,"\"tx_end\":%lld",(long long)(c.tx_start+8));
            CHECK(strstr(text,expected)!=NULL && strstr(text,"\"deferred_log\":true")!=NULL);
            if (source==SLE_RT_LATE_SUBMIT_RX) {
                CHECK(strstr(text,"\"total\":18,\"overwritten\":2")!=NULL);
                CHECK(!strstr(text,"\"seq\":17,") && !strstr(text,"\"seq\":18,"));
                CHECK(strstr(text,"\"seq\":19,")!=NULL && strstr(text,"\"seq\":34,")!=NULL);
            }
            free(text);
        }
    }
    /* RX-only expired commands must not invent a TX end. */
    reset_backend(); CHECK(!sle_rt_radio_start(r,1,80));
    atomic_store(&r->rx_head,40);
    sle_rt_command c={.seq=100,.mhz=2424,.seed=77,.rx_end=40};
    CHECK(sle_rt_radio_submit(r,&c)==SLE_RT_LATE); CHECK(!sle_rt_radio_stop(r));
    char *text=NULL; size_t bytes=0; FILE *out=open_memstream(&text,&bytes); CHECK(out!=NULL);
    if (out) {
        CHECK(!sle_rt_radio_timing_write(r,out,1)); CHECK(!fclose(out));
        CHECK(strstr(text,"\"tx_end\":null,\"wave_samples\":0")!=NULL); free(text);
    }
}
int main(void)
{
    sle_rt_radio *r=calloc(1,sizeof *r); if (!r) return 1;
    CHECK(!sle_rt_radio_setup(-30,30));
    write_fail=1; CHECK(sle_rt_radio_retune(1,2440)==-1); write_fail=0;
    for (int i=1;i<=2;i++) {
        reset_backend(); open_fail=i;
        CHECK(sle_rt_radio_start(r,1,80)==-1);
        CHECK(!r->started && !allocations && r->txq.fd==-1 && r->rxq.fd==-1);
        CHECK(closes==i);
    }
    reset_backend(); rt_fail=1;
    CHECK(sle_rt_radio_start(r,1,80)==-1);
    CHECK(atomic_load(&r->error)==SLE_RT_IO_THREAD && !r->started && !allocations);
    reset_backend(); create_fail=1;
    CHECK(sle_rt_radio_start(r,1,80)==-1);
    CHECK(!r->started && !allocations && r->rxq.fd==-1 && r->txq.fd==-1);
    const int faults[]={BAD_RX_ID,SHORT_RX,BAD_TX_ID,DRAIN_TX,TX_PUT_FAIL,IDLE,RX_LAG};
    const int expected[]={SLE_RT_IO_RX,SLE_RT_IO_RX,SLE_RT_IO_TX,SLE_RT_IO_UNDERFLOW,SLE_RT_IO_TX,SLE_RT_IO_STALL,SLE_RT_IO_RX_LAG};
    for (unsigned i=0;i<sizeof faults/sizeof faults[0];i++) {
        reset_backend(); CHECK(!sle_rt_radio_start(r,1,80));
        CHECK(atomic_load(&rt_signal_mask_ok));
        sigset_t mask; CHECK(!pthread_sigmask(SIG_SETMASK,NULL,&mask));
        CHECK(!sigismember(&mask,SIGINT) && !sigismember(&mask,SIGTERM) &&
            !sigismember(&mask,SIGHUP) && !sigismember(&mask,SIGPIPE));
        atomic_store(&r->guard,1); atomic_store(&fault,faults[i]);
        wait_error(r,expected[i]);
    }
    /* Before guard (calibration) a drained TX queue is counted, not fatal. */
    reset_backend(); CHECK(!sle_rt_radio_start(r,1,80));
    atomic_store(&fault,DRAIN_TX);
    {
        struct timespec pause={0,100000}; int64_t until=sle_iio_now_ns()+20000000;
        while (sle_iio_now_ns()<until) nanosleep(&pause,NULL);
    }
    CHECK(!atomic_load(&r->error));
    CHECK(!sle_rt_radio_stop(r));
    CHECK(r->tx_drain_unguarded>0 && r->tx_drain_head[0]>=SLE_RT_ACCESS_DEPTH*SLE_RT_BLOCK);
    /* Normal cancellation with a future waveform that is still owned by RT. */
    reset_backend(); CHECK(!sle_rt_radio_start(r,1,80));
    sle_rt_command stale={.seq=99,.mhz=2424,.seed=77,.rx_end=1};
    atomic_store(&r->rx_head,2);
    CHECK(sle_rt_radio_submit(r,&stale)==SLE_RT_LATE && !atomic_load(&r->pending));
    atomic_store(&r->rx_head,0);
    sle_rt_command c={.seq=1,.mhz=2424,.seed=77,.rx_end=INT64_MAX,.tx_start=100000};
    c.wave.n=1; c.wave.iq[0]=10;
    CHECK(!sle_rt_radio_submit(r,&c));
    struct timespec nap={0,100000}; int64_t end=sle_iio_now_ns()+20000000;
    while (atomic_load(&r->ack_seq)!=1 && sle_iio_now_ns()<end) nanosleep(&nap,NULL);
    CHECK(atomic_load(&r->ack_seq)==1 && atomic_load(&r->ack_result)==SLE_RT_OK);
    c.wave.iq[0]=999; /* mailbox and renderer copies must retain old data */
    CHECK(!sle_rt_radio_stop(r)); CHECK(!allocations && !r->renderer.active && !atomic_load(&r->pending));
    CHECK(sle_rt_radio_submit(r,&c)==SLE_RT_RANGE); c.seq=2;
    CHECK(sle_rt_radio_submit(r,&c)==SLE_RT_CANCELLED);
    reset_backend(); CHECK(!sle_rt_radio_start(r,1,80));
    pthread_t saved=r->thread; join_fail=1;
    CHECK(sle_rt_radio_stop(r)==-1);
    CHECK(atomic_load(&r->exited) && !r->started && !allocations);
    join_fail=0; CHECK(!__real_pthread_join(saved,NULL));
    /* Process-directed signal generated on CPU1 must reach CPU0 after its
     * create-time mask is restored. No shared signal flag is read by CPU1. */
    reset_backend();
    struct sigaction sa={.sa_handler=catch_signal}, old;
    sigemptyset(&sa.sa_mask); CHECK(!sigaction(SIGHUP,&sa,&old));
    caught_signal=0; rt_raise_signal=SIGHUP;
    CHECK(!sle_rt_radio_start(r,1,80));
    CHECK(caught_signal==SIGHUP && atomic_load(&rt_signal_mask_ok));
    CHECK(!sle_rt_radio_stop(r)); CHECK(!sigaction(SIGHUP,&old,NULL));
    timing_diagnostics(r);
    {   /* hwstat: host has no E310 cores, so open must fail closed; the
         * writer must emit one summary and one row per stored event. */
        sle_rt_hwstat h; CHECK(sle_rt_hwstat_open(&h)==-1 && h.fd==-1 && !h.event);
        memset(&h,0,sizeof h); h.fd=-1;
        sle_rt_hw_event ev[2]={{.mono_ns=10,.prev_poll_ns=5,.rx_head=4096,.tx_head=7168,.dac=1},
                           {.mono_ns=20,.prev_poll_ns=10,.rx_head=5120,.tx_head=8192,.adc=4,.adc_after=4}};
        h.event=ev; h.n_events=2; h.polls=9; h.dac_hits=1; h.adc_hits=1; h.adc_version=0x000a0300u; h.dac_version=0x00090162u;
        char *t=NULL; size_t b=0; FILE *o=open_memstream(&t,&b); CHECK(o!=NULL);
        if (o) {
            CHECK(!sle_rt_hwstat_write(&h,o,3)); CHECK(!fclose(o));
            CHECK(strstr(t,"\"kind\":\"hw_status_summary\",\"attempt\":3")!=NULL);
            CHECK(strstr(t,"\"dac_version\":\"0x00090162\"")!=NULL && strstr(t,"\"events\":2")!=NULL);
            CHECK(strstr(t,"\"i\":0,\"mono_ns\":10,\"prev_poll_ns\":5,\"rx_head\":4096,\"tx_head\":7168,\"dac_unf\":1,\"adc_ovf\":0")!=NULL);
            CHECK(strstr(t,"\"adc_ovf\":1,\"dac_after_clear\":0,\"adc_after_clear\":1")!=NULL);
            free(t);
        }
    }
    CHECK(!sle_rt_radio_restore());
    for (unsigned i=0;i<stored;i++) CHECK(!strcmp(store[i].val,store[i].original));
    concurrent_ring(); free(r);
    printf("Radio mock DMA/lifecycle: %u checks, %u failures (no hardware)\n",checks,failures);
    return failures ? 1 : 0;
}
