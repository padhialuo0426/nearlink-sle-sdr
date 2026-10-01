#define _GNU_SOURCE
#include "sle_hwstat.h"

#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "sle_iio.h"

#define MAP_BYTES 0x1000u

int sle_rt_hwstat_open(sle_rt_hwstat *h)
{
    memset(h,0,sizeof *h); h->fd=-1;
    h->event=calloc(SLE_RT_HW_EVENTS,sizeof *h->event);
    if (!h->event) return -1;
    h->fd=open("/dev/mem",O_RDWR|O_SYNC|O_CLOEXEC);
    if (h->fd<0) goto bad;
    h->adc_map=mmap(NULL,MAP_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED,h->fd,SLE_RT_HW_ADC_BASE);
    h->dac_map=mmap(NULL,MAP_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED,h->fd,SLE_RT_HW_DAC_BASE);
    if (h->adc_map==MAP_FAILED || h->dac_map==MAP_FAILED) goto bad;
    h->adc=h->adc_map; h->dac=h->dac_map;
    h->adc_version=h->adc[0]; h->dac_version=h->dac[0];
    /* Refuse unknown cores: the bit layout is only verified for these. */
    if (h->adc_version!=0x000a0300u || h->dac_version!=0x00090162u) goto bad;
    return 0;
bad:
    sle_rt_hwstat_close(h); return -1;
}

int sle_rt_hwstat_track_dma(sle_rt_hwstat *h)
{
    if (!h || h->fd<0 || h->started) return -1;
    const uint32_t base[2]={SLE_RT_HW_RX_DMAC,SLE_RT_HW_TX_DMAC};
    for (int i=0;i<2;i++) {
        h->dmac_map[i]=mmap(NULL,MAP_BYTES,PROT_READ,MAP_SHARED,h->fd,base[i]);
        if (h->dmac_map[i]==MAP_FAILED) { h->dmac_map[i]=NULL; return -1; }
        h->dmac[i]=h->dmac_map[i]; h->dmac_version[i]=h->dmac[i][0];
        if (h->dmac_version[i]!=SLE_RT_HW_DMAC_VERSION) return -1;
    }
    h->dma_track=1;
    return 0;
}

static void dma_poll(sle_rt_hwstat *h, int64_t now)
{
    for (int i=0;i<2;i++) {
        sle_rt_hw_dma *d=&h->dma[i];
        uint32_t p=h->dmac[i][SLE_RT_HW_DMAC_PENDING/4]&3u;
        if (p && !d->prev) { d->first_ns=now; d->episodes++; }
        if (p) { if (d->prev) d->multi+=d->last_ns==d->first_ns; d->last_ns=now; }
        else if (d->prev) {
            int64_t lo=d->last_ns-d->first_ns;
            uint64_t b=(uint64_t)(lo/10000); if (b>=SLE_RT_HW_DMA_BINS) b=SLE_RT_HW_DMA_BINS-1;
            d->hist[b]++;
            if (lo>d->max_lo_ns) { d->max_lo_ns=lo; d->max_at_ns=d->first_ns; }
            if (lo>=100000) {
                if (d->n_long<SLE_RT_HW_DMA_LONG) {
                    d->long_at_ns[d->n_long]=d->first_ns; d->long_lo_ns[d->n_long]=lo;
                    d->long_rx[d->n_long]=h->radio ? atomic_load(&h->radio->rx_head) : -1;
                    d->long_tx[d->n_long]=h->radio ? atomic_load(&h->radio->tx_head) : -1;
                }
                d->n_long++;
            }
        }
        d->prev=p;
    }
}

static void *poll_loop(void *arg)
{
    sle_rt_hwstat *h=arg;
    /* No mlockall here: it would re-fault the whole process while the radio
     * streams. The control thread's MCL_FUTURE already covers our buffer. */
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(h->cpu,&set);
    if (pthread_setaffinity_np(pthread_self(),sizeof set,&set)) { atomic_store(&h->ready,-1); return NULL; }
    if (h->prio>0) {
        struct sched_param sp={.sched_priority=h->prio};
        if (pthread_setschedparam(pthread_self(),SCHED_FIFO,&sp)) { atomic_store(&h->ready,-1); return NULL; }
    }
    const uint32_t reg=SLE_RT_HW_STATUS_REG/4;
    /* Record and clear whatever is latched from the idle period first. */
    h->dac_initial=h->dac[reg]; h->adc_initial=h->adc[reg];
    h->dac[reg]=SLE_RT_HW_DAC_UNF; h->adc[reg]=SLE_RT_HW_ADC_OVF;
    h->start_ns=h->last_poll_ns=sle_iio_now_ns();
    atomic_store(&h->ready,1);
    struct timespec nap={0,(long)h->period_ns};
    while (!atomic_load_explicit(&h->stop,memory_order_acquire)) {
        uint32_t d=h->dac[reg]&SLE_RT_HW_DAC_UNF, a=h->adc[reg]&SLE_RT_HW_ADC_OVF;
        int64_t now=sle_iio_now_ns(), gap=now-h->last_poll_ns;
        if (gap>h->max_gap_ns) { h->max_gap_ns=gap; h->max_gap_at_ns=now; }
        h->polls++;
        if (h->dma_track) dma_poll(h,now);
        if (d || a) {
            if (d) { h->dac[reg]=d; h->dac_hits++; }
            if (a) { h->adc[reg]=a; h->adc_hits++; }
            if (h->n_events<SLE_RT_HW_EVENTS) {
                sle_rt_hw_event *e=&h->event[h->n_events];
                e->mono_ns=now; e->prev_poll_ns=h->last_poll_ns;
                e->rx_head=h->radio ? atomic_load(&h->radio->rx_head) : -1;
                e->tx_head=h->radio ? atomic_load(&h->radio->tx_head) : -1;
                e->dac=d; e->adc=a;
                e->dac_after=h->dac[reg]&SLE_RT_HW_DAC_UNF; e->adc_after=h->adc[reg]&SLE_RT_HW_ADC_OVF;
                h->n_events++;
            } else h->dropped++;
        }
        h->last_poll_ns=now;
        nanosleep(&nap,NULL);
    }
    h->end_ns=sle_iio_now_ns();
    return NULL;
}

int sle_rt_hwstat_start(sle_rt_hwstat *h, sle_rt_radio *r, int cpu, int prio, int64_t period_ns)
{
    if (!h || h->fd<0 || h->started) return -1;
    h->radio=r; h->cpu=cpu; h->prio=prio; h->period_ns=period_ns>0 ? period_ns:50000;
    atomic_init(&h->stop,0); atomic_init(&h->ready,0);
    if (pthread_create(&h->thread,NULL,poll_loop,h)) return -1;
    h->started=1;
    /* The caller may be a higher-priority FIFO thread on the same CPU, so
     * sleep (sched_yield would never run the lower-priority poller). */
    int64_t end=sle_iio_now_ns()+100000000;
    struct timespec pause={0,50000};
    while (!atomic_load(&h->ready) && sle_iio_now_ns()<end) nanosleep(&pause,NULL);
    if (atomic_load(&h->ready)!=1) { sle_rt_hwstat_stop(h); return -1; }
    return 0;
}

int sle_rt_hwstat_stop(sle_rt_hwstat *h)
{
    if (!h || !h->started) return 0;
    atomic_store_explicit(&h->stop,1,memory_order_release);
    int e=pthread_join(h->thread,NULL);
    h->started=0;
    return e ? -1:0;
}

void sle_rt_hwstat_close(sle_rt_hwstat *h)
{
    if (!h) return;
    sle_rt_hwstat_stop(h);
    if (h->adc_map && h->adc_map!=MAP_FAILED) munmap(h->adc_map,MAP_BYTES);
    if (h->dac_map && h->dac_map!=MAP_FAILED) munmap(h->dac_map,MAP_BYTES);
    for (int i=0;i<2;i++) if (h->dmac_map[i]) munmap(h->dmac_map[i],MAP_BYTES);
    h->dmac_map[0]=h->dmac_map[1]=NULL; h->dmac[0]=h->dmac[1]=NULL; h->dma_track=0;
    if (h->fd>=0) close(h->fd);
    free(h->event);
    h->adc_map=h->dac_map=NULL; h->adc=h->dac=NULL; h->fd=-1; h->event=NULL;
}

int sle_rt_hwstat_write(const sle_rt_hwstat *h, FILE *out, int attempt)
{
    if (!h || !out || h->started) return -1;
    if (fprintf(out,"{\"kind\":\"hw_status_summary\",\"attempt\":%d,\"adc_base\":\"0x%08x\","
        "\"dac_base\":\"0x%08x\",\"status_reg\":\"0x%02x\",\"adc_version\":\"0x%08x\","
        "\"dac_version\":\"0x%08x\",\"dac_unf_mask\":%u,\"adc_ovf_mask\":%u,"
        "\"dac_initial\":%u,\"adc_initial\":%u,\"cpu\":%d,\"prio\":%d,\"period_ns\":%" PRId64 ","
        "\"start_ns\":%" PRId64 ",\"end_ns\":%" PRId64 ",\"polls\":%" PRIu64 ","
        "\"max_gap_ns\":%" PRId64 ",\"max_gap_at_ns\":%" PRId64 ",\"dac_hits\":%" PRIu64 ","
        "\"adc_hits\":%" PRIu64 ",\"events\":%" PRIu64 ",\"dropped\":%" PRIu64 "}\n",
        attempt,SLE_RT_HW_ADC_BASE,SLE_RT_HW_DAC_BASE,SLE_RT_HW_STATUS_REG,h->adc_version,h->dac_version,
        SLE_RT_HW_DAC_UNF,SLE_RT_HW_ADC_OVF,h->dac_initial,h->adc_initial,h->cpu,h->prio,h->period_ns,
        h->start_ns,h->end_ns,h->polls,h->max_gap_ns,h->max_gap_at_ns,h->dac_hits,h->adc_hits,
        h->n_events,h->dropped)<0) return -1;
    for (int k=0;h->dma_track && k<2;k++) {
        const sle_rt_hw_dma *d=&h->dma[k];
        if (fprintf(out,"{\"kind\":\"hw_dma_latency\",\"attempt\":%d,\"dmac\":\"%s\",\"version\":\"0x%08x\","
            "\"episodes\":%" PRIu64 ",\"multi_poll\":%" PRIu64 ",\"max_lo_ns\":%" PRId64 ",\"max_at_ns\":%" PRId64 ","
            "\"n_ge_100us\":%" PRIu64 ",\"hist_10us\":[",attempt,k ? "tx":"rx",h->dmac_version[k],
            d->episodes,d->multi,d->max_lo_ns,d->max_at_ns,d->n_long)<0) return -1;
        for (unsigned b=0;b<SLE_RT_HW_DMA_BINS;b++) if (fprintf(out,"%s%" PRIu64,b ? ",":"",d->hist[b])<0) return -1;
        if (fprintf(out,"]}\n")<0) return -1;
        for (uint64_t j=0;j<d->n_long && j<SLE_RT_HW_DMA_LONG;j++)
            if (fprintf(out,"{\"kind\":\"hw_dma_long\",\"attempt\":%d,\"dmac\":\"%s\",\"first_ns\":%" PRId64
                ",\"lo_ns\":%" PRId64 ",\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64 "}\n",attempt,k ? "tx":"rx",
                d->long_at_ns[j],d->long_lo_ns[j],d->long_rx[j],d->long_tx[j])<0) return -1;
    }
    for (uint64_t i=0;i<h->n_events;i++) {
        const sle_rt_hw_event *e=&h->event[i];
        if (fprintf(out,"{\"kind\":\"hw_status\",\"attempt\":%d,\"i\":%" PRIu64 ",\"mono_ns\":%" PRId64
            ",\"prev_poll_ns\":%" PRId64 ",\"rx_head\":%" PRId64 ",\"tx_head\":%" PRId64
            ",\"dac_unf\":%u,\"adc_ovf\":%u,\"dac_after_clear\":%u,\"adc_after_clear\":%u}\n",
            attempt,i,e->mono_ns,e->prev_poll_ns,e->rx_head,e->tx_head,e->dac?1u:0u,e->adc?1u:0u,
            e->dac_after?1u:0u,e->adc_after?1u:0u)<0) return -1;
    }
    return 0;
}
