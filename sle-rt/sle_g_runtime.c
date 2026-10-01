#define _GNU_SOURCE
#include "sle_g_runtime.h"
#include "sle_cmtc.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

void sle_rt_wipe(void *p, size_t n)
{
    volatile uint8_t *v=p;
    while (n--) *v++=0;
}
int sle_rt_queue(sle_rt_tx_store *s, sle_link_t *l, uint8_t type, const uint8_t *p, size_t n)
{
    if (!p || !n || n>SLE_RT_TX_MAX) return -1;
    for (unsigned i=0;i<SLE_RT_TX_SLOTS;i++) {
        if (s->used[i]) {
            int live=l->arq.has_cur && l->cur.data==s->data[i];
            for (unsigned j=0;j<l->q_len && !live;j++)
                live=l->q[(l->q_head+j)%SLE_LINK_QUEUE_MAX].data==s->data[i];
            if (live) continue;
            sle_rt_wipe(s->data[i],sizeof s->data[i]); s->used[i]=0;
        }
        memcpy(s->data[i],p,n);
        if (sle_link_push(l,type,s->data[i],(uint16_t)n)) {
            sle_rt_wipe(s->data[i],sizeof s->data[i]); return -1;
        }
        s->used[i]=1; return 0;
    }
    return -2;
}
unsigned sle_rt_free_slots(const sle_rt_tx_store *s, const sle_link_t *l)
{
    unsigned n=0;
    for (unsigned i=0;i<SLE_RT_TX_SLOTS;i++) {
        int live=s->used[i] && l->arq.has_cur && l->cur.data==s->data[i];
        for (unsigned j=0;s->used[i] && j<l->q_len && !live;j++)
            live=l->q[(l->q_head+j)%SLE_LINK_QUEUE_MAX].data==s->data[i];
        n+=!live;
    }
    return n;
}
static int os_random(void *ctx, uint8_t *out, size_t n)
{
    int fd=*(const int *)ctx;
    while (n) {
        ssize_t got=getrandom(out,n,0);
        if (got<0 && errno==ENOSYS) got=read(fd,out,n);
        if (got<0 && errno==EINTR) continue;
        if (got<=0) return -1;
        out+=(size_t)got; n-=(size_t)got;
    }
    return 0;
}
static void *work_main(void *arg)
{
    /* arg owns work/results only: no route to the live pair or link object. */
    sle_rt_worker *w=arg;
    for (;;) {
        int e;
        do { e=sem_wait(&w->wake); } while (e && errno==EINTR);
        if (e || atomic_load_explicit(&w->stop,memory_order_acquire)) break;
        if (atomic_load_explicit(&w->job,memory_order_acquire)!=1) continue;
        int rc=sle_pair_run_work(&w->work,&w->result);
        if (rc && !w->result.error) w->result.error=rc;
        atomic_store_explicit(&w->job,2,memory_order_release);
    }
    return NULL;
}
static int worker_start(sle_rt_worker *w, int cpu)
{
    atomic_init(&w->stop,0); atomic_init(&w->job,0);
    if (cpu<0 || cpu>=CPU_SETSIZE || sem_init(&w->wake,0,0)) return -1;
    w->sem_ready=1;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr)) return -1;
    struct sched_param sp={.sched_priority=0};
    cpu_set_t cpus; CPU_ZERO(&cpus); CPU_SET(cpu,&cpus);
    int e=pthread_attr_setinheritsched(&attr,PTHREAD_EXPLICIT_SCHED);
    if (!e) e=pthread_attr_setstacksize(&attr,256u*1024u);
    if (!e) e=pthread_attr_setschedpolicy(&attr,SCHED_OTHER);
    if (!e) e=pthread_attr_setschedparam(&attr,&sp);
    if (!e) e=pthread_attr_setaffinity_np(&attr,sizeof cpus,&cpus);
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block,SIGINT); sigaddset(&block,SIGTERM);
    sigaddset(&block,SIGHUP); sigaddset(&block,SIGPIPE);
    int masked=0;
    if (!e) { e=pthread_sigmask(SIG_BLOCK,&block,&old); masked=!e; }
    if (!e) { e=pthread_create(&w->thread,&attr,work_main,w); w->started=!e; }
    if (masked && pthread_sigmask(SIG_SETMASK,&old,NULL)) e=-1;
    pthread_attr_destroy(&attr);
    return e ? -1:0;
}
int sle_g_runtime_destroy(sle_g_runtime *r)
{
    if (!r) return 0;
    sle_rt_worker *w=&r->worker;
    if (w->started) {
        atomic_store_explicit(&w->stop,1,memory_order_release);
        if (sem_post(&w->wake) || pthread_join(w->thread,NULL)) return -1;
        w->started=0;
    }
    if (w->sem_ready) { sem_destroy(&w->wake); w->sem_ready=0; }
    sle_pair_work_clear(&w->work); sle_pair_work_result_clear(&w->result);
    sle_pair_clear(&r->pair);
    if (r->initialized && r->rng_fd>=0) close(r->rng_fd);
    sle_rt_wipe(r,sizeof *r); r->rng_fd=-1;
    return 0;
}
int sle_g_runtime_init(sle_g_runtime *r, const uint8_t g[6], const uint8_t t[6],
                    uint32_t sync_low32, int cpu)
{
    return sle_g_runtime_init_variant(r,g,t,sync_low32,cpu,SLE_PAIR_PROFILE_WS63);
}
int sle_g_runtime_init_variant(sle_g_runtime *r, const uint8_t g[6], const uint8_t t[6],
                            uint32_t sync_low32, int cpu, unsigned variant)
{
    memset(r,0,sizeof *r); r->initialized=1;
    r->rng_fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);
    int e=r->rng_fd<0 ? SLE_PAIR_ERR_RNG:0;
    sle_pair_config_t cfg={.sync_low32=sync_low32,.rng=os_random,.rng_ctx=&r->rng_fd,.variant=variant};
    memcpy(cfg.g_addr,g,6); memcpy(cfg.t_addr,t,6); memcpy(r->peer,t,6);
    if (!e) e=sle_pair_init(&r->pair,&cfg);
    if (!e) e=sle_pair_prepare(&r->pair);
    if (!e && worker_start(&r->worker,cpu)) e=SLE_PAIR_ERR_STATE;
    r->error=e;
    return e;
}
static int failed(sle_g_runtime *r, int e)
{
    if (e<0 && !r->error) r->error=e;
    return e;
}
int sle_g_runtime_start(sle_g_runtime *r, uint64_t now)
{
    if (r->error) return r->error;
    return failed(r,sle_pair_start(&r->pair,now));
}
int sle_g_runtime_poll(sle_g_runtime *r, uint64_t now)
{
    if (r->error) return r->error;
    int e=sle_pair_tick(&r->pair,now);
    if (e) return failed(r,e);
    sle_rt_worker *w=&r->worker;
    int job=atomic_load_explicit(&w->job,memory_order_acquire);
    if (job==2) {
        e=sle_pair_finish_work(&r->pair,&w->result,now);
        atomic_store_explicit(&w->job,0,memory_order_release);
        if (e) return failed(r,e);
        job=0;
    }
    sle_pair_status_t status; sle_pair_status(&r->pair,&status);
    if (!job && status.state==SLE_PAIR_WAIT_ECDH) {
        if (!w->started) return failed(r,SLE_PAIR_ERR_STATE);
        e=sle_pair_take_work(&r->pair,&w->work);
        if (e) return failed(r,e);
        atomic_store_explicit(&w->job,1,memory_order_release);
        if (sem_post(&w->wake)) return failed(r,SLE_PAIR_ERR_STATE);
    }
    return 0;
}
int sle_g_runtime_queue(sle_g_runtime *r, sle_rt_tx_store *s, sle_link_t *l)
{
    if (r->error) return r->error;
    sle_pair_pdu_t pdu;
    int e=sle_pair_pop(&r->pair,&pdu);
    if (e==1) {
        if (pdu.len+(pdu.encrypted ? 4u:0u)>SLE_RT_TX_MAX ||
            sle_rt_queue(s,l,SLE_PTYPE_CTRL,pdu.data,pdu.len)) e=SLE_PAIR_ERR_QUEUE;
        else e=0;
    }
    sle_rt_wipe(&pdu,sizeof pdu);
    return failed(r,e);
}
int sle_g_runtime_tx(sle_g_runtime *r, sle_link_tx_t *tx)
{
    if (r->error) return r->error;
    if (tx->empty && !tx->len) return 0;
    sle_pair_status_t s; sle_pair_status(&r->pair,&s);
    size_t n=tx->len;
    if (!n || n+(s.secure ? 4u:0u)>SLE_RT_TX_MAX) return failed(r,SLE_PAIR_ERR_LENGTH);
    if (r->tx_cached && r->tx_secure!=s.secure) return failed(r,SLE_PAIR_ERR_STATE);
    if (s.secure) {
        /* g_prepare counts unsent/skipped events as retx. Only OUR cache
         * determines whether this PDU already consumed a CCM counter. */
        int e=sle_pair_protect(&r->pair,tx->data,n,tx->sn,r->tx_cached,
                               r->wire,sizeof r->wire,&n);
        if (e) return failed(r,e);
    } else memcpy(r->wire,tx->data,n);
    r->tx_secure=s.secure;
    r->tx_business=s.state==SLE_PAIR_ENCRYPTED && tx->ptype!=SLE_PTYPE_CTRL;
    r->tx_cached=1;
    tx->data=r->wire; tx->len=(uint16_t)n;
    return 0;
}
void sle_g_runtime_submitted(sle_g_runtime *r, const sle_link_tx_t *tx)
{
    if (!tx->empty && tx->len && r->tx_cached) {
        if (!r->tx_submitted && !r->tx_secure &&
            (r->pair.cfg.variant & SLE_PAIR_V_COUNT_PLAIN)) {
            if (r->plain_tx >= SLE_PAIR_COUNTER_LIMIT - 1)
                failed(r,SLE_PAIR_ERR_COUNTER);
            else r->plain_tx++;
        }
        r->tx_submitted=1;
    }
}
int sle_g_runtime_encrypted(const sle_g_runtime *r)
{
    sle_pair_status_t s; sle_pair_status(&r->pair,&s);
    return !r->error && s.secure && s.state==SLE_PAIR_ENCRYPTED;
}
static int control_rx(sle_g_runtime *r, const sle_link_rx_t *rx,
                      sle_rt_rx *v, uint64_t now, size_t *n)
{
    /* The required pair API authenticates the actual wire exactly once and
     * classifies it. Ordinary controls return plaintext for link_on_rx;
     * verified duplicates return no plaintext and cannot be dispatched twice. */
    int e=sle_pair_on_control_ex(&r->pair,r->peer,rx->data,rx->len,rx->sn,
        v->duplicate,now,v->plain,sizeof v->plain,n,&v->pair_control);
    if (e>=0 && *n>=3) v->opcode=(uint16_t)(v->plain[0]|v->plain[1]<<8);
    return e;
}
int sle_g_runtime_rx(sle_g_runtime *r, sle_link_t *l, const sle_link_rx_t *wire,
                  sle_link_rx_out_t *out, sle_rt_rx *v, uint64_t now)
{
    memset(v,0,sizeof *v); memset(out,0,sizeof *out);
    if (r->error) return r->error;
    int e=sle_g_runtime_poll(r,now);
    if (e) return e;
    sle_pair_status_t s; sle_pair_status(&r->pair,&s);
    sle_link_rx_t rx=*wire;
    if (!l->have_event || l->down) return 1;
    if (rx.len>sizeof v->plain || (rx.len && !rx.data) || (rx.empty && rx.len))
        return failed(r,SLE_PAIR_ERR_LENGTH);
    /* A corrupt protected body may not acknowledge an outstanding PDU via
     * its CRC-only NESN. Legacy radio BODYFAIL behaviour remains outside G pairing. */
    if (!rx.empty && rx.kind!=SLE_RX_OK) return 1;
    v->duplicate=!rx.empty && rx.sn!=l->arq.rx_nesn; /* BEFORE link_on_rx */
    size_t n=0;
    if (!rx.empty && rx.kind==SLE_RX_OK) {
        if (!rx.len) return failed(r,SLE_PAIR_ERR_LENGTH);
        v->protected_frame=s.secure;
        if (rx.ptype==SLE_PTYPE_CTRL) e=control_rx(r,&rx,v,now,&n);
        else if (s.state==SLE_PAIR_ENCRYPTED) {
            e=sle_pair_unprotect(&r->pair,rx.data,rx.len,rx.sn,v->duplicate,
                                 v->plain,sizeof v->plain,&n);
        } else if (rx.ptype==SLE_PTYPE_DATA && !s.secure &&
                   (sle_cmtc_capability_req_pdu(rx.data,rx.len) ||
                    sle_cmtc_capability_rsp_pdu(rx.data,rx.len))) {
            /* 1.10.108 CMTC exchange on link creation, before any pairing. */
            memcpy(v->plain,rx.data,rx.len); n=rx.len; e=0;
        } else e=SLE_PAIR_ERR_STATE; /* no user data while starting security */
        if (e<0) {
            if (e==SLE_PAIR_ERR_MIC) { v->mic=-1; r->mic_failed++; }
            sle_rt_wipe(v->plain,sizeof v->plain);
            return failed(r,e); /* ARQ/ACK/supervision untouched */
        }
        /* Exact last plaintext 0006 duplicate has no MIC. The pair module
         * alone authorizes that exception; do not count it as authenticated. */
        int plain_retry=s.state==SLE_PAIR_WAIT_SECURITY_ACK && v->duplicate &&
            rx.ptype==SLE_PTYPE_CTRL && rx.len==3 && rx.data[0]==6 && !rx.data[1] && !rx.data[2];
        v->protected_frame=s.secure && !plain_retry;
        if (v->protected_frame) { v->mic=1; r->mic_ok++; }
        rx.data=v->plain; rx.len=(uint16_t)n;
        if (v->pair_control) { rx.ptype=SLE_PTYPE_DATA; rx.len=0; }
    }
    sle_link_on_rx(l,&rx,out);
    if (out->acked) {
        if (r->tx_cached && r->tx_submitted && r->tx_secure && r->tx_business)
            r->protected_tx_acked++;
        r->tx_cached=r->tx_secure=r->tx_business=r->tx_submitted=0;
        /* wire is still used by this event's own-witness comparison. */
    }
    if ((r->pair.cfg.variant & SLE_PAIR_V_COUNT_PLAIN) &&
        !s.secure && !wire->empty && wire->len && !v->duplicate) {
        if (r->plain_rx >= SLE_PAIR_COUNTER_LIMIT - 1)
            return failed(r,SLE_PAIR_ERR_COUNTER);
        r->plain_rx++;
        sle_pair_status_t after; sle_pair_status(&r->pair,&after);
        if (after.secure) {
            /* Include the accepted plaintext 0006. Its retry cannot enter
             * this branch, so counters are seeded exactly once. */
            e=sle_pair_seed_plain_counters(&r->pair,r->plain_tx,r->plain_rx);
            if (e) return failed(r,e);
        }
    }
    if (v->pair_control) { out->deliver=0; out->data=NULL; out->len=0; }
    if (out->deliver && out->len && out->ptype!=SLE_PTYPE_CTRL && v->protected_frame)
        r->protected_rx++;
    if (!r->encrypted_ms && sle_g_runtime_encrypted(r)) r->encrypted_ms=now;
    return 0;
}
int sle_g_runtime_accepted(const sle_g_runtime *r, int ssap, int validated, int write, int verified)
{
    return sle_g_runtime_encrypted(r) && (!ssap ||
        (validated && r->protected_tx_acked && r->protected_rx)) && (!write || verified);
}
