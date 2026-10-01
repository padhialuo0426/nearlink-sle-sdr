#define _GNU_SOURCE
#include "sle_t_runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

static int os_random(void *ctx, uint8_t *out, size_t n) {
  int fd = *(const int *)ctx;
  while (n) {
    ssize_t got = getrandom(out, n, 0);
    if (got < 0 && errno == ENOSYS)
      got = read(fd, out, n);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return -1;
    out += (size_t)got;
    n -= (size_t)got;
  }
  return 0;
}
static void *work_main(void *arg) {
  /* arg owns work/results only: no route to the live pair or link object. */
  sle_rt_worker *w = arg;
  for (;;) {
    int e;
    do {
      e = sem_wait(&w->wake);
    } while (e && errno == EINTR);
    if (e || atomic_load_explicit(&w->stop, memory_order_acquire))
      break;
    if (atomic_load_explicit(&w->job, memory_order_acquire) != 1)
      continue;
    int rc = sle_pair_run_work(&w->work, &w->result);
    if (rc && !w->result.error)
      w->result.error = rc;
    atomic_store_explicit(&w->job, 2, memory_order_release);
  }
  return NULL;
}
static int worker_start(sle_rt_worker *w, int cpu) {
  atomic_init(&w->stop, 0);
  atomic_init(&w->job, 0);
  if (cpu < 0 || cpu >= CPU_SETSIZE || sem_init(&w->wake, 0, 0))
    return -1;
  w->sem_ready = 1;
  pthread_attr_t attr;
  if (pthread_attr_init(&attr))
    return -1;
  struct sched_param sp = {.sched_priority = 0};
  cpu_set_t cpus;
  CPU_ZERO(&cpus);
  CPU_SET(cpu, &cpus);
  int e = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
  if (!e)
    e = pthread_attr_setstacksize(&attr, 256u * 1024u);
  if (!e)
    e = pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
  if (!e)
    e = pthread_attr_setschedparam(&attr, &sp);
  if (!e)
    e = pthread_attr_setaffinity_np(&attr, sizeof cpus, &cpus);
  sigset_t block, old;
  sigemptyset(&block);
  sigaddset(&block, SIGINT);
  sigaddset(&block, SIGTERM);
  sigaddset(&block, SIGHUP);
  sigaddset(&block, SIGPIPE);
  int masked = 0;
  if (!e) {
    e = pthread_sigmask(SIG_BLOCK, &block, &old);
    masked = !e;
  }
  if (!e) {
    e = pthread_create(&w->thread, &attr, work_main, w);
    w->started = !e;
  }
  if (masked && pthread_sigmask(SIG_SETMASK, &old, NULL))
    e = -1;
  pthread_attr_destroy(&attr);
  return e ? -1 : 0;
}
int sle_t_runtime_destroy(sle_t_runtime *r) {
  if (!r)
    return 0;
  sle_rt_worker *w = &r->worker;
  if (w->started) {
    atomic_store_explicit(&w->stop, 1, memory_order_release);
    if (sem_post(&w->wake) || pthread_join(w->thread, NULL))
      return -1;
    w->started = 0;
  }
  if (w->sem_ready) {
    sem_destroy(&w->wake);
    w->sem_ready = 0;
  }
  sle_pair_work_clear(&w->work);
  sle_pair_work_result_clear(&w->result);
  sle_t_pair_clear(&r->pair);
  if (r->initialized && r->rng_fd >= 0)
    close(r->rng_fd);
  sle_rt_wipe(r, sizeof *r);
  r->rng_fd = -1;
  return 0;
}
static int failed(sle_t_runtime *r, int e) {
  if (e < 0 && !r->error)
    r->error = e;
  return e;
}
int sle_t_runtime_init(sle_t_runtime *r, const uint8_t t[6], int cpu) {
  return sle_t_runtime_init_variant(r, t, cpu, SLE_PAIR_PROFILE_WS63);
}
int sle_t_runtime_init_variant(sle_t_runtime *r, const uint8_t t[6], int cpu,
                            unsigned variant) {
  if (!r || !t)
    return SLE_PAIR_ERR_ARGUMENT;
  memset(r, 0, sizeof *r);
  r->initialized = 1;
  r->rng_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  int e = r->rng_fd < 0 ? SLE_PAIR_ERR_RNG : 0;
  sle_pair_config_t cfg = {.rng = os_random,
                           .rng_ctx = &r->rng_fd,
                           .variant = variant};
  memcpy(cfg.t_addr, t, 6);
  memcpy(cfg.g_addr, t, 6);
  cfg.g_addr[0] ^= 2;
  if (!e)
    e = sle_t_pair_init(&r->pair, &cfg);
  if (!e)
    e = sle_t_pair_prepare(&r->pair);
  if (!e && worker_start(&r->worker, cpu))
    e = SLE_PAIR_ERR_STATE;
  r->error = e;
  return e;
}
int sle_t_runtime_bind(sle_t_runtime *r, const uint8_t g[6], uint32_t sync) {
  if (!r || !g)
    return SLE_PAIR_ERR_ARGUMENT;
  if (r->error)
    return r->error;
  sle_t_pair *p = &r->pair;
  if (!r->initialized || r->bound || p->state != SLE_T_PAIR_READY || p->rx_valid ||
      p->tx_valid || p->count || p->rx_next || p->tx_next ||
      !memcmp(g, p->cfg.t_addr, 6))
    return SLE_PAIR_ERR_STATE;
  memcpy(p->cfg.g_addr, g, 6);
  memcpy(r->peer, g, 6);
  p->cfg.sync_low32 = sync;
  r->bound = 1;
  return 0;
}
int sle_t_runtime_poll(sle_t_runtime *r, uint64_t now) {
  if (r->error)
    return r->error;
  int e = sle_t_pair_tick(&r->pair, now);
  if (e)
    return failed(r, e);
  sle_rt_worker *w = &r->worker;
  int job = atomic_load_explicit(&w->job, memory_order_acquire);
  if (job == 2) {
    e = sle_t_pair_finish_work(&r->pair, &w->result, now);
    atomic_store_explicit(&w->job, 0, memory_order_release);
    if (e)
      return failed(r, e);
    job = 0;
  }
  if (!job && r->pair.state == SLE_T_PAIR_WAIT_WORK && !r->pair.work_taken) {
    if (!w->started)
      return failed(r, SLE_PAIR_ERR_STATE);
    e = sle_t_pair_take_work(&r->pair, &w->work);
    if (e)
      return failed(r, e);
    atomic_store_explicit(&w->job, 1, memory_order_release);
    if (sem_post(&w->wake))
      return failed(r, SLE_PAIR_ERR_STATE);
  }
  if (!r->encrypted_ms && sle_t_runtime_encrypted(r))
    r->encrypted_ms = now;
  return 0;
}
int sle_t_runtime_queue(sle_t_runtime *r, sle_rt_tx_store *s, sle_link_t *l) {
  if (r->error)
    return r->error;
  if (!r->bound)
    return SLE_PAIR_ERR_STATE;
  sle_pair_pdu_t pdu;
  int e = sle_t_pair_pop(&r->pair, &pdu);
  if (e == 1) {
    e = (pdu.len + (pdu.encrypted ? 4u : 0u) > SLE_RT_TX_MAX ||
         sle_rt_queue(s, l, SLE_PTYPE_CTRL, pdu.data, pdu.len))
            ? SLE_PAIR_ERR_QUEUE
            : 0;
  }
  sle_rt_wipe(&pdu, sizeof pdu);
  return failed(r, e);
}
int sle_t_runtime_tx(sle_t_runtime *r, sle_link_tx_t *tx) {
  if (r->error)
    return r->error;
  if (!r->bound)
    return SLE_PAIR_ERR_STATE;
  if (tx->empty && !tx->len)
    return 0;
  size_t n = 0;
  int e = sle_t_pair_tx(&r->pair, tx->ptype, tx->data, tx->len, tx->sn,
                       r->tx_cached, r->wire, sizeof r->wire, &n);
  if (e)
    return failed(r, e);
  r->tx_secure = r->pair.tx_cached_secure;
  r->tx_business =
      r->pair.state == SLE_T_PAIR_ENCRYPTED && tx->ptype != SLE_PTYPE_CTRL;
  r->tx_cached = 1;
  tx->data = r->wire;
  tx->len = (uint16_t)n;
  return 0;
}
int sle_t_runtime_submitted(sle_t_runtime *r, const sle_link_tx_t *tx) {
  if (r->error)
    return r->error;
  if (tx->empty && !tx->len)
    return 0;
  if (!r->tx_cached)
    return failed(r, SLE_PAIR_ERR_STATE);
  int e = sle_t_pair_submitted(&r->pair, tx->sn);
  if (!e)
    r->tx_submitted = 1;
  return failed(r, e);
}
int sle_t_runtime_encrypted(const sle_t_runtime *r) {
  return !r->error && r->bound && r->pair.state == SLE_T_PAIR_ENCRYPTED;
}
int sle_t_runtime_rx(sle_t_runtime *r, sle_link_t *l, const sle_link_rx_t *wire,
                  sle_link_rx_out_t *out, sle_rt_rx *v, uint64_t now) {
  memset(v, 0, sizeof *v);
  memset(out, 0, sizeof *out);
  if (r->error)
    return r->error;
  if (!r->bound)
    return SLE_PAIR_ERR_STATE;
  int e = sle_t_runtime_poll(r, now);
  if (e)
    return e;
  sle_link_rx_t rx = *wire;
  if (!l->have_event || l->down)
    return 1;
  if (rx.len > sizeof v->plain || (rx.len && !rx.data) || (rx.empty && rx.len))
    return failed(r, SLE_PAIR_ERR_LENGTH);
  if (!rx.empty && rx.kind != SLE_RX_OK)
    return 1;
  v->duplicate = !rx.empty && rx.sn != l->arq.rx_nesn;
  if (!rx.empty && rx.kind == SLE_RX_OK) {
    size_t n = 0;
    int secure = r->pair.rx_secure;
    e = sle_t_pair_rx(&r->pair, r->peer, rx.ptype, rx.data, rx.len, rx.sn,
                     v->duplicate, now, v->plain, sizeof v->plain, &n,
                     &v->pair_control);
    if (e < 0) {
      if (e == SLE_PAIR_ERR_MIC) {
        v->mic = -1;
        r->mic_failed++;
      }
      sle_rt_wipe(v->plain, sizeof v->plain);
      return failed(r, e);
    }
    v->protected_frame = v->duplicate ? r->pair.rx_cached_secure : secure;
    if (v->protected_frame) {
      v->mic = 1;
      r->mic_ok++;
    }
    if (rx.ptype == SLE_PTYPE_CTRL && n >= 3)
      v->opcode = (uint16_t)(v->plain[0] | v->plain[1] << 8);
    rx.data = v->plain;
    rx.len = (uint16_t)n;
    if (v->pair_control) {
      rx.ptype = SLE_PTYPE_DATA;
      rx.len = 0;
    }
  }
  sle_link_on_rx(l, &rx, out);
  if (out->acked) {
    if (r->tx_cached && r->tx_submitted && r->tx_secure && r->tx_business)
      r->protected_tx_acked++;
    r->tx_cached = r->tx_secure = r->tx_business = r->tx_submitted = 0;
  }
  if (v->pair_control) {
    out->deliver = 0;
    out->data = NULL;
    out->len = 0;
  }
  if (out->deliver && out->len && out->ptype != SLE_PTYPE_CTRL &&
      v->protected_frame)
    r->protected_rx++;
  if (!r->encrypted_ms && sle_t_runtime_encrypted(r))
    r->encrypted_ms = now;
  return 0;
}
