/* Offline regression; build and coverage notes: ../docs/e310-source.md. */
#define _GNU_SOURCE
#include "sle_g_runtime.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include "sle_cmtc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"G runtime %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); \
} } while (0)
static const uint8_t ga[6]={0xc2,0x53,0x4c,0x45,0,0x10}, ta[6]={1,2,3,4,5,6};
static const uint8_t test_key[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const uint8_t test_iv[8]={0x23,0x41,0x87,0x22,0x61,0x70,0x85,0x49};
static int zero(const void *p,size_t n)
{
    const uint8_t *b=p;
    for (size_t i=0;i<n;i++) if (b[i]) return 0;
    return 1;
}
static void snapshot(sle_g_runtime *r, sle_pair_state_t state)
{
    memset(r,0,sizeof *r); r->rng_fd=-1;
    atomic_init(&r->worker.job,0); atomic_init(&r->worker.stop,0);
    memcpy(r->peer,ta,6); memcpy(r->pair.cfg.t_addr,ta,6); memcpy(r->pair.cfg.g_addr,ga,6);
    r->pair.cfg.variant=0; /* explicit historical fixture, not runtime default */
    r->pair.state=state; r->pair.secure=state>=SLE_PAIR_WAIT_SECURITY_ACK;
    r->pair.cfg.step_timeout_ms=5000; r->pair.cfg.total_timeout_ms=30000;
    memcpy(r->pair.cipher.key,test_key,16); memcpy(r->pair.cipher.iv,test_iv,8);
}
static sle_link_t *link_new(void)
{
    sle_link_t *l=calloc(1,sizeof *l); CHECK(l);
    sle_conn_sched_t s={.t0_ns=1000000,.period_slots=100,.slot_ns=125000,
        .lid=0x66a275,.sync32=0x1c4eac4a,.used={0,2},.n_used=2,.timeout_ms=5000,.intra_gap_ns=150000};
    sle_link_init(l,SLE_LINK_ROLE_G,&s,0xe4004c6e);
    sle_link_tx_t tx; CHECK(!sle_link_g_prepare(l,0,0,&tx));
    return l;
}
static size_t peer_wire(uint8_t *wire,const uint8_t *plain,size_t len,uint64_t counter)
{
    uint8_t nonce[13]={0},aad=0;
    for (unsigned i=0;i<5;i++) nonce[i]=(uint8_t)(counter>>(8*i));
    memcpy(nonce+5,test_iv,8);
    CHECK(!sle_aes_ccm_encrypt(test_key,nonce,13,&aad,1,plain,len,wire,wire+len,4));
    return len+4;
}
static sle_link_tx_t queued(sle_g_runtime *r,sle_rt_tx_store *store,sle_link_t *l,
                            uint8_t type,const uint8_t *p,size_t n)
{
    CHECK(!sle_rt_queue(store,l,type,p,n));
    sle_link_tx_t tx;
    CHECK(!sle_link_g_prepare(l,0,0,&tx));
    CHECK(!sle_g_runtime_tx(r,&tx));
    sle_g_runtime_submitted(r,&tx);
    return tx;
}
static void authentication_and_retry(void)
{
    const uint8_t data[]={0x50,0,0x0a,0,6,0,3,3,8,2,1,0};
    uint8_t wire[128],first_tx[128];
    sle_g_runtime r; snapshot(&r,SLE_PAIR_ENCRYPTED);
    sle_rt_tx_store store={0}; sle_link_t *l=link_new();
    sle_link_tx_t tx=queued(&r,&store,l,SLE_PTYPE_DATA,data,sizeof data);
    CHECK(tx.len==sizeof data+4 && r.pair.cipher.tx_next==1);
    memcpy(first_tx,tx.data,tx.len);
    /* An empty frame does not disturb either counter/retransmission cache. */
    sle_link_tx_t empty={.empty=1,.sn=1}; CHECK(!sle_g_runtime_tx(&r,&empty));
    CHECK(r.pair.cipher.tx_next==1);
    for (unsigned i=0;i<3;i++) {
        CHECK(!sle_link_g_prepare(l,0,0,&tx) && tx.retx);
        CHECK(!sle_g_runtime_tx(&r,&tx));
        CHECK(tx.len==sizeof data+4 && !memcmp(tx.data,first_tx,tx.len));
        CHECK(r.pair.cipher.tx_next==1);
    }
    size_t n=peer_wire(wire,data,sizeof data,0);
    sle_link_rx_t rx={.kind=SLE_RX_OK,.ptype=SLE_PTYPE_DATA,.sn=0,.nesn=1,.data=wire,.len=(uint16_t)n};
    sle_link_rx_out_t out; sle_rt_rx scratch;
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1));
    CHECK(out.acked && out.deliver && !scratch.duplicate && scratch.mic==1);
    CHECK(out.len==sizeof data && !memcmp(out.data,data,sizeof data));
    CHECK(r.pair.cipher.rx_next==1 && l->arq.rx_nesn==1 && l->arq.tx_sn==1);
    CHECK(r.protected_tx_acked==1 && r.protected_rx==1);
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,2));
    CHECK(out.dup && !out.deliver && scratch.duplicate && scratch.mic==1);
    CHECK(r.pair.cipher.rx_next==1 && r.protected_rx==1);
    rx=(sle_link_rx_t){.kind=SLE_RX_OK,.empty=1,.sn=1,.nesn=1};
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,3));
    CHECK(!scratch.mic && r.pair.cipher.rx_next==1);
    CHECK(sle_g_runtime_accepted(&r,1,1,0,0));
    CHECK(!sle_g_runtime_accepted(&r,1,0,0,0));
    CHECK(!sle_g_runtime_accepted(&r,1,1,1,0));
    CHECK(sle_g_runtime_accepted(&r,1,1,1,1));
    free(l); CHECK(!sle_g_runtime_destroy(&r));

    /* Bad MIC must not acknowledge the outstanding TX, change RX NESN,
     * refresh supervision, or deliver unauthenticated bytes. */
    for (unsigned type=0;type<2;type++) {
        snapshot(&r,SLE_PAIR_ENCRYPTED); memset(&store,0,sizeof store); l=link_new();
        tx=queued(&r,&store,l,SLE_PTYPE_DATA,data,sizeof data);
        uint8_t disc[16]; size_t dn=sle_ctrl_disconnect_build(l->s.lid,0x13,disc,sizeof disc);
        n=peer_wire(wire,type ? disc:data,type ? dn:sizeof data,0); wire[n-1]^=1;
        rx=(sle_link_rx_t){.kind=SLE_RX_OK,.ptype=type ? SLE_PTYPE_CTRL:SLE_PTYPE_DATA,
            .sn=0,.nesn=1,.data=wire,.len=(uint16_t)n};
        sle_arq_t before=l->arq; int64_t last=l->last_valid_ns;
        CHECK(sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1)==SLE_PAIR_ERR_MIC);
        CHECK(!memcmp(&before,&l->arq,sizeof before) && l->last_valid_ns==last);
        CHECK(!out.acked && !out.deliver && !l->n_ack && !l->down && scratch.mic==-1);
        CHECK(zero(scratch.plain,sizeof scratch.plain));
        CHECK(!sle_g_runtime_accepted(&r,0,0,0,0));
        free(l); CHECK(!sle_g_runtime_destroy(&r));
    }
    /* CRC failure does not ACK a protected frame; a valid ordinary encrypted
     * disconnect is authenticated and reaches the link control dispatcher. */
    snapshot(&r,SLE_PAIR_ENCRYPTED); memset(&store,0,sizeof store); l=link_new();
    tx=queued(&r,&store,l,SLE_PTYPE_DATA,data,sizeof data);
    rx=(sle_link_rx_t){.kind=SLE_RX_BODYFAIL,.nesn=1,.len=8,.data=wire};
    CHECK(sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1)==1 && l->arq.has_cur && !l->n_ack);
    uint8_t disc[16]; size_t dn=sle_ctrl_disconnect_build(l->s.lid,0x13,disc,sizeof disc);
    n=peer_wire(wire,disc,dn,0);
    rx=(sle_link_rx_t){.kind=SLE_RX_OK,.ptype=SLE_PTYPE_CTRL,.nesn=1,.len=(uint16_t)n,.data=wire};
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,2));
    CHECK(l->down && l->down_reason==0x13 && out.acked && !scratch.pair_control && scratch.mic==1);
    free(l); CHECK(!sle_g_runtime_destroy(&r));
}
static void switch_boundary(void)
{
    for (int v=0;v<2;v++) for (int corrupt=0;corrupt<2;corrupt++) {
        sle_g_runtime r; snapshot(&r,SLE_PAIR_WAIT_SECURITY_START);
        r.pair.cfg.variant=v ? SLE_PAIR_V_KDF_ECB:0;
        sle_link_t *l=link_new(); sle_rt_tx_store store={0}; sle_rt_rx scratch; sle_link_rx_out_t out;
        uint8_t start[]={6,0,0};
        sle_link_rx_t rx={.kind=SLE_RX_OK,.ptype=SLE_PTYPE_CTRL,.data=start,.len=3};
        CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1));
        CHECK(r.pair.state==SLE_PAIR_WAIT_SECURITY_ACK && !out.deliver && l->arq.rx_nesn==1);
        CHECK(!sle_g_runtime_encrypted(&r) && !sle_g_runtime_accepted(&r,0,0,0,0));
        CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,2));
        CHECK(out.dup && !scratch.mic && !r.pair.cipher.rx_next);
        if (corrupt) {
            start[0]=5;
            CHECK(sle_g_runtime_rx(&r,l,&rx,&out,&scratch,3)<0);
            CHECK(l->arq.rx_nesn==1 && !out.deliver);
        } else {
            CHECK(!sle_g_runtime_queue(&r,&store,l));
            sle_link_tx_t tx; CHECK(!sle_link_g_prepare(l,0,0,&tx));
            CHECK(tx.ptype==SLE_PTYPE_CTRL && tx.len==3 && !memcmp(tx.data,"\7\0\0",3));
            CHECK(!sle_g_runtime_tx(&r,&tx) && tx.len==7);
            sle_g_runtime_submitted(&r,&tx);
            CHECK(r.pair.cipher.tx_next==1 && !sle_g_runtime_encrypted(&r));
            uint8_t wire[8],ack[]={7,0,0}; size_t n=peer_wire(wire,ack,3,0);
            rx=(sle_link_rx_t){.kind=SLE_RX_OK,.ptype=SLE_PTYPE_CTRL,.data=wire,.len=(uint16_t)n,.sn=1,.nesn=1};
            CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,3));
            CHECK(sle_g_runtime_encrypted(&r) && out.acked && !out.deliver && scratch.mic==1);
            CHECK(r.pair.cipher.tx_next==1 && r.pair.cipher.rx_next==1);
            CHECK(sle_g_runtime_accepted(&r,0,0,0,0)); /* explicitly hold-only */
            CHECK(!sle_g_runtime_accepted(&r,1,1,0,0)); /* no business yet */
            CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,4));
            CHECK(out.dup && r.pair.cipher.rx_next==1);
            rx.data=start; rx.len=3; rx.sn=0;
            CHECK(sle_g_runtime_rx(&r,l,&rx,&out,&scratch,5)<0); /* plaintext now forbidden */
            CHECK(!out.deliver && l->arq.rx_nesn==0);
        }
        free(l); CHECK(!sle_g_runtime_destroy(&r));
    }
}
/* Exercise the WS63 counter inheritance with real ARQ state, not
 * counter assignment: five acknowledged plain TX, six accepted plain RX,
 * then the seventh RX (0006). Empty frames and cached retries do not count. */
static void count_plain_candidate(void)
{
    sle_g_runtime r; snapshot(&r,SLE_PAIR_WAIT_SECURITY_START);
    r.pair.cfg.variant=SLE_PAIR_PROFILE_WS63;
    sle_link_t *l=link_new(); sle_rt_tx_store store={0};
    sle_rt_rx scratch; sle_link_rx_out_t out;
    const uint8_t ordinary[]={0x20,0,0},start[]={6,0,0},ack[]={7,0,0};
    for (unsigned i=0;i<5;i++) {
        sle_link_tx_t tx=queued(&r,&store,l,SLE_PTYPE_CTRL,ordinary,3);
        CHECK(r.plain_tx==i+1);
        CHECK(!sle_link_g_prepare(l,0,0,&tx));
        CHECK(!sle_g_runtime_tx(&r,&tx)); sle_g_runtime_submitted(&r,&tx);
        CHECK(r.plain_tx==i+1); /* retransmit retains the same count */
        sle_link_rx_t empty={.kind=SLE_RX_OK,.empty=1,.nesn=(uint8_t)(l->arq.tx_sn^1)};
        CHECK(!sle_g_runtime_rx(&r,l,&empty,&out,&scratch,1));
        CHECK(out.acked && !r.plain_rx);
        CHECK(!sle_link_g_prepare(l,0,0,&tx) && tx.empty);
        CHECK(!sle_g_runtime_tx(&r,&tx)); sle_g_runtime_submitted(&r,&tx);
        CHECK(r.plain_tx==i+1);
    }
    for (unsigned i=0;i<6;i++) {
        sle_link_rx_t rx={.kind=SLE_RX_OK,.ptype=SLE_PTYPE_CTRL,.data=ordinary,
            .len=3,.sn=l->arq.rx_nesn,.nesn=l->arq.tx_sn};
        CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,2));
        CHECK(r.plain_rx==i+1);
        CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,2) && out.dup);
        CHECK(r.plain_rx==i+1);
    }
    sle_link_rx_t corrupt={.kind=SLE_RX_BODYFAIL,.ptype=SLE_PTYPE_CTRL,.data=start,
        .len=3,.sn=l->arq.rx_nesn,.nesn=l->arq.tx_sn};
    CHECK(sle_g_runtime_rx(&r,l,&corrupt,&out,&scratch,2)==1 && r.plain_rx==6);
    sle_link_rx_t rx={.kind=SLE_RX_OK,.ptype=SLE_PTYPE_CTRL,.data=start,
        .len=3,.sn=l->arq.rx_nesn,.nesn=l->arq.tx_sn};
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,3));
    CHECK(r.plain_tx==5 && r.plain_rx==7);
    CHECK(r.pair.cipher.tx_next==5 && r.pair.cipher.rx_next==7);
    CHECK(r.pair.cipher.counters_seeded);
    CHECK(sle_pair_seed_plain_counters(&r.pair,0,0)==SLE_PAIR_ERR_STATE);
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,4) && out.dup);
    CHECK(r.pair.cipher.tx_next==5 && r.pair.cipher.rx_next==7 && r.plain_rx==7);
    CHECK(!sle_g_runtime_queue(&r,&store,l));
    sle_link_tx_t tx; CHECK(!sle_link_g_prepare(l,0,0,&tx));
    CHECK(!sle_g_runtime_tx(&r,&tx)); sle_g_runtime_submitted(&r,&tx);
    CHECK(r.pair.cipher.tx_next==6 && r.plain_tx==5);
    uint8_t expected[7],nonce[13]={5,0,0,0,0x80},aad=0;
    memcpy(nonce+5,test_iv,8);
    CHECK(!sle_aes_ccm_encrypt(test_key,nonce,13,&aad,1,ack,3,expected,expected+3,4));
    CHECK(tx.len==7 && !memcmp(tx.data,expected,7));
    CHECK(!sle_link_g_prepare(l,0,0,&tx));
    CHECK(!sle_g_runtime_tx(&r,&tx)); sle_g_runtime_submitted(&r,&tx);
    CHECK(r.pair.cipher.tx_next==6 && !memcmp(tx.data,expected,7));
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,4) && out.dup);
    CHECK(r.pair.cipher.tx_next==6 && r.pair.cipher.rx_next==7);
    uint8_t wire[7]; size_t n=peer_wire(wire,ack,3,7);
    rx=(sle_link_rx_t){.kind=SLE_RX_OK,.ptype=SLE_PTYPE_CTRL,.data=wire,
        .len=(uint16_t)n,.sn=l->arq.rx_nesn,.nesn=(uint8_t)(l->arq.tx_sn^1)};
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,5));
    CHECK(sle_g_runtime_encrypted(&r) && r.pair.cipher.rx_next==8);
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,6) && out.dup);
    CHECK(r.pair.cipher.rx_next==8 && r.plain_rx==7 && r.plain_tx==5);
    free(l); CHECK(!sle_g_runtime_destroy(&r));

    snapshot(&r,SLE_PAIR_WAIT_SECURITY_START); r.pair.cfg.variant=SLE_PAIR_PROFILE_WS63;
    CHECK(sle_pair_seed_plain_counters(&r.pair,5,7)==SLE_PAIR_ERR_STATE);
    r.pair.state=SLE_PAIR_WAIT_SECURITY_ACK; r.pair.secure=1;
    CHECK(sle_pair_seed_plain_counters(&r.pair,SLE_PAIR_COUNTER_LIMIT,7)==SLE_PAIR_ERR_COUNTER);
    CHECK(!r.pair.cipher.tx_next && !r.pair.cipher.rx_next && !r.pair.cipher.counters_seeded);
    CHECK(!sle_pair_seed_plain_counters(&r.pair,5,7));
    CHECK(sle_pair_seed_plain_counters(&r.pair,5,7)==SLE_PAIR_ERR_STATE);
    CHECK(!sle_g_runtime_destroy(&r));
}

static void control_routing(void)
{
    sle_g_runtime r; snapshot(&r,SLE_PAIR_READY);
    sle_link_t *l=link_new(); sle_link_rx_out_t out; sle_rt_rx scratch;
    uint8_t ordinary[]={0x20,0,0}, indication[]={0x33,1,1,5};
    sle_link_rx_t rx={.kind=SLE_RX_OK,.ptype=SLE_PTYPE_CTRL,.data=ordinary,.len=3};
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1));
    CHECK(out.deliver && !scratch.pair_control && r.pair.state==SLE_PAIR_READY);
    rx.data=indication; rx.len=4; rx.sn=1;
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,2));
    CHECK(!out.deliver && scratch.pair_control && r.pair.state==SLE_PAIR_WAIT_RESPONSE);
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,3) && out.dup);
    free(l); CHECK(!sle_g_runtime_destroy(&r));
    snapshot(&r,SLE_PAIR_ENCRYPTED); l=link_new();
    uint8_t wire[16]; size_t n=peer_wire(wire,ordinary,3,0);
    rx=(sle_link_rx_t){.kind=SLE_RX_OK,.ptype=SLE_PTYPE_CTRL,.data=wire,.len=(uint16_t)n};
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1));
    CHECK(out.deliver && out.ptype==SLE_PTYPE_CTRL && out.len==3 && scratch.opcode==0x20);
    CHECK(!memcmp(out.data,ordinary,3) && r.pair.cipher.rx_next==1);
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,2) && out.dup && r.pair.cipher.rx_next==1);
    wire[n-1]^=1;
    sle_arq_t arq=l->arq; int64_t last=l->last_valid_ns;
    CHECK(sle_g_runtime_rx(&r,l,&rx,&out,&scratch,3)==SLE_PAIR_ERR_MIC);
    CHECK(!out.deliver && !memcmp(&arq,&l->arq,sizeof arq) && l->last_valid_ns==last);
    free(l); CHECK(!sle_g_runtime_destroy(&r));
}
static void startup_control_routing(void)
{
    sle_g_runtime r; snapshot(&r,SLE_PAIR_WAIT_SECURITY_START);
    sle_link_t *l=link_new(); sle_rt_tx_store store={0}; sle_link_rx_out_t out; sle_rt_rx scratch;
    const uint8_t start[]={6,0,0}, ordinary[]={0x20,0,0}, ack[]={7,0,0};
    sle_link_rx_t rx={.kind=SLE_RX_OK,.ptype=SLE_PTYPE_CTRL,.data=start,.len=3};
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1));
    CHECK(r.pair.pending && r.pair.state==SLE_PAIR_WAIT_SECURITY_ACK && !out.deliver);
    uint8_t wire[16]; size_t n=peer_wire(wire,ordinary,sizeof ordinary,0);
    rx.data=wire; rx.len=(uint16_t)n; rx.sn=1;
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,2));
    CHECK(out.deliver && out.ptype==SLE_PTYPE_CTRL && out.len==sizeof ordinary &&
        !memcmp(out.data,ordinary,sizeof ordinary) && !scratch.pair_control && scratch.mic==1);
    CHECK(r.pair.state==SLE_PAIR_WAIT_SECURITY_ACK && r.pair.pending && r.pair.step_ms==1);
    CHECK(!sle_g_runtime_encrypted(&r) && !sle_g_runtime_accepted(&r,1,1,0,0));
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,3));
    CHECK(out.dup && !out.deliver && !scratch.pair_control && r.pair.cipher.rx_next==1);
    CHECK(!sle_g_runtime_queue(&r,&store,l));
    CHECK(!r.pair.pending && zero(&r.pair.outgoing,sizeof r.pair.outgoing));
    sle_link_tx_t tx; CHECK(!sle_link_g_prepare(l,0,0,&tx));
    CHECK(tx.len==sizeof ack && !memcmp(tx.data,ack,sizeof ack)); /* owned copy survived pop/wipe */
    CHECK(!sle_g_runtime_tx(&r,&tx) && tx.len==sizeof ack+4);
    sle_g_runtime_submitted(&r,&tx);
    n=peer_wire(wire,ack,sizeof ack,1); rx.len=(uint16_t)n; rx.sn=0; rx.nesn=1;
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,4));
    CHECK(out.acked && !out.deliver && scratch.pair_control && scratch.opcode==7 && scratch.mic==1);
    CHECK(sle_g_runtime_encrypted(&r) && r.pair.cipher.rx_next==2 && r.pair.cipher.tx_next==1);
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,5));
    CHECK(out.dup && !out.deliver && scratch.pair_control && r.pair.cipher.rx_next==2);
    free(l); CHECK(!sle_g_runtime_destroy(&r));
}
static void ownership_and_limits(void)
{
    sle_link_t *l=link_new(); sle_rt_tx_store store={0}; uint8_t input[96]={0x13,0,0};
    for (unsigned i=0;i<SLE_RT_TX_SLOTS;i++) {
        input[0]=(uint8_t)i;
        CHECK(!sle_rt_queue(&store,l,SLE_PTYPE_DATA,input,16));
    }
    memset(input,0xff,sizeof input);
    CHECK(sle_rt_queue(&store,l,SLE_PTYPE_DATA,input,16)<0);
    for (unsigned i=0;i<SLE_RT_TX_SLOTS;i++) {
        sle_link_tx_t tx; CHECK(!sle_link_g_prepare(l,0,0,&tx));
        CHECK(tx.data[0]==i); /* every input was copied and remained alive */
        sle_link_rx_t rx={.kind=SLE_RX_OK,.empty=1,.nesn=(uint8_t)(tx.sn^1)};
        sle_link_rx_out_t out; sle_link_on_rx(l,&rx,&out); CHECK(out.acked);
    }
    CHECK(!sle_rt_queue(&store,l,SLE_PTYPE_DATA,input,16)); free(l);
    sle_g_runtime r; snapshot(&r,SLE_PAIR_ENCRYPTED);
    sle_link_tx_t tx={.ptype=SLE_PTYPE_CTRL,.data=input,.len=93,.retx=1};
    CHECK(sle_g_runtime_tx(&r,&tx)==SLE_PAIR_ERR_LENGTH && !r.pair.cipher.tx_next);
    CHECK(!sle_g_runtime_destroy(&r)); snapshot(&r,SLE_PAIR_ENCRYPTED);
    tx.len=92;
    CHECK(!sle_g_runtime_tx(&r,&tx) && tx.len==96 && r.pair.cipher.tx_next==1);
    CHECK(!sle_g_runtime_destroy(&r));
    /* g_prepare may already call this a retry although the first event was
     * skipped before encryption. The first real materialization still works. */
    snapshot(&r,SLE_PAIR_ENCRYPTED); tx.data=input; tx.len=12; tx.retx=1;
    CHECK(!sle_g_runtime_tx(&r,&tx) && r.pair.cipher.tx_next==1);
    CHECK(!sle_g_runtime_destroy(&r));
}

static atomic_int create_fail, slow_work, work_entered, worker_checks;
static int worker_cpu;
int __real_pthread_create(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *);
int __wrap_pthread_create(pthread_t *t,const pthread_attr_t *a,void *(*fn)(void *),void *arg)
{
    return atomic_load(&create_fail) ? EAGAIN:__real_pthread_create(t,a,fn,arg);
}
int __real_sle_pair_run_work(sle_pair_work_t *,sle_pair_work_result_t *);
int __wrap_sle_pair_run_work(sle_pair_work_t *w,sle_pair_work_result_t *r)
{
    sigset_t mask; pthread_sigmask(SIG_SETMASK,NULL,&mask);
    struct sched_param sp; int policy;
    pthread_getschedparam(pthread_self(),&policy,&sp);
    int ok=sigismember(&mask,SIGINT) && sigismember(&mask,SIGTERM) &&
        sigismember(&mask,SIGHUP) && sigismember(&mask,SIGPIPE) &&
        policy==SCHED_OTHER && !sp.sched_priority && sched_getcpu()==worker_cpu;
    atomic_store(&worker_checks,ok); atomic_store(&work_entered,1);
    if (atomic_load(&slow_work)) { struct timespec t={0,30000000}; nanosleep(&t,NULL); }
    return __real_sle_pair_run_work(w,r);
}
static int rng_error(void *ctx,uint8_t *out,size_t n)
{
    (void)ctx; (void)out; (void)n; return -1;
}
static void start_work(sle_g_runtime *r,int invalid,int rng_fail)
{
    CHECK(!sle_g_runtime_start(r,1));
    sle_pair_pdu_t pdu; CHECK(sle_pair_pop(&r->pair,&pdu)==1);
    uint8_t response[]={0x35,1,10,3,0,5,16,0,2,2,2,2,0};
    CHECK(!sle_pair_on_control(&r->pair,ta,response,sizeof response,0,0,2));
    CHECK(sle_pair_pop(&r->pair,&pdu)==1 && pdu.len==73);
    const char *pub="f39c58483add05d5eaba04735760165f469ea757ff5218081b3daa7c97935ad68512c9e9fc33c5c307d55bf05567dbfd73e45775133aea2162df7253895e1850";
    uint8_t pk[67]={0x37,1,64};
    if (!invalid) for (unsigned i=0;i<64;i++) {
        unsigned x; CHECK(sscanf(pub+2*i,"%2x",&x)==1); pk[i+3]=(uint8_t)x;
    }
    CHECK(!sle_pair_on_control(&r->pair,ta,pk,sizeof pk,1,0,3));
    if (rng_fail) r->pair.cfg.rng=rng_error;
    CHECK(!sle_g_runtime_poll(r,4));
    CHECK(zero(r->pair.private_be,sizeof r->pair.private_be));
}
static void worker_lifecycle(void)
{
    cpu_set_t cpus; CHECK(!sched_getaffinity(0,sizeof cpus,&cpus));
    for (worker_cpu=0;worker_cpu<CPU_SETSIZE;worker_cpu++) if (CPU_ISSET(worker_cpu,&cpus)) break;
    CHECK(worker_cpu<CPU_SETSIZE);
    sigset_t before,after; CHECK(!pthread_sigmask(SIG_SETMASK,NULL,&before));
    sle_g_runtime r; uint8_t previous_public[64]={0};
    for (unsigned mode=0;mode<5;mode++) {
        atomic_store(&work_entered,0); atomic_store(&worker_checks,0);
        atomic_store(&slow_work,mode==0 || mode==3);
        CHECK(!sle_g_runtime_init(&r,ga,ta,0x1c4eac4a,worker_cpu));
        CHECK(r.pair.cfg.variant==SLE_PAIR_PROFILE_WS63);
        CHECK(memcmp(previous_public,r.pair.public_le,64));
        memcpy(previous_public,r.pair.public_le,64);
        CHECK(!pthread_sigmask(SIG_SETMASK,NULL,&after));
        const int signals[]={SIGINT,SIGTERM,SIGHUP,SIGPIPE};
        for (unsigned i=0;i<4;i++) CHECK(sigismember(&before,signals[i])==sigismember(&after,signals[i]));
        int fd=r.rng_fd;
        start_work(&r,mode==1,mode==2);
        for (unsigned wait=0;wait<2000 && !atomic_load(&work_entered);wait++) {
            struct timespec t={0,1000000}; nanosleep(&t,NULL);
        }
        CHECK(atomic_load(&work_entered) && atomic_load(&worker_checks));
        if (!mode) {
            uint8_t confirm[19]={0x38,1,16};
            CHECK(!sle_pair_on_control(&r.pair,ta,confirm,sizeof confirm,0,0,4));
            CHECK(r.pair.state==SLE_PAIR_WAIT_ECDH && r.pair.have_confirm);
        }
        if (mode==3) {
            CHECK(atomic_load(&r.worker.job)==1);
            CHECK(!sle_g_runtime_poll(&r,5)); /* never waits for the worker */
            CHECK(r.pair.state==SLE_PAIR_WAIT_ECDH);
            CHECK(!sle_g_runtime_destroy(&r)); /* stop while crypto is running */
        } else {
            for (unsigned wait=0;wait<2000 && atomic_load(&r.worker.job)!=2;wait++) {
                struct timespec t={0,1000000}; nanosleep(&t,NULL);
            }
            CHECK(atomic_load(&r.worker.job)==2);
            int expected=mode==1 ? SLE_PAIR_ERR_PUBLIC_KEY:mode==2 ? SLE_PAIR_ERR_RNG:
                mode==4 ? SLE_PAIR_ERR_TIMEOUT:0;
            CHECK(sle_g_runtime_poll(&r,mode==4 ? 5004:5)==expected);
            CHECK(zero(&r.worker.work,sizeof r.worker.work));
            if (mode!=4) CHECK(zero(&r.worker.result,sizeof r.worker.result));
            CHECK(mode ? r.pair.state==SLE_PAIR_FAILED:r.pair.state==SLE_PAIR_WAIT_RB);
            CHECK(!sle_g_runtime_destroy(&r));
        }
        CHECK(!r.worker.started && zero(&r.pair,sizeof r.pair));
        CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
        CHECK(!sle_g_runtime_destroy(&r));
    }
    atomic_store(&create_fail,1);
    CHECK(sle_g_runtime_init(&r,ga,ta,0x1c4eac4a,worker_cpu)<0);
    CHECK(!r.worker.started && !sle_g_runtime_destroy(&r));
    atomic_store(&create_fail,0);
    /* Worker/owner failure before radio start must not modify caller mask. */
    CHECK(!pthread_sigmask(SIG_SETMASK,NULL,&after));
    CHECK(sigismember(&before,SIGTERM)==sigismember(&after,SIGTERM));
}
/* 1.10.108 T sends CMTC CAPABILITY_REQ on link creation (captured frame
 * logs/e310/sdk-upgrade-t-standard-a-20260928/p7.jsonl). G admits exactly
 * that plaintext DATA before security, counts it, and nothing else. */
static void cmtc_capability(void)
{
    static const uint8_t req[]={0x60,0,2,0,8,0,1,0,4,0,0xa0,0,0,0};
    sle_g_runtime r; snapshot(&r,SLE_PAIR_READY);
    r.pair.cfg.variant=SLE_PAIR_PROFILE_WS63;
    sle_link_t *l=link_new(); sle_link_rx_out_t out; sle_rt_rx scratch;
    sle_link_rx_t rx={.kind=SLE_RX_OK,.ptype=SLE_PTYPE_DATA,.data=req,.len=sizeof req,
        .sn=l->arq.rx_nesn,.nesn=l->arq.tx_sn};
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1));
    CHECK(out.deliver && out.ptype==SLE_PTYPE_DATA && out.len==sizeof req &&
        !memcmp(out.data,req,sizeof req) && !scratch.pair_control && !scratch.mic);
    CHECK(r.plain_rx==1 && r.pair.state==SLE_PAIR_READY && !r.protected_rx); /* CMTC counts */
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,2) && out.dup && !out.deliver && r.plain_rx==1);
    /* Our plaintext CMTC reply counts once as well. */
    sle_rt_tx_store store={0};
    uint8_t rsp[SLE_CMTC_RSP_SDU_LEN+2]={0x80,0}; size_t rl;
    CHECK(!sle_cmtc_capability_reply(req+2,sizeof req-2,rsp+2,sizeof rsp-2,&rl));
    sle_link_tx_t tx=queued(&r,&store,l,SLE_PTYPE_DATA,rsp,sizeof rsp);
    CHECK(tx.len==sizeof rsp && !memcmp(tx.data,rsp,sizeof rsp) && r.plain_tx==1);
    uint8_t reply[SLE_CMTC_RSP_SDU_LEN]; size_t rn;
    CHECK(!sle_cmtc_capability_reply(req+2,sizeof req-2,reply,sizeof reply,&rn) && rn==sizeof reply);
    /* WS63's reply to our own request is admitted and counted too. */
    static const uint8_t peer_rsp[]={0x80,0,2,0,12,0,2,0,8,0,0xa0,0,0,0,0xa0,2,1,1};
    rx=(sle_link_rx_t){.kind=SLE_RX_OK,.ptype=SLE_PTYPE_DATA,.data=peer_rsp,.len=sizeof peer_rsp,
        .sn=l->arq.rx_nesn,.nesn=l->arq.tx_sn};
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,3) && out.deliver && r.plain_rx==2);
    free(l); CHECK(!sle_g_runtime_destroy(&r));
    /* Mid-pairing plaintext request still admitted (peer need not wait). */
    snapshot(&r,SLE_PAIR_WAIT_RB); r.pair.cfg.variant=SLE_PAIR_PROFILE_WS63; l=link_new();
    rx.sn=l->arq.rx_nesn; rx.nesn=l->arq.tx_sn;
    CHECK(!sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1) && out.deliver && r.pair.state==SLE_PAIR_WAIT_RB);
    free(l); CHECK(!sle_g_runtime_destroy(&r));
    /* Other bitmap, other TCID, or SSAP before encryption: rejected. */
    const uint8_t bad_bitmap[]={0x60,0,2,0,8,0,1,0,4,0,0xa1,0,0,0};
    const uint8_t ssap[]={0x50,0,0x0a,0,6,0,3,3,8,2,1,0};
    const uint8_t *bad[]={bad_bitmap,ssap}; size_t bad_len[]={sizeof bad_bitmap,sizeof ssap};
    for (unsigned i=0;i<2;i++) {
        snapshot(&r,SLE_PAIR_READY); l=link_new();
        rx=(sle_link_rx_t){.kind=SLE_RX_OK,.ptype=SLE_PTYPE_DATA,.data=bad[i],.len=(uint16_t)bad_len[i],
            .sn=l->arq.rx_nesn,.nesn=l->arq.tx_sn};
        sle_arq_t arq=l->arq;
        CHECK(sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1)==SLE_PAIR_ERR_STATE);
        CHECK(!out.deliver && !memcmp(&arq,&l->arq,sizeof arq));
        free(l); CHECK(!sle_g_runtime_destroy(&r));
    }
    /* After the switch the same plaintext bytes are a MIC failure, not CMTC. */
    snapshot(&r,SLE_PAIR_ENCRYPTED); l=link_new();
    rx=(sle_link_rx_t){.kind=SLE_RX_OK,.ptype=SLE_PTYPE_DATA,.data=req,.len=sizeof req,
        .sn=l->arq.rx_nesn,.nesn=l->arq.tx_sn};
    CHECK(sle_g_runtime_rx(&r,l,&rx,&out,&scratch,1)==SLE_PAIR_ERR_MIC && !out.deliver);
    free(l); CHECK(!sle_g_runtime_destroy(&r));
}
int main(void)
{
    authentication_and_retry(); switch_boundary(); control_routing(); startup_control_routing();
    ownership_and_limits(); count_plain_candidate(); worker_lifecycle(); cmtc_capability();
    printf("G runtime: %u checks, 0 failures (offline; no RF validation)\n",checks);
    return 0;
}
