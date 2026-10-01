/* Offline regression; build and coverage notes: ../docs/e310-source.md. */
#define _GNU_SOURCE
#include "sle_radio.h"
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, failures;
#define CHECK(x) do { checks++; if (!(x)) { failures++; \
    fprintf(stderr,"Radio check failed %s:%d: %s\n",__FILE__,__LINE__,#x); } } while (0)
#include "radio_fixtures.h"
static void protocol(void)
{
    sle_rt_peer p; const uint8_t local[]={0xee,0xef,0x33,0x9b,0x8d,0x5c}, server[]={1,2,3,4,5,6};
    CHECK(sle_rt_peer_init(&p,local,server,0x66a275,0xe4004c6e,0xdf488c)==SLE_RT_OK);
    uint8_t req[84]; CHECK(sle_access_request_build(local,server,&p.txi,&p.req,req,sizeof req)==84);
    /* Field offsets taken from the recording, not re-decoded by this codec. */
    CHECK(req[0]==0x15 && req[14]==1 && req[15]==60 && req[42]==0x75 && req[43]==0xa2 && req[44]==0x66);
    CHECK(req[20]==0x3e && req[21]==0x25 && req[54]==0x6e && req[57]==0xe4);
    CHECK(req[78]==0xff && req[79]==0xcd);
    sle_found_frame_t f=primary(); sle_access_plan_t plan;
    CHECK(sle_rt_primary(&p,&f,4001000,9200,0,&plan)==SLE_RT_OK);
    CHECK(plan.aux_sync_ns==1002150000 && plan.req_sync_ns==1004650000 && plan.rsp_sync_ns==1008400000);
    CHECK(plan.aux_channel==11 && plan.aux_mhz==2414 && plan.req_tx_start_ns==1004640000);
    /* New standard resource vector: 37 11 00 00 means channel55, offset17
     * at 125 us. The same raw word under legacy means unit1, offset8. */
    sle_found_frame_t standard=f;
    standard.frame.payload[8]=0x37; standard.frame.payload[9]=0x11;
    CHECK(sle_rt_primary_layout(&p,&standard,4001000,9200,0,SLE_RESOURCE_STANDARD,&plan)==SLE_RT_OK);
    CHECK(plan.aux_channel==55 && plan.aux_sync_ns==1002150000 &&
          plan.req_sync_ns==1004650000 && plan.rsp_sync_ns==1008400000);
    CHECK(sle_rt_primary_layout(&p,&standard,4001000,9200,0,SLE_RESOURCE_LEGACY_WS63,&plan)==SLE_RT_OK);
    CHECK(plan.aux_sync_ns==1010025000 && plan.req_sync_ns==1012525000);
    CHECK(sle_rt_primary_layout(&p,&standard,4001000,9200,0,(sle_resource_layout_t)2,&plan)==SLE_RT_RANGE);
    CHECK(sle_rt_primary(&p,&f,4001000,9200,0,&plan)==SLE_RT_OK); /* old fixture still default */
    CHECK(sle_rt_primary(&p,&f,4018560,0,0,&plan)==SLE_RT_OK); /* exactly on preamble */
    CHECK(sle_rt_primary(&p,&f,4018561,0,0,&plan)==SLE_RT_LATE);
    CHECK(sle_rt_primary(&p,&f,4018500,0,-100,&plan)==SLE_RT_LATE);
    f.frame.payload[2]^=1; CHECK(sle_rt_primary(&p,&f,4001000,0,0,&plan)==SLE_RT_IDENTITY);
    f=primary(); f.frame.crc24_ok=0; CHECK(sle_rt_primary(&p,&f,4001000,0,0,&plan)==SLE_RT_BAD_FRAME);
    f=primary(); f.frame.payload[8]=78; CHECK(sle_rt_primary(&p,&f,4001000,0,0,&plan)==SLE_RT_RANGE);
    f=primary(); CHECK(sle_rt_primary(&p,&f,4001000,0,0,&plan)==SLE_RT_OK);
    f=response(); CHECK(sle_rt_response(&p,&plan,&f)==SLE_RT_OK);
    f.frame.payload[2]^=1; CHECK(sle_rt_response(&p,&plan,&f)==SLE_RT_IDENTITY);
    f=response(); f.frame.payload[11]^=1; CHECK(sle_rt_response(&p,&plan,&f)==SLE_RT_IDENTITY);
    f=response(); f.frame.payload[17]=0x41; CHECK(sle_rt_response(&p,&plan,&f)==SLE_RT_REJECTED);
    f=response(); f.frame.payload[19]|=1; CHECK(sle_rt_response(&p,&plan,&f)==SLE_RT_BAD_FRAME);
    f=response(); f.frame.crc24_ok=0; CHECK(sle_rt_response(&p,&plan,&f)==SLE_RT_BAD_FRAME);
    f=response(); f.frame.seed=3; CHECK(sle_rt_response(&p,&plan,&f)==SLE_RT_IGNORE);
    f=response(); f.sample_index+=161; CHECK(sle_rt_response(&p,&plan,&f)==SLE_RT_LATE);
    f=response(); f.sample_index+=160; CHECK(sle_rt_response(&p,&plan,&f)==SLE_RT_OK);
    CHECK(!sle_rt_expired(100,100) && sle_rt_expired(101,100));
    CHECK(sle_rt_access_lead()==12792); /* TX 2300+768+128+2 us */
    CHECK(sle_rt_access_response_lead(1)==22072 && sle_rt_access_response_lead(0)==12872);
    f=primary();
    CHECK(sle_rt_primary(&p,&f,4006200,sle_rt_access_lead(),0,&plan)==SLE_RT_LATE);
    CHECK(plan.req_sync_ns==1004650000 && plan.rsp_sync_ns==1008400000);
    CHECK(sle_rt_primary(&p,&f,4002800,sle_rt_access_lead(),0,&plan)==SLE_RT_OK);
    CHECK(sle_rt_primary(&p,&f,4000800,sle_rt_access_lead(),0,&plan)==SLE_RT_OK);
    CHECK(!sle_rt_maintained(1000,1000,1250,10000000000LL,5080000000LL,100000000));
    CHECK(!sle_rt_maintained(1000,10000001000LL,10200001000LL,10000000000LL,5080000000LL,100000000));
    CHECK(!sle_rt_maintained(0,5080000000LL,5080000000LL,5080000000LL,5080000000LL,100000000));
    CHECK(sle_rt_maintained(1000,10000001000LL,10050001000LL,10000000000LL,5080000000LL,100000000));

    sle_conn_sched_t s;
    CHECK(sle_conn_sched_init(&s,plan.req_sync_ns,&p.txi)==0);
    sle_conn_event_t ev; sle_conn_event(&s,0,&ev);
    CHECK(ev.t_ns==1014184000 && ev.slot==0xdf488c && ev.mhz==2418 && ev.white_seed==76);
    sle_conn_event(&s,1,&ev); CHECK(ev.t_ns==1026684000 && ev.slot==0xdf48f0 && ev.white_seed==112);
    sle_link_t *l=calloc(1,sizeof *l); CHECK(l!=NULL); if (!l) return;
    sle_link_init(l,SLE_LINK_ROLE_G,&s,p.txi.first_crc_init);
    sle_link_tx_t tx;
    CHECK(!sle_link_g_prepare(l,plan.req_sync_ns,0,&tx));
    CHECK(tx.k==0 && tx.empty && !tx.sn && !tx.nesn);
    f=(sle_found_frame_t){.channel_mhz=2418,.sample_index=4057724}; /* t0 + 247 us */
    f.frame.kind=SLE_FRAME_CONNECT; f.frame.seed=76; f.frame.crc12_ok=1; f.frame.conn_empty=1;
    int64_t error;
    CHECK(sle_rt_reply_matches(&tx,&s,&f,&error)==SLE_RT_OK && error==0);
    f.sample_index=4056736; /* our own sync: never a reply */
    CHECK(sle_rt_reply_matches(&tx,&s,&f,&error)==SLE_RT_LATE);
    CHECK(!sle_link_g_prepare(l,s.t0_ns+12500000-10000+1,0,&tx) && tx.k==2);
    sle_link_init(l,SLE_LINK_ROLE_G,&s,p.txi.first_crc_init);
    unsigned sent=0;
    while (!sle_link_g_prepare(l,0,0,&tx)) {
        sent++;
        sle_link_rx_t rx={.kind=SLE_RX_NONE}; sle_link_rx_out_t out; sle_link_on_rx(l,&rx,&out);
        if (sent>500) break;
    }
    CHECK(sent==407 && l->down && l->down_reason==7);
    free(l);
}
static void scheduling(void)
{
    sle_rt_cal c={0}; int64_t start;
    CHECK(sle_rt_tx_index(&c,20000,0,&start)==SLE_RT_NO_CAL);
    CHECK(!sle_rt_cal_observe(&c,1000,14514)); CHECK(!c.valid);
    CHECK(!sle_rt_cal_observe(&c,2000,15515)); CHECK(!c.valid);
    CHECK(!sle_rt_cal_observe(&c,3000,16514)); CHECK(c.valid && c.offset==13514);
    CHECK(sle_rt_cal_fresh(&c,17514,1000) && !sle_rt_cal_fresh(&c,17515,1000));
    CHECK(!sle_rt_tx_index(&c,20000,0,&start)); CHECK(start==20000-13514-sle_rt_sync_in_wave());
    CHECK(sle_rt_tx_index(&c,20000,start+1,&start)==SLE_RT_LATE);
    CHECK(sle_rt_cal_observe(&c,4000,17523)==SLE_RT_OFFSET_JUMP && !c.valid && !c.count);
    CHECK(sle_rt_cal_observe(&c,1,INT64_MAX)==SLE_RT_RANGE);
    sle_rt_renderer *r=calloc(1,sizeof *r); CHECK(r!=NULL); if (!r) return;
    sle_rt_wave w={.n=1500};
    for (size_t i=0;i<w.n*2;i++) w.iq[i]=(int16_t)(i+1);
    CHECK(sle_rt_render_arm(r,1024,1000,&w)==SLE_RT_LATE && !r->active);
    CHECK(!sle_rt_render_arm(r,1024,1500,&w));
    CHECK(sle_rt_render_arm(r,1024,1500,&w)==SLE_RT_BUSY);
    int16_t dst[2*SLE_RT_BLOCK+2]; dst[2*SLE_RT_BLOCK]=123; dst[2*SLE_RT_BLOCK+1]=456;
    CHECK(!sle_rt_render_block(r,dst,1024,SLE_RT_BLOCK));
    CHECK(dst[950]==0 && dst[952]==1 && dst[2047]==1096);
    CHECK(dst[2048]==123 && dst[2049]==456 && r->active);
    memset(&w,0,sizeof w); /* renderer owns a copy */
    CHECK(!sle_rt_render_block(r,dst,2048,SLE_RT_BLOCK));
    CHECK(dst[0]==1097 && dst[1903]==3000 && dst[1904]==0 && !r->active);
    CHECK(sle_rt_render_block(r,dst,0,SLE_RT_BLOCK+1)==SLE_RT_RANGE);
    w.n=SLE_RT_WAVE_MAX+1; CHECK(sle_rt_render_arm(r,0,0,&w)==SLE_RT_RANGE);
    w.n=1; CHECK(sle_rt_render_arm(r,0,INT64_MAX,&w)==SLE_RT_RANGE);
    CHECK(!sle_rt_render_arm(r,0,100,&w));
    CHECK(sle_rt_render_block(r,dst,101,SLE_RT_BLOCK)==SLE_RT_LATE && !r->active && !dst[0]);
    CHECK(!sle_rt_render_arm(r,0,100,&w)); sle_rt_render_clear(r); CHECK(!r->active && !r->wave.n);
    free(r);
}
static void queues(void)
{
    sle_rt_frame_ring *q=calloc(1,sizeof *q); CHECK(q!=NULL); if (!q) return;
    sle_rt_ring_init(q);
    /* Exercise unsigned wrap, full/empty, and ownership across reuse. */
    atomic_store(&q->head,UINT_MAX-20); atomic_store(&q->tail,UINT_MAX-20);
    sle_rt_received f={0}, out;
    for (unsigned i=0;i<SLE_RT_FRAME_RING;i++) { f.seq=i; CHECK(!sle_rt_ring_push(q,&f)); }
    CHECK(sle_rt_ring_push(q,&f)==-1);
    for (unsigned i=0;i<SLE_RT_FRAME_RING;i++) { CHECK(!sle_rt_ring_pop(q,&out)); CHECK(out.seq==i); }
    CHECK(sle_rt_ring_pop(q,&out)==-1);
    free(q);
}
static unsigned decoded;
static uint64_t decoded_sample;
static void wave_frame(const sle_found_frame_t *f,void *u)
{
    (void)u;
    CHECK(f->frame.crc12_ok && f->frame.crc24_ok && f->frame.payload_len==12);
    decoded++; decoded_sample=f->sample_index;
}
static void waveform(void)
{
    sle_found_frame_t f=primary(); uint8_t bits[256];
    size_t n=sle_access_encode_frame(bits,sizeof bits,f.frame.payload,12,77,3,0);
    CHECK(n==184);
    sle_rt_wave w; CHECK(!sle_rt_modulate(&w,bits,n,0));
    sle_demod_channel_t *d=calloc(1,sizeof *d); CHECK(d!=NULL); if (!d) return;
    CHECK(!sle_demod_channel_init(d,SLE_RT_FS,0,2424,wave_frame,NULL));
    sle_demod_set_fir_bypass(d,1); sle_demod_set_dedup(d,1);
    CHECK(!sle_demod_add_broadcast_target(d,77,0));
    int16_t iq[2*2048]={0}; memcpy(iq+2*100,w.iq,w.n*4);
    decoded=0;
    for (int k=0;k<2048;k+=256) CHECK(sle_demod_channel_process(d,iq+2*k,256,(uint64_t)k)==SLE_STREAM_OK);
    CHECK(decoded==1);
    CHECK(llabs((int64_t)decoded_sample-100-sle_rt_sync_in_wave())<=4);
    free(d);
}
static sle_rt_radio *offline_radio(const sle_rt_command *cmd, int gated)
{
    sle_rt_radio *r=calloc(1,sizeof *r);
    if (!r) abort();
    sle_rt_ring_init(&r->frames);
    atomic_init(&r->mute,0); atomic_init(&r->stop,0); atomic_init(&r->error,0);
    CHECK(!sle_rt_radio_rx_configure(r,cmd));
    if (!gated) r->energy_enabled=0;
    return r;
}
static void gate_edges(void)
{
    sle_rt_energy g; sle_rt_energy_reset(&g,0);
    int16_t iq[2*SLE_RT_BLOCK];
    for (unsigned i=0;i<2*SLE_RT_BLOCK;i++) iq[i]=-32768;
    for (unsigned k=0;k<32;k++) {
        unsigned flags=sle_rt_energy_step(&g,iq);
        CHECK(flags&SLE_RT_GATE_CURRENT); /* no contrast: fail open, never learn a burst away */
    }
    CHECK(g.floor_sum==549755813888ULL && g.peak_bin_sum==68719476736ULL);
    CHECK(g.clipped==256);
    memset(iq,0,sizeof iq);
    CHECK(sle_rt_energy_step(&g,iq)&SLE_RT_GATE_POST);
    CHECK(!(sle_rt_energy_step(&g,iq)&SLE_RT_GATE_CURRENT));
    iq[0]=2000;
    unsigned f=sle_rt_energy_step(&g,iq);
    CHECK((f&(SLE_RT_GATE_PREVIOUS|SLE_RT_GATE_CURRENT))==(SLE_RT_GATE_PREVIOUS|SLE_RT_GATE_CURRENT));
    sle_rt_energy_reset(&g,1); CHECK(!g.have_previous && g.learned==SLE_RT_ENERGY_LEARN_BLOCKS && !g.floor_sum);
    sle_rt_energy_reset(&g,0); CHECK(!g.learned && g.floor_sum==UINT64_MAX);
}
static void gated_waveforms(void)
{
    enum { BLOCKS=80, NS=BLOCKS*SLE_RT_BLOCK };
    int16_t *iq=calloc(NS*2,sizeof *iq); if (!iq) abort();
    const unsigned offsets[]={0,1,960,975,984,1023};
    const double offsets_hz[]={0,80000,-80000};
    for (unsigned kind=0;kind<2;kind++) for (unsigned cf=0;cf<3;cf++) for (unsigned j=0;j<6;j++) {
        for (unsigned n=0;n<NS;n++) { iq[2*n]=4; iq[2*n+1]=-3; }
        /* Establish observed power contrast, like the preceding calibration
         * leakage in live operation. A tone has no valid SLE sync/header. */
        for (unsigned n=10*SLE_RT_BLOCK;n<10*SLE_RT_BLOCK+128;n++) iq[2*n]=1000;
        sle_found_frame_t f=primary(); uint8_t bits[256];
        if (kind) { f.frame.payload[0]=0x50; f.frame.payload[1]=0x34; }
        size_t nb=sle_access_encode_frame(bits,sizeof bits,f.frame.payload,12,77,kind ? 0:3,0);
        sle_rt_wave w; CHECK(!sle_rt_modulate(&w,bits,nb,offsets_hz[cf]));
        size_t start=23*SLE_RT_BLOCK+offsets[j]; /* crosses the circular-history boundary */
        for (size_t n=0;n<w.n;n++) {
            iq[2*(start+n)]+=(int16_t)(w.iq[2*n]/8);
            iq[2*(start+n)+1]+=(int16_t)(w.iq[2*n+1]/8);
        }
        sle_rt_command cmd={.seq=1,.mhz=2424,.seed=77,.estimate_cfo=!kind,.rx_end=INT64_MAX};
        if (kind) cmd.wave.n=1;
        sle_rt_radio *g=offline_radio(&cmd,1), *ref=offline_radio(&cmd,0);
        int64_t origin=j==5 ? (1LL<<34):0; /* absolute indices beyond uint32 */
        for (unsigned k=0;k<BLOCKS;k++) {
            CHECK(!sle_rt_radio_rx_block(g,iq+2*k*SLE_RT_BLOCK,origin+(int64_t)k*SLE_RT_BLOCK));
            CHECK(!sle_rt_radio_rx_block(ref,iq+2*k*SLE_RT_BLOCK,origin+(int64_t)k*SLE_RT_BLOCK));
        }
        sle_rt_received a,b;
        CHECK(!sle_rt_ring_pop(&g->frames,&a) && !sle_rt_ring_pop(&ref->frames,&b));
        CHECK(a.f.frame.crc24_ok && b.f.frame.crc24_ok);
        CHECK(a.f.sample_index==b.f.sample_index && llabs((int64_t)a.f.sample_index-origin-(int64_t)start-sle_rt_sync_in_wave())<=4);
        CHECK(a.f.frame.payload_len==12 && !memcmp(a.f.frame.payload,f.frame.payload,12));
        if (!kind) {
            CHECK(isfinite(a.cfo_hz) && fabs(a.cfo_hz-b.cfo_hz)<0.01);
            CHECK(fabs(a.cfo_hz-offsets_hz[cf])<20000);
        } else CHECK(isnan(a.cfo_hz));
        CHECK(sle_rt_ring_pop(&g->frames,&a)==-1 && sle_rt_ring_pop(&ref->frames,&b)==-1);
        sle_rt_rx_stats *s=&g->rx_stats[kind ? SLE_RT_RX_CAL:SLE_RT_RX_SCAN];
        CHECK(s->demod_samples<NS/4 && s->pre && s->post && !s->history_errors);
        CHECK(s->cfo_estimates==(kind ? 0u:1u));
        CHECK(!g->demod.stats.rejected_chunks);
        /* Target switch retains noise learning but never replays old IQ. */
        uint64_t floor=g->energy.floor_sum; cmd.seq=2; cmd.wave.n=kind ? 0:1;
        CHECK(!sle_rt_radio_rx_configure(g,&cmd));
        CHECK(!g->energy.have_previous && g->energy.floor_sum==floor && g->energy.learned==SLE_RT_ENERGY_LEARN_BLOCKS);
        CHECK(sle_rt_radio_rx_block(g,iq,0)==-1); /* accidental index rewind */
        free(g); free(ref);
    }
    /* A2 finite receive window bypasses energy even after a high floor. */
    memset(iq,0,NS*4);
    sle_connect_config_t cfg={.lid=0x66a275,.white_seed=76,.crc_type=SLE_CRC_TYPE_24,.crc_init=0xe4004c6e};
    uint8_t bits[128]; size_t nb=sle_encode_connect_config(bits,sizeof bits,NULL,0,&cfg,0,1,0,0,0,0,0);
    sle_rt_wave w; CHECK(nb && !sle_rt_modulate(&w,bits,nb,80000));
    size_t start=23*SLE_RT_BLOCK+1023;
    for (size_t n=0;n<w.n*2;n++) iq[start*2+n]=(int16_t)(w.iq[n]/100);
    sle_rt_command c={.seq=1,.mhz=2418,.seed=76,.connect=1,.lid=cfg.lid,.crc=cfg.crc_init,
        .rx_start=(int64_t)start-16,.rx_end=(int64_t)(start+w.n)+64};
    sle_rt_radio *r=offline_radio(&c,1); r->energy.floor_sum=100000000;
    for (unsigned k=0;k<BLOCKS;k++) CHECK(!sle_rt_radio_rx_block(r,iq+2*k*SLE_RT_BLOCK,(int64_t)k*SLE_RT_BLOCK));
    sle_rt_received got; CHECK(!sle_rt_ring_pop(&r->frames,&got));
    CHECK(got.f.frame.kind==SLE_FRAME_CONNECT && got.f.frame.crc12_ok && got.f.frame.conn_empty);
    CHECK(r->rx_stats[SLE_RT_RX_WINDOW].energy_blocks==0 &&
        r->rx_stats[SLE_RT_RX_WINDOW].demod_samples==(uint64_t)(c.rx_end-c.rx_start));
    free(r);
    /* A mute/retune boundary clears power learning and pre-roll. No stale
     * high-power block may be replayed after unmute or under a new target. */
    c=(sle_rt_command){.seq=1,.mhz=2424,.seed=77,.estimate_cfo=1,.rx_end=INT64_MAX};
    r=offline_radio(&c,1);
    int16_t block[2*SLE_RT_BLOCK]={0};
    for (int k=0;k<12;k++) CHECK(!sle_rt_radio_rx_block(r,block,(int64_t)k*SLE_RT_BLOCK));
    CHECK(r->energy.learned==8);
    atomic_store(&r->mute,1);
    for (unsigned i=0;i<2*SLE_RT_BLOCK;i++) block[i]=2000;
    CHECK(!sle_rt_radio_rx_block(r,block,12*SLE_RT_BLOCK));
    CHECK(!r->energy.learned && !r->energy.have_previous && r->history_start==13*SLE_RT_BLOCK);
    atomic_store(&r->mute,0); memset(block,0,sizeof block);
    c.seq=2; CHECK(!sle_rt_radio_rx_configure(r,&c));
    CHECK(!sle_rt_radio_rx_block(r,block,13*SLE_RT_BLOCK));
    CHECK(!r->rx_stats[SLE_RT_RX_SCAN].pre && !r->rx_stats[SLE_RT_RX_SCAN].history_errors);
    CHECK(r->rx_stats[SLE_RT_RX_SCAN].muted==1 && sle_rt_ring_pop(&r->frames,&got)==-1);
    free(r); free(iq);
}
int sle_rt_selftest(void)
{
    checks=failures=0;
    protocol(); scheduling(); queues(); waveform(); gate_edges(); gated_waveforms();
    printf("Radio core offline selftest: %u checks, %u failures; no hardware or peer interoperability tested\n",checks,failures);
    return failures ? 1 : 0;
}

int main(void) { return sle_rt_selftest(); }
