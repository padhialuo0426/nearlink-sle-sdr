#define _POSIX_C_SOURCE 200809L
#include "sle_t_wave.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static unsigned rng=0x73504;
static unsigned random_u(void){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;}
static int max_error;static double max_freq;static unsigned vectors,frames;
static uint8_t expected[100];static size_t expected_n;
static void received(const sle_found_frame_t *f,void *u)
{
    (void)u;assert(f->frame.crc12_ok && f->frame.crc24_ok);
    assert(f->frame.payload_len==expected_n);
    assert(f->frame.seed==77 && f->frame.packet_type==1 && f->frame.broadcast_type==1);
    assert(!memcmp(f->frame.payload,expected,expected_n));frames++;
}
static void compare(const uint8_t *bits,size_t n)
{
    sle_rt_wave a,b;int x=sle_rt_modulate(&a,bits,n,0),y=sle_t_modulate(&b,bits,n);
    assert(x==y);if(x)return;assert(a.n==b.n);vectors++;
    for(size_t i=0;i<2*a.n;i++){int e=abs(a.iq[i]-b.iq[i]);if(e>max_error)max_error=e;}
    /* Quantized instantaneous-frequency difference, flat envelope only. */
    for(size_t i=9;i<a.n-8;i++){
        double ar=a.iq[2*i],ai=a.iq[2*i+1],ap=a.iq[2*i-2],aq=a.iq[2*i-1];
        double br=b.iq[2*i],bi=b.iq[2*i+1],bp=b.iq[2*i-2],bq=b.iq[2*i-1];
        double da=atan2(ai*ap-ar*aq,ar*ap+ai*aq),db=atan2(bi*bp-br*bq,br*bp+bi*bq);
        double e=fabs(da-db)*4000000/(2*3.14159265358979323846);if(e>max_freq)max_freq=e;
    }
}
static double now(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return t.tv_sec+t.tv_nsec*1e-9;}
int main(void)
{
    sle_t_wave_init();uint8_t bits[1100]={0};
    sle_rt_wave invalid; assert(sle_t_modulate(NULL,bits,1)==SLE_RT_RANGE);
    assert(sle_t_modulate(&invalid,NULL,1)==SLE_RT_RANGE);
    assert(sle_t_modulate(&invalid,bits,(size_t)-1)==SLE_RT_RANGE);
    const size_t lengths[]={0,1,2,3,4,5,31,64,73,128,511,1009,1010,1011,1014,1015};
    for(unsigned mode=0;mode<4;mode++)for(size_t j=0;j<sizeof lengths/sizeof *lengths;j++){
        for(size_t k=0;k<sizeof bits;k++)bits[k]=(uint8_t)(mode==0?0:mode==1?1:mode==2?k&1:random_u()&1);
        compare(bits,lengths[j]);
    }
    for(int j=0;j<200;j++){size_t n=random_u()%1011;for(size_t k=0;k<n;k++)bits[k]=random_u()&1;compare(bits,n);}
    for(int test=0;test<30;test++){
        expected_n=1+random_u()%100;for(size_t i=0;i<expected_n;i++)expected[i]=(uint8_t)random_u();
        size_t n=sle_access_encode_frame(bits,sizeof bits,expected,expected_n,77,1,1);assert(n);
        compare(bits,n);sle_rt_wave w;assert(!sle_t_modulate(&w,bits,n));
        sle_demod_channel_t *d=calloc(1,sizeof *d);assert(d);
        assert(!sle_demod_channel_init(d,SLE_RT_FS,0,2424,received,NULL));
        sle_demod_set_fir_bypass(d,1);sle_demod_set_dedup(d,1);assert(!sle_demod_add_broadcast_target(d,77,0));
        size_t count=((w.n+512+255)/256)*256;int16_t *iq=calloc(count*2,sizeof *iq);assert(iq);
        memcpy(iq+200,w.iq,w.n*4);unsigned before=frames;
        for(size_t k=0;k<count;k+=256)assert(sle_demod_channel_process(d,iq+2*k,256,k)==SLE_STREAM_OK);
        assert(frames==before+1);free(iq);free(d);
    }
    assert(max_error<=4);assert(max_freq<500);
    for(int i=0;i<760;i++)bits[i]=random_u()&1;
    sle_rt_wave w;double start=now();for(int i=0;i<1000;i++)assert(!sle_rt_modulate(&w,bits,760,0));double old=now()-start;
    start=now();for(int i=0;i<1000;i++)assert(!sle_t_modulate(&w,bits,760));double fast=now()-start;
    printf("vectors=%u crc_payload_roundtrips=%u max_iq_error=%d max_quantized_frequency_difference_hz=%.6f\n",vectors,frames,max_error,max_freq);
    printf("760bit_1000_calls old_s=%.6f fast_s=%.6f speedup=%.3f (qemu timing is not board timing)\n",old,fast,old/fast);
    return 0;
}
