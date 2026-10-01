#include "sle_t_wave.h"
#include <math.h>
#include <string.h>
#define PI 3.14159265358979323846
/* Ternary symbols: 0=zero extension, 1=NRZ -1, 2=NRZ +1.
 * Five symbols cover every 17-tap convolution at four samples/symbol. */
static float rot_re[243][4],rot_im[243][4],rise[8],fall[8];
static int ready;
void sle_t_wave_init(void)
{
    if(ready)return;
    double taps[17],sum=0,sigma=sqrt(log(2.0))*4/(2*PI*.5);
    for(int k=0;k<17;k++){double x=(k-8)/sigma;taps[k]=exp(-.5*x*x);sum+=taps[k];}
    for(int k=0;k<17;k++)taps[k]/=sum;
    for(int code=0;code<243;code++){
        int symbols[5],c=code;
        for(int j=0;j<5;j++){int t=c%3;c/=3;symbols[j]=t==0?0:t==1?-1:1;}
        for(int phase=0;phase<4;phase++){
            double y=0;
            for(int k=0;k<17;k++)y+=taps[k]*symbols[(phase+16-k)/4];
            double angle=2*PI*250000*y/4000000;
            rot_re[code][phase]=(float)cos(angle);rot_im[code][phase]=(float)sin(angle);
        }
    }
    for(int i=0;i<8;i++){
        rise[i]=(float)(8000*(.5-.5*cos(PI*i/7)));
        fall[i]=(float)(8000*(.5+.5*cos(PI*i/7)));
    }
    ready=1;
}
static int16_t quantize(float x){return (int16_t)(x>=0?x+.5f:x-.5f);}
int sle_t_modulate(sle_rt_wave *w,const uint8_t *bits,size_t n)
{
    if(!w || !bits || n>1014)return SLE_RT_RANGE;
    size_t count=n+10,total=16+count*4;
    if(total>SLE_RT_WAVE_MAX)return SLE_RT_RANGE;
    sle_t_wave_init();
    uint8_t all[1024];
    for(int j=0;j<10;j++)all[j]=(uint8_t)(j&1);
    memcpy(all+10,bits,n);
    float re=1,im=0;size_t out=0;
    for(int j=0;j<8;j++){w->iq[out++]=quantize(rise[j]);w->iq[out++]=0;}
    for(size_t b=0;b<count;b++){
        unsigned code=0,power=1;
        for(int j=-2;j<=2;j++,power*=3){
            long index=(long)b+j;
            if(index>=0 && (size_t)index<count)code+=power*(all[index]?2u:1u);
        }
        for(int j=0;j<4;j++){
            float r=re*rot_re[code][j]-im*rot_im[code][j];
            im=re*rot_im[code][j]+im*rot_re[code][j];re=r;
            w->iq[out++]=quantize(8000*re);w->iq[out++]=quantize(8000*im);
        }
    }
    for(int j=0;j<8;j++){w->iq[out++]=quantize(fall[j]*re);w->iq[out++]=quantize(fall[j]*im);}
    w->n=total;return SLE_RT_OK;
}
