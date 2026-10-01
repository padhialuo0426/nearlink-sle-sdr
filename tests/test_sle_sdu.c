/* Independently constructed SDU records and synthetic fragmentation tests.
 * These are not RF, MIC, ARQ or SSAP acceptance tests. */
#include "sle_sdu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr,"SDU %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); \
} } while (0)
typedef struct {
    unsigned calls, fragments[8];
    size_t len[8];
    uint8_t bytes[8][SLE_SDU_MAX];
} sink;
static void collect(void *ctx,const uint8_t *p,size_t n,unsigned fragments)
{
    sink *s=ctx;
    CHECK(s->calls<8 && n<=SLE_SDU_MAX);
    unsigned i=s->calls++;
    memcpy(s->bytes[i],p,n); s->len[i]=n; s->fragments[i]=fragments;
}
static size_t unhex(const char *hex,uint8_t *p)
{
    size_t n=strlen(hex)/2; CHECK(strlen(hex)==2*n);
    for (size_t i=0;i<n;i++) {
        unsigned b; CHECK(sscanf(hex+2*i,"%2x",&b)==1); p[i]=(uint8_t)b;
    }
    return n;
}
static int feed(sle_sdu_rx *r,sink *s,const char *hex)
{
    uint8_t b[4096]; size_t n=unhex(hex,b);
    CHECK(n<=sizeof b);
    return sle_sdu_rx_feed(r,b,n,collect,s);
}
static void want(sink *s,unsigned i,const char *hex,unsigned fragments)
{
    uint8_t b[SLE_SDU_MAX]; size_t n=unhex(hex,b);
    CHECK(i<s->calls && s->len[i]==n && s->fragments[i]==fragments);
    CHECK(!memcmp(s->bytes[i],b,n));
}
static void records(void)
{
    sle_sdu_rx r; sink s={0}; sle_sdu_rx_init(&r,20);
    CHECK(!feed(&r,&s,"0800aa0800bb"));
    want(&s,0,"aa",1); want(&s,1,"bb",1);
    CHECK(!feed(&r,&s,"0a00cc0c00dd0e00ee0800ff"));
    want(&s,2,"ccddee",3); want(&s,3,"ff",1);
    CHECK(!r.pending);
    CHECK(!feed(&r,&s,"0a0011"));
    CHECK(!feed(&r,&s,"0e0022080033"));
    want(&s,4,"1122",2); want(&s,5,"33",1);
    CHECK(!feed(&r,&s,"09c044")); /* reserved bits ignored */
    want(&s,6,"44",1);
}
static void failures(void)
{
    static const struct {const char *p; int error;} bad[]={
        {"08",SLE_SDU_INVALID},{"1000aa",SLE_SDU_INVALID},
        {"0000",SLE_SDU_INVALID},{"0200",SLE_SDU_INVALID},
        {"0c00aa",SLE_SDU_SEQUENCE},{"0e00aa",SLE_SDU_SEQUENCE},
        {"0800aa08",SLE_SDU_INVALID}, /* valid prefix, malformed tail */
        {"0800aa0e00bb",SLE_SDU_SEQUENCE}, /* semantic error after complete */
        {"0800aa0a00bb0800cc",SLE_SDU_SEQUENCE}, /* interrupted pending */
        {"0800aa28000102030405",SLE_SDU_OVERFLOW}
    };
    for (unsigned i=0;i<sizeof bad/sizeof *bad;i++) {
        sle_sdu_rx r; sink s={0}; sle_sdu_rx_init(&r,4);
        CHECK(feed(&r,&s,bad[i].p)==bad[i].error);
        CHECK(!s.calls && !r.pending && !r.len && r.limit==4);
        CHECK(!feed(&r,&s,"0800ff")); want(&s,0,"ff",1);
    }
    const char *interrupt[]={"0a00bb","0800bb","08","0000"};
    for (unsigned i=0;i<4;i++) {
        sle_sdu_rx r; sink s={0}; sle_sdu_rx_init(&r,8);
        CHECK(!feed(&r,&s,"0a00aa"));
        CHECK(feed(&r,&s,interrupt[i])==(i<2 ? SLE_SDU_SEQUENCE:SLE_SDU_INVALID));
        CHECK(!s.calls && !r.pending && !r.len);
        for (size_t j=0;j<sizeof r.data;j++) CHECK(!r.data[j]);
    }
    /* Even a LAST that could finish an existing SDU cannot be published if
     * a later record in the same PDU is invalid. */
    sle_sdu_rx r; sink s={0}; sle_sdu_rx_init(&r,8);
    CHECK(!feed(&r,&s,"0a00aa"));
    CHECK(feed(&r,&s,"0e00bb08")==SLE_SDU_INVALID);
    CHECK(!s.calls && !r.pending);
    CHECK(!feed(&r,&s,"0a00aa"));
    sle_sdu_rx_init(&r,8); /* new connection, old LAST forbidden */
    CHECK(feed(&r,&s,"0e00bb")==SLE_SDU_SEQUENCE && !s.calls);
    CHECK(!feed(&r,&s,"0a00aa"));
    CHECK(!feed(&r,&s,"0e00bb"));
    CHECK(feed(&r,&s,"0e00bb")==SLE_SDU_SEQUENCE && s.calls==1);
}
/* Construct headers from the independent integer field definition, not the
 * implementation's byte masks. Exercise boundaries across the byte split. */
static size_t record(uint8_t *p,unsigned seg,const uint8_t *data,size_t n)
{
    CHECK(n<=2047 && seg<4);
    unsigned field=(unsigned)n*8+seg*2;
    p[0]=(uint8_t)field; p[1]=(uint8_t)(field/256);
    memcpy(p+2,data,n); return n+2;
}
static void bounds_and_synthetic(void)
{
    uint8_t original[SLE_SDU_MAX+1],b[SLE_SDU_MAX+4];
    for (size_t i=0;i<sizeof original;i++) original[i]=(uint8_t)(i*73+19);
    const size_t lengths[]={1,2,31,32,33,255,256,1027,1028};
    for (unsigned i=0;i<sizeof lengths/sizeof *lengths;i++) {
        size_t len=lengths[i]; sle_sdu_rx r; sink s={0}; sle_sdu_rx_init(&r,len);
        size_t n=record(b,0,original,len);
        CHECK(!sle_sdu_rx_feed(&r,b,n,collect,&s));
        CHECK(s.calls==1 && s.len[0]==len && !memcmp(s.bytes[0],original,len));
        if (len>1) {
            memset(&s,0,sizeof s); sle_sdu_rx_init(&r,len);
            size_t first=len/2;
            n=record(b,1,original,first);
            CHECK(!sle_sdu_rx_feed(&r,b,n,collect,&s) && !s.calls);
            n=record(b,3,original+first,len-first);
            CHECK(!sle_sdu_rx_feed(&r,b,n,collect,&s));
            CHECK(s.calls==1 && s.len[0]==len && s.fragments[0]==2);
            CHECK(!memcmp(s.bytes[0],original,len));
        }
    }
    sle_sdu_rx r; sink s={0}; sle_sdu_rx_init(&r,SLE_SDU_MAX);
    size_t n=record(b,0,original,SLE_SDU_MAX+1);
    CHECK(sle_sdu_rx_feed(&r,b,n,collect,&s)==SLE_SDU_OVERFLOW && !s.calls);
    n=record(b,1,original,SLE_SDU_MAX);
    CHECK(!sle_sdu_rx_feed(&r,b,n,collect,&s));
    CHECK(feed(&r,&s,"0e00aa")==SLE_SDU_OVERFLOW && !s.calls && !r.pending);
    for (unsigned disabled=0;disabled<2;disabled++) {
        sle_sdu_rx_init(&r,disabled ? SLE_SDU_MAX+1:0);
        CHECK(feed(&r,&s,"0800aa")==SLE_SDU_INVALID && !s.calls);
    }
    sle_sdu_rx_init(NULL,1);
    CHECK(sle_sdu_rx_feed(NULL,b,n,collect,&s)==SLE_SDU_INVALID);
    sle_sdu_rx_init(&r,8);
    CHECK(sle_sdu_rx_feed(&r,NULL,3,collect,&s)==SLE_SDU_INVALID);
    CHECK(sle_sdu_rx_feed(&r,b,0,collect,&s)==SLE_SDU_INVALID);
    CHECK(sle_sdu_rx_feed(&r,b,3,NULL,&s)==SLE_SDU_INVALID);
}
static void sequence_limitations(void)
{
    /* No sequence number exists here. Deliberately document that omitted,
     * repeated or reordered MIDDLE data cannot be detected by this layer.
     * Integration must feed only the lower-layer validated ordered stream. */
    sle_sdu_rx r; sink s={0}; sle_sdu_rx_init(&r,8);
    CHECK(!feed(&r,&s,"0a00aa"));
    CHECK(!feed(&r,&s,"0e00cc")); /* omitted middle BB is undetectable */
    want(&s,0,"aacc",2);
    CHECK(!feed(&r,&s,"0a00aa0c00bb0c00bb0e00cc"));
    want(&s,1,"aabbbbcc",4); /* repeated middle is undetectable */
    CHECK(!feed(&r,&s,"0a00aa0c00cc0c00bb0e00dd"));
    want(&s,2,"aaccbbdd",4);
}
/* Synthetic TX length/fragment-size round trips and invalid inputs. */
static void tx_fragments(void)
{
    uint8_t sdu[SLE_SDU_MAX],rec[SLE_SDU_MAX+2];
    size_t off=0,m;
    static const size_t sizes[]={1,24,90,0x7ff};
    for (size_t k=0;k<sizeof sizes/sizeof sizes[0];k++)
        for (size_t len=1;len<=SLE_SDU_MAX;len+=len<40?1:37) {
            for (size_t i=0;i<len;i++) sdu[i]=(uint8_t)(i*7+len);
            sle_sdu_rx r; sink sk={0}; sle_sdu_rx_init(&r,SLE_SDU_MAX);
            unsigned frags=0; off=0;
            while (off<len) {
                size_t before=off; m=sle_sdu_tx_fragment(sdu,len,&off,sizes[k],rec,sizeof rec);
                CHECK(m>2 && m-2<=sizes[k] && off-before==m-2);
                CHECK(!sle_sdu_rx_feed(&r,rec,m,collect,&sk)); frags++;
            }
            CHECK(sk.calls==1 && sk.len[0]==len && !memcmp(sk.bytes[0],sdu,len));
            CHECK(sk.fragments[0]==frags && frags==(len+sizes[k]-1)/sizes[k]);
        }
    off=0;
    CHECK(!sle_sdu_tx_fragment(NULL,5,&off,24,rec,sizeof rec));
    CHECK(!sle_sdu_tx_fragment(sdu,0,&off,24,rec,sizeof rec));
    CHECK(!sle_sdu_tx_fragment(sdu,SLE_SDU_MAX+1,&off,24,rec,sizeof rec));
    CHECK(!sle_sdu_tx_fragment(sdu,5,&off,0,rec,sizeof rec));
    CHECK(!sle_sdu_tx_fragment(sdu,5,&off,0x800,rec,sizeof rec));
    CHECK(!sle_sdu_tx_fragment(sdu,30,&off,24,rec,25) && off==0);          /* cap too small */
}
int main(void)
{
    records(); failures(); bounds_and_synthetic(); sequence_limitations(); tx_fragments();
    printf("SDU reassembly and TX fragmentation: %u checks, 0 failures (synthetic contracts only)\n",checks);
    return 0;
}
