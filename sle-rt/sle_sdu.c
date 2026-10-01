#include "sle_sdu.h"
#include <string.h>

void sle_sdu_rx_init(sle_sdu_rx *r, size_t limit)
{
    if (!r) return;
    memset(r,0,sizeof *r);
    if (limit && limit<=SLE_SDU_MAX) r->limit=limit;
}

static int fail(sle_sdu_rx *r, int error)
{
    size_t limit=r->limit;
    sle_sdu_rx_init(r,limit);
    return error;
}

int sle_sdu_rx_feed(sle_sdu_rx *r, const uint8_t *p, size_t n,
                    sle_sdu_deliver deliver, void *ctx)
{
    if (!r) return SLE_SDU_INVALID;
    if (!r->limit || r->limit>SLE_SDU_MAX || !p || !n || !deliver)
        return fail(r,SLE_SDU_INVALID);
    size_t used=r->len;
    int pending=r->pending;
    /* Validate the entire PDU before modifying state or calling consumers.
     * In particular a valid first record plus a truncated tail publishes
     * nothing, and cannot leave a new pending SDU behind. */
    for (size_t off=0;off<n;) {
        if (n-off<2) return fail(r,SLE_SDU_INVALID);
        unsigned seg=(p[off]>>1)&3u;
        size_t size=(p[off]>>3)|((size_t)(p[off+1]&0x3f)<<5);
        off+=2;
        if (!size || size>n-off) return fail(r,SLE_SDU_INVALID);
        if ((seg<2 && pending) || (seg>=2 && !pending))
            return fail(r,SLE_SDU_SEQUENCE);
        if (seg<2) used=0;
        if (used>r->limit || size>r->limit-used)
            return fail(r,SLE_SDU_OVERFLOW);
        used+=size;
        pending=seg==1 || seg==2;
        if (!pending) used=0;
        off+=size;
    }
    for (size_t off=0;off<n;) {
        unsigned seg=(p[off]>>1)&3u;
        size_t size=(p[off]>>3)|((size_t)(p[off+1]&0x3f)<<5);
        off+=2;
        if (seg==0) {
            deliver(ctx,p+off,size,1);
        } else {
            if (seg==1) { r->len=0; r->fragments=0; }
            memcpy(r->data+r->len,p+off,size);
            r->len+=size; r->fragments++;
            r->pending=seg!=3;
            if (seg==3) {
                deliver(ctx,r->data,r->len,r->fragments);
                memset(r->data,0,r->len);
                r->len=0; r->fragments=0;
            }
        }
        off+=size;
    }
    return SLE_SDU_OK;
}

size_t sle_sdu_tx_fragment(const uint8_t *sdu, size_t n, size_t *off,
                           size_t max_data, uint8_t *out, size_t cap)
{
    if (!sdu || !off || !out || !n || n>SLE_SDU_MAX || *off>=n ||
        !max_data || max_data>0x7ffu) return 0;
    size_t left=n-*off, size=left<max_data ? left:max_data;
    if (cap<size+2) return 0;
    unsigned seg=n<=max_data ? 0u : *off==0 ? 1u : size==left ? 3u : 2u;
    out[0]=(uint8_t)((size&31u)<<3 | seg<<1);
    out[1]=(uint8_t)(size>>5);
    memcpy(out+2,sdu+*off,size);
    *off+=size;
    return size+2;
}
