/* Deterministic synthetic test inputs; never use these as real keys.
 * No numeric vectors copied from any standard or device capture. */
#include "sle_crypto.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"crypto synthetic line %d: %s\n",__LINE__,#x); return 1; } } while (0)
int main(void) {
    unsigned char key[16],nonce[13],aad[7],plain[65],ct[65],out[65],tag[16];
    for(unsigned i=0;i<16;i++)key[i]=(unsigned char)(i*7+3);
    for(unsigned i=0;i<13;i++)nonce[i]=(unsigned char)(i*11+5);
    for(unsigned i=0;i<7;i++)aad[i]=(unsigned char)(i+19);
    for(unsigned i=0;i<65;i++)plain[i]=(unsigned char)(i*13+23);
    for(size_t n=0;n<=65;n+=(n<2?1:21)) {
        CHECK(!sle_aes_ccm_encrypt(key,nonce,13,aad,7,plain,n,ct,tag,8));
        CHECK(!sle_aes_ccm_decrypt(key,nonce,13,aad,7,ct,n,tag,8,out));
        CHECK(!memcmp(out,plain,n));
        tag[2]^=1; memset(out,0xa5,sizeof out);
        CHECK(sle_aes_ccm_decrypt(key,nonce,13,aad,7,ct,n,tag,8,out));
        for(size_t j=0;j<n;j++) CHECK(out[j]==0);
    }
    unsigned char a[32]={0},b[32]={0},ax[32],ay[32],bx[32],by[32],ab[32],ba[32];
    a[31]=7; b[31]=13;
    CHECK(!sle_p256_public_key(a,ax,ay)); CHECK(!sle_p256_public_key(b,bx,by));
    CHECK(sle_p256_valid_point(ax,ay)); CHECK(sle_p256_valid_point(bx,by));
    CHECK(!sle_p256_ecdh(a,bx,by,ab)); CHECK(!sle_p256_ecdh(b,ax,ay,ba));
    CHECK(!memcmp(ab,ba,32));
    memset(ax,0,sizeof ax); memset(ay,0,sizeof ay); CHECK(!sle_p256_valid_point(ax,ay));
    puts("synthetic crypto: CCM roundtrip/tamper/wipe, P-256 agreement/invalid point PASS");
    return 0;
}
