/* Synthetic broadcast round trips and configured A2 boundary/error tests. */
#include "sle_phy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { \
    if (!(cond)) { g_fail++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static void test_broadcast_encode(void)
{
    uint8_t payload[255], bits[SLE_MAX_FRAME_BITS], sync[32];
    for (size_t i=0;i<sizeof payload;i++) payload[i]=(uint8_t)(i*53+17);
    sle_sync_from_lid(0xffffff, sync);
    for (unsigned seed=0; seed<128; seed+=17) {
        for (size_t len=0;len<=255;len+=(len<2?1:253)) {
            sle_frame_t f;
            size_t n=sle_encode_broadcast(bits,payload,len,seed,3,0,0);
            CHECK(n==64+len*8+24,"broadcast bit count");
            CHECK(sle_decode_broadcast(bits,n,seed,sync,&f)==SLE_DECODE_OK,"broadcast decode");
            CHECK(f.payload_len==len && !memcmp(f.payload,payload,len),"broadcast payload");
            CHECK(sle_decode_broadcast(bits,n-1,seed,sync,&f)==SLE_DECODE_NEED_MORE,"broadcast truncation");
            bits[64]^=1;
            CHECK(sle_decode_broadcast(bits,n,seed,sync,&f)==SLE_DECODE_CRC24_FAIL,"broadcast corruption");
        }
    }
    for (uint32_t lid=1;lid<0xffffff;lid+=7919) {
        uint32_t decoded=0;
        sle_sync_from_lid(lid,sync);
        CHECK(sle_sync_check_window(sync,&decoded) && decoded==lid,"LID roundtrip");
    }
    puts("synthetic broadcast and LID round trips: PASS");
}

static void test_connect_config(void)
{
    static uint8_t bits[SLE_MAX_FRAME_BITS + 8];
    static uint8_t payload[SLE_MAX_CONNECT_PAYLOAD_BYTES + 1];
    sle_frame_t fr;
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i * 37u + 3u);
    sle_connect_config_t cfg = {0xE56436u, 92, SLE_CRC_TYPE_24, 0xAB123456u, 0};
    CHECK(sle_connect_config_validate(&cfg) == SLE_DECODE_OK, "valid config rejected");
    const size_t lengths[] = {0, 1, 255, 256, 2047};
    for (size_t k = 0; k < sizeof lengths / sizeof lengths[0]; k++) {
        size_t len = lengths[k];
        uint8_t empty = (uint8_t)(len == 0);
        size_t n = sle_encode_connect_config(bits, SLE_MAX_FRAME_BITS, payload, len,
                       &cfg, 2, empty, 1, 0, 1, 0, 0);
        CHECK(n == 64 + (empty ? 0 : len * 8 + 24), "wrong encoded size len=%zu n=%zu", len, n);
        if (!n) continue;
        CHECK(sle_decode_connect_config(bits, n, &cfg, &fr) == SLE_DECODE_OK,
              "configured decode failed len=%zu", len);
        CHECK(fr.length == len && fr.payload_len == len && fr.conn_empty == empty,
              "decoded header/length wrong len=%zu", len);
        CHECK(memcmp(fr.payload, payload, len) == 0, "decoded payload mismatch len=%zu", len);
        if (len) {
            sle_connect_config_t low_cfg = cfg;
            low_cfg.crc_init &= 0xffffffu;
            CHECK(sle_decode_connect_config(bits, n, &low_cfg, &fr) == SLE_DECODE_OK,
                  "CRC24 upper config byte changed decode len=%zu", len);
            uint8_t sync[32];
            sle_sync_from_lid(cfg.lid, sync);
            CHECK(sle_decode_connect(bits, n, sync, &fr) == SLE_DECODE_NEED_CONFIG,
                  "legacy decoder accepted nonempty without CRC config len=%zu", len);
            CHECK(sle_decode_connect_config(bits, n - 1, &cfg, &fr) == SLE_DECODE_NEED_MORE,
                  "truncated frame accepted len=%zu", len);
            bits[64 + len * 4] ^= 1;
            CHECK(sle_decode_connect_config(bits, n, &cfg, &fr) == SLE_DECODE_CRC24_FAIL,
                  "bad body accepted len=%zu", len);
            bits[64 + len * 4] ^= 1;
            cfg.crc_init ^= 1;
            CHECK(sle_decode_connect_config(bits, n, &cfg, &fr) == SLE_DECODE_CRC24_FAIL,
                  "wrong CRC init accepted len=%zu", len);
            cfg.crc_init ^= 1;
            cfg.white_seed ^= 1;
            CHECK(sle_decode_connect_config(bits, n, &cfg, &fr) == SLE_DECODE_CRC12_FAIL,
                  "wrong whitening seed accepted len=%zu", len);
            cfg.white_seed ^= 1;
            if (len > 255) {
                cfg.max_payload_bytes = 255;
                CHECK(sle_decode_connect_config(bits, n, &cfg, &fr) == SLE_DECODE_BAD_LENGTH,
                      "configured decode payload capacity ignored len=%zu", len);
                cfg.max_payload_bytes = 0;
            }
        }
        bits[32] ^= 1;
        CHECK(sle_decode_connect_config(bits, n, &cfg, &fr) == SLE_DECODE_CRC12_FAIL,
              "bad header accepted len=%zu", len);
        bits[32] ^= 1;
        cfg.lid ^= 1;
        CHECK(sle_decode_connect_config(bits, n, &cfg, &fr) == SLE_DECODE_SYNC_MISMATCH,
              "wrong lid accepted len=%zu", len);
        cfg.lid ^= 1;
    }
    CHECK(sle_encode_connect_config(bits, SLE_MAX_FRAME_BITS, payload, 2048,
          &cfg, 2, 0, 1, 0, 1, 0, 0) == 0, "2048-byte payload accepted");
    CHECK(sle_encode_connect_config(bits, 63, payload, 0,
          &cfg, 2, 1, 1, 0, 1, 0, 0) == 0, "short output capacity accepted");
    CHECK(sle_encode_connect_config(bits, SLE_MAX_FRAME_BITS, payload, 1,
          &cfg, 4, 0, 1, 0, 1, 0, 0) == 0, "out-of-range pkt_type accepted");
    CHECK(sle_encode_connect_config(bits, SLE_MAX_FRAME_BITS, payload, 1,
          &cfg, 2, 1, 1, 0, 1, 0, 0) == 0, "empty/length conflict accepted");
    CHECK(sle_encode_connect_config(bits, SLE_MAX_FRAME_BITS, payload, 0,
          &cfg, 2, 0, 1, 0, 1, 0, 0) == 0, "nonempty/zero-length conflict accepted");
    cfg.max_payload_bytes = 255;
    CHECK(sle_encode_connect_config(bits, SLE_MAX_FRAME_BITS, payload, 256,
          &cfg, 2, 0, 1, 0, 1, 0, 0) == 0, "configured payload capacity ignored");
    cfg.max_payload_bytes = 0;
    cfg.crc_type = SLE_CRC_TYPE_32;
    CHECK(sle_connect_config_validate(&cfg) == SLE_DECODE_UNSUPPORTED_CRC,
          "CRC32 not reported as unsupported");
    CHECK(sle_encode_connect_config(bits, SLE_MAX_FRAME_BITS, payload, 1,
          &cfg, 2, 0, 1, 0, 1, 0, 0) == 0, "CRC32 silently encoded as CRC24");
    CHECK(sle_decode_connect_config(bits, 64, &cfg, &fr) == SLE_DECODE_UNSUPPORTED_CRC,
          "CRC32 silently decoded as CRC24");
    cfg.crc_type = SLE_CRC_TYPE_24;
    cfg.white_seed = 128;
    CHECK(sle_connect_config_validate(&cfg) == SLE_DECODE_BAD_CONFIG,
          "out-of-range seed accepted");
    printf("test_connect_config: sizes, capacity, CRC failures, invalid config ok\n");
}

int main(void)
{
    test_broadcast_encode();
    test_connect_config();
    if (g_fail) {
        fprintf(stderr, "%d checks FAILED\n", g_fail);
        return 1;
    }
    printf("all sle_phy unit tests passed\n");
    return 0;
}
