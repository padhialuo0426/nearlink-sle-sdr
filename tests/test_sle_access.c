/* Synthetic resource layout and boundary cases; no recorded frames. */
#include "sle_access.h"
#include <stdio.h>
static int g_fail;
#define CHECK(cond, ...) do { if (!(cond)) { g_fail++; fprintf(stderr, __VA_ARGS__); fputc('\n',stderr); } } while (0)
static void test_resource_layouts(void)
{
    sle_resource_word_t rw = { .channel=55, .offset=17 };
    uint32_t word=0;
    CHECK(sle_resource_word_encode_layout(&rw,SLE_RESOURCE_STANDARD,&word)==SLE_ACC_OK &&
          word==0x00001137u,"standard fixed vector 37 11 00 00");
    sle_resource_word_t parsed={0};
    CHECK(sle_resource_word_decode_layout(0x00001137u,SLE_RESOURCE_STANDARD,&parsed)==SLE_ACC_OK &&
          parsed.channel==55 && parsed.offset==17 && parsed.unit==0 &&
          sle_resource_word_offset_us(&parsed)==2125,"standard fixed decode");
    CHECK(sle_resource_word_decode_layout(0x00001137u,SLE_RESOURCE_LEGACY_WS63,&parsed)==SLE_ACC_OK &&
          parsed.channel==55 && parsed.offset==8 && parsed.unit==1 &&
          sle_resource_word_offset_us(&parsed)==10000,"legacy interpretation retained");
    rw=(sle_resource_word_t){.channel=0x55,.unit=1,.offset=0xabc,.frame_type=6,
                             .bandwidth=2,.pilot=1,.clock_accuracy=5};
    const uint32_t asymmetric[]={0xacd57955u,0xd66abc55u};
    for (unsigned layout=0;layout<=1;layout++) {
        CHECK(sle_resource_word_encode_layout(&rw,(sle_resource_layout_t)layout,&word)==SLE_ACC_OK &&
              word==asymmetric[layout],"layout %u asymmetric fixed encode",layout);
        parsed=(sle_resource_word_t){0};
        CHECK(sle_resource_word_decode_layout(asymmetric[layout],(sle_resource_layout_t)layout,&parsed)==SLE_ACC_OK &&
              parsed.channel==0x55 && parsed.unit==1 && parsed.offset==0xabc &&
              parsed.frame_type==6 && parsed.bandwidth==2 && parsed.pilot==1 &&
              parsed.clock_accuracy==5,"layout %u asymmetric fixed decode",layout);
    }
    rw=(sle_resource_word_t){.channel=255,.unit=1,.offset=4095,.frame_type=15,
                             .bandwidth=3,.pilot=3,.clock_accuracy=7};
    for (unsigned layout=0;layout<=1;layout++) {
        CHECK(sle_resource_word_encode_layout(&rw,(sle_resource_layout_t)layout,&word)==SLE_ACC_OK &&
              word==UINT32_MAX,"layout %u upper field boundary",layout);
        CHECK(sle_resource_word_decode_layout(word,(sle_resource_layout_t)layout,&parsed)==SLE_ACC_OK &&
              parsed.channel==rw.channel && parsed.unit==rw.unit && parsed.offset==rw.offset &&
              parsed.frame_type==rw.frame_type && parsed.bandwidth==rw.bandwidth &&
              parsed.pilot==rw.pilot && parsed.clock_accuracy==rw.clock_accuracy,
              "layout %u upper field roundtrip",layout);
    }
    rw.offset=4096;
    CHECK(sle_resource_word_encode_layout(&rw,SLE_RESOURCE_STANDARD,&word)==SLE_ACC_RANGE,
          "standard rejects 13-bit offset");
    rw.offset=17; rw.unit=2;
    CHECK(sle_resource_word_encode_layout(&rw,SLE_RESOURCE_LEGACY_WS63,&word)==SLE_ACC_RANGE,
          "legacy rejects 2-bit unit");
    CHECK(sle_resource_word_decode_layout(0,(sle_resource_layout_t)2,&parsed)==SLE_ACC_RANGE,
          "unknown layout rejected");
    printf("test_resource_layouts: old and standard fixed vectors, boundaries ok\n");
}

int main(void) { test_resource_layouts(); return g_fail ? 1 : 0; }
