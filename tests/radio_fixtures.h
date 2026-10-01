/* Shared in-memory frame fixtures for radio and G application regressions. */
#ifndef SLE_TEST_RADIO_FIXTURES_H
#define SLE_TEST_RADIO_FIXTURES_H
#include "sle_radio.h"
#include <string.h>
static sle_found_frame_t primary(void)
{
    sle_found_frame_t f={.sample_index=4000000,.channel_mhz=2424};
    const uint8_t p[]={9,0,1,2,3,4,5,6,0x0b,0x22,0,0};
    f.frame.kind=SLE_FRAME_BROADCAST; f.frame.seed=77;
    f.frame.broadcast_type=3; f.frame.packet_type=0;
    f.frame.crc12_ok=f.frame.crc24_ok=f.frame.has_crc24=1;
    f.frame.length=f.frame.payload_len=sizeof p; memcpy(f.frame.payload,p,sizeof p);
    return f;
}
static sle_found_frame_t response(void)
{
    /* Exact captured payload: source server, destination ee:ef:33:9b:8d:5c. */
    static const uint8_t p[]={0x11,0,1,2,3,4,5,6,4,14,1,
        0xee,0xef,0x33,0x9b,0x8d,0x5c,0x40,0xff,0xcc,0x81,0x6a,0x43,0x18};
    sle_found_frame_t f={.sample_index=4033600,.channel_mhz=2414};
    f.frame.kind=SLE_FRAME_BROADCAST; f.frame.seed=11;
    f.frame.broadcast_type=3; f.frame.packet_type=5;
    f.frame.crc12_ok=f.frame.crc24_ok=f.frame.has_crc24=1;
    f.frame.length=f.frame.payload_len=sizeof p; memcpy(f.frame.payload,p,sizeof p);
    return f;
}
#endif
