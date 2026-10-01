#include "sle_cmtc.h"
#include <string.h>

/* DTAP: tcid(2) len(2) | CM signal: code(1) identifier(1) len(2) body.
 * Request body is the 4-byte bitmap. Response body is the bitmap followed
 * by one field per set bit in bit order (g_capability_signal_byte_len:
 * bit5 -> 2 bytes, bit7 -> 2 bytes), exactly as gle_tm_signal_capability_rsp
 * builds it and gle_tm_signal_capability_cfm validates it. */
static const uint8_t req_head[] = {2, 0, 8, 0, 1};
static const uint8_t req_tail[] = {4, 0, SLE_CMTC_BITMAP, 0, 0, 0};
static const uint8_t rsp_head[] = {2, 0, 12, 0, 2};
static const uint8_t rsp_tail[] = {8, 0, SLE_CMTC_BITMAP, 0, 0, 0,
                                   SLE_CMTC_MPS & 0xff, SLE_CMTC_MPS >> 8,
                                   SLE_CMTC_VERSION & 0xff, SLE_CMTC_VERSION >> 8};

static int request_sdu(const uint8_t *p, size_t n)
{
    return p && n == SLE_CMTC_REQ_SDU_LEN &&
           !memcmp(p, req_head, sizeof req_head) &&
           !memcmp(p + 6, req_tail, sizeof req_tail);
}

static int response_sdu(const uint8_t *p, size_t n)
{
    return p && n == SLE_CMTC_RSP_SDU_LEN &&
           !memcmp(p, rsp_head, sizeof rsp_head) &&
           !memcmp(p + 6, rsp_tail, 6); /* len + bitmap; fields free */
}

/* Table-146 header for an unsegmented, non-multiplexed SDU of length n. */
static int pdu_header(const uint8_t *p, size_t sdu)
{
    return p[0] == (uint8_t)((sdu & 31) << 3) && p[1] == (uint8_t)(sdu >> 5);
}

int sle_cmtc_capability_req_pdu(const uint8_t *p, size_t n)
{
    return p && n == SLE_CMTC_REQ_SDU_LEN + 2 &&
           pdu_header(p, SLE_CMTC_REQ_SDU_LEN) && request_sdu(p + 2, n - 2);
}

int sle_cmtc_capability_rsp_pdu(const uint8_t *p, size_t n)
{
    return p && n == SLE_CMTC_RSP_SDU_LEN + 2 &&
           pdu_header(p, SLE_CMTC_RSP_SDU_LEN) && response_sdu(p + 2, n - 2);
}

int sle_cmtc_capability_reply(const uint8_t *req, size_t n,
                              uint8_t *reply, size_t cap, size_t *reply_len)
{
    if (reply_len) *reply_len = 0;
    if (!request_sdu(req, n) || !reply || !reply_len ||
        cap < SLE_CMTC_RSP_SDU_LEN)
        return -1;
    memcpy(reply, rsp_head, sizeof rsp_head);
    reply[5] = req[5];
    memcpy(reply + 6, rsp_tail, sizeof rsp_tail);
    *reply_len = SLE_CMTC_RSP_SDU_LEN;
    return 0;
}

int sle_cmtc_capability_request(uint8_t identifier, uint8_t *sdu, size_t cap,
                                size_t *len)
{
    if (len) *len = 0;
    if (!sdu || !len || cap < SLE_CMTC_REQ_SDU_LEN) return -1;
    memcpy(sdu, req_head, sizeof req_head);
    sdu[5] = identifier;
    memcpy(sdu + 6, req_tail, sizeof req_tail);
    *len = SLE_CMTC_REQ_SDU_LEN;
    return 0;
}

int sle_cmtc_capability_parse_rsp(const uint8_t *sdu, size_t n,
                                  uint8_t *identifier, uint16_t *mps,
                                  uint16_t *version)
{
    if (!response_sdu(sdu, n)) return -1;
    if (identifier) *identifier = sdu[5];
    if (mps) *mps = (uint16_t)(sdu[12] | sdu[13] << 8);
    if (version) *version = (uint16_t)(sdu[14] | sdu[15] << 8);
    return 0;
}
