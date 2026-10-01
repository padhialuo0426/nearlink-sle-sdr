/* Narrow CMTC (DTAP TCID 0x0002) capability exchange for WS63 SDK 1.10.108.
 *
 * 1.10.108 libbth_gle.a gle_tm_lcid_init sends CAPABILITY_REQ bitmap 0xa0
 * on every new link, in both roles; 1.10.102 does not. Only that exact
 * unfragmented request is admitted before encryption; everything else in
 * plaintext DATA remains rejected by the pair state machines.
 * Evidence: docs/experiments/cmtc-capability-2026-09-28.md */
#ifndef SLE_CMTC_H
#define SLE_CMTC_H
#include <stddef.h>
#include <stdint.h>

#define SLE_CMTC_TCID 0x0002u
#define SLE_CMTC_BITMAP 0xa0u      /* bit5 MPS, bit7 version */
#define SLE_CMTC_MPS 90u           /* discarded by 1.10.108 capability_cfm */
#define SLE_CMTC_VERSION 0x0101u   /* g_tm_version_default in 1.10.108 */
#define SLE_CMTC_REQ_SDU_LEN 12u
#define SLE_CMTC_RSP_SDU_LEN 16u

/* Complete table-146 PDU (2-byte header + SDU), plaintext. Any identifier;
 * a response may carry any MPS/version values (WS63 sends 672 / 0x0101). */
int sle_cmtc_capability_req_pdu(const uint8_t *p, size_t n);
int sle_cmtc_capability_rsp_pdu(const uint8_t *p, size_t n);
/* Our own request, sent once per link like 1.10.108 gle_tm_lcid_init. The
 * peer then classifies us through capability_ind first (dev_type 3), which
 * keeps its SSAP discovery in the 1.10.102 format. */
int sle_cmtc_capability_request(uint8_t identifier, uint8_t *sdu, size_t cap,
                                size_t *len);
/* Parse a peer response SDU; returns 0 or -1. */
int sle_cmtc_capability_parse_rsp(const uint8_t *sdu, size_t n,
                                  uint8_t *identifier, uint16_t *mps,
                                  uint16_t *version);
/* Input is a reassembled DTAP SDU; output is the DTAP SDU to queue.
 * The request identifier is echoed. Returns 0 or -1. */
int sle_cmtc_capability_reply(const uint8_t *req, size_t n,
                              uint8_t *reply, size_t cap, size_t *reply_len);
#endif
