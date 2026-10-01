/* sle_access.h - SLE access framing (GB/T 46803.2-2025 6.1.4) in portable C.
 *
 * Structured encode/parse of the common broadcast structure (Table 1/Fig. 4)
 * and of the TLV units needed for access: discovery/access resource
 * configuration (0x00, Table 4), transmission indication (0x01, Table 5/6),
 * access request information (0x03, Table 8/9) and access response
 * information (0x04, Fig. 8/Table 10). Resource words have an explicit
 * standard or legacy WS63 layout; the historical entry points remain legacy.
 *
 * Bit packing: LSB-first, continuous across bytes; multi-byte fields are
 * little-endian. MAC-layer identities are 6 bytes in air order, which equals
 * the SDK/API print order (ee:ef:33:9b:8d:5c is sent as ee ef 33 9b 8d 5c).
 * Validated field-by-field against the attempt-8 WS63 recording; see
 * docs/research/sle-access-framing-2026-09-26.md for which fields are only
 * standard-derived.
 *
 * No dynamic allocation. All functions are reentrant.
 */
#ifndef SLE_ACCESS_H
#define SLE_ACCESS_H

#include <stddef.h>
#include <stdint.h>

#include "sle_phy.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SLE_ACC_OK = 0,
    SLE_ACC_TRUNCATED = -1,
    SLE_ACC_TRAILING = -2,
    SLE_ACC_RANGE = -3,      /* a field value does not fit its width */
    SLE_ACC_CAPACITY = -4,   /* output buffer or table too small */
    SLE_ACC_BAD_LENGTH = -5  /* TLV length not allowed by the standard */
} sle_acc_status_t;

/* A1 header values (GB/T 46803.1 6.3.1, control information A1). */
enum { SLE_BTYPE_NONCONN = 0, SLE_BTYPE_CONN_NOQUERY = 1,
       SLE_BTYPE_QUERY_NOCONN = 2, SLE_BTYPE_CONN_QUERY = 3 };
enum { SLE_PTYPE_PRIMARY = 0, SLE_PTYPE_AUX = 1, SLE_PTYPE_QUERY_REQ = 2,
       SLE_PTYPE_QUERY_RSP = 3, SLE_PTYPE_ACCESS_REQ = 4, SLE_PTYPE_ACCESS_RSP = 5 };

/* Table 2 data types. */
enum { SLE_TLV_DISC_ACCESS_CFG = 0x00, SLE_TLV_TX_INDICATION = 0x01,
       SLE_TLV_ACCESS_BASIC = 0x02, SLE_TLV_ACCESS_REQ_INFO = 0x03,
       SLE_TLV_ACCESS_RSP_INFO = 0x04, SLE_TLV_HIGH_LAYER = 0xFF };

/* Common structure present bits (Table 1). */
enum { SLE_PRESENT_LOCAL_ID = 1, SLE_PRESENT_IRK_ID = 2, SLE_PRESENT_PEER_ID = 4,
       SLE_PRESENT_RESOURCE = 8, SLE_PRESENT_DATA = 16 };

#define SLE_BCAST_MAX_TLV 8

typedef struct {
    uint8_t type;
    uint8_t len;
    uint16_t off;              /* offset into sle_bcast_pdu_t.data */
} sle_tlv_ref_t;

typedef struct {
    uint8_t present;           /* 5 bits */
    uint8_t rsv0;              /* 3 bits */
    uint8_t local_id_type;     /* 3 bits */
    uint8_t peer_id_type;      /* 3 bits */
    uint8_t rsv1;              /* 2 bits */
    uint8_t local_id[6];
    uint8_t irk_id;
    uint8_t peer_id[6];
    uint32_t resource_word;    /* raw little-endian 32-bit word */
    uint8_t n_tlv;
    sle_tlv_ref_t tlv[SLE_BCAST_MAX_TLV];
    uint8_t data[SLE_MAX_PAYLOAD_BYTES];
    uint16_t data_len;
} sle_bcast_pdu_t;

void sle_bcast_pdu_init(sle_bcast_pdu_t *pdu);
sle_acc_status_t sle_bcast_pdu_parse(const uint8_t *p, size_t n, sle_bcast_pdu_t *out);
/* Returns payload length (>= 2) or 0 on error. */
size_t sle_bcast_pdu_build(const sle_bcast_pdu_t *pdu, uint8_t *out, size_t cap);
/* Appends a TLV and sets SLE_PRESENT_DATA. */
sle_acc_status_t sle_bcast_pdu_add_tlv(sle_bcast_pdu_t *pdu, uint8_t type,
                                       const uint8_t *data, size_t len);
/* First TLV of `type`, or NULL. */
const uint8_t *sle_bcast_pdu_find_tlv(const sle_bcast_pdu_t *pdu, uint8_t type, size_t *len);

/* ---- Resource word layouts --------------------------------------------- */
typedef enum {
    SLE_RESOURCE_LEGACY_WS63 = 0, /* unit bit 8, offset bits 9-20 */
    SLE_RESOURCE_STANDARD = 1     /* offset bits 8-19, unit bit 31 */
} sle_resource_layout_t;

typedef struct {
    uint8_t channel;           /* bits 0-7: physical channel number */
    uint8_t unit;              /* 0 -> 125 us, 1 -> 1250 us */
    uint16_t offset;           /* 12 bits */
    uint8_t frame_type;        /* 4 bits */
    uint8_t bandwidth;         /* 2 bits */
    uint8_t pilot;             /* 2 bits */
    uint8_t clock_accuracy;    /* 3 bits */
} sle_resource_word_t;

sle_acc_status_t sle_resource_word_encode_layout(const sle_resource_word_t *rw,
                                                  sle_resource_layout_t layout, uint32_t *word);
sle_acc_status_t sle_resource_word_decode_layout(uint32_t word,
                                                  sle_resource_layout_t layout, sle_resource_word_t *rw);
/* Backward-compatible legacy WS63 entry points. */
sle_acc_status_t sle_resource_word_encode(const sle_resource_word_t *rw, uint32_t *word);
void sle_resource_word_decode(uint32_t word, sle_resource_word_t *rw);
uint32_t sle_resource_word_offset_us(const sle_resource_word_t *rw);

/* ---- TLV 0x00 discovery/access resource configuration (Table 4) -------- */
typedef struct {
    uint16_t req_offset_us;
    uint8_t req_max_len;
    uint16_t rsp_offset_us;
    uint8_t gt;                /* 2 bits: bit0 0=T/1=G, bit1 0=negotiable */
    uint8_t count;             /* 6 bits: request windows */
    uint8_t req_type;          /* 2 bits: 0 query, 1 access, 2 unrestricted */
    uint8_t carry_info;        /* 2 bits */
    uint8_t peer_id_type;      /* 3 bits */
    uint8_t id_present;        /* 1 bit */
    uint8_t peer_id[6];
} sle_access_resource_t;

/* Parses up to `max_units` units; *n_units receives the count. */
sle_acc_status_t sle_access_resource_parse(const uint8_t *p, size_t n,
                                           sle_access_resource_t *units,
                                           size_t max_units, size_t *n_units);
/* Returns bytes written or 0 on error. */
size_t sle_access_resource_build(const sle_access_resource_t *units, size_t n_units,
                                 uint8_t *out, size_t cap);
/* floor((rsp - req - 125) / count) per Table 4. Returns 0 if invalid. */
uint32_t sle_access_window_len_us(const sle_access_resource_t *u);

/* ---- TLV 0x01 transmission indication (Table 5) ------------------------ */
#define SLE_TX_IND_LEN_2G4 60
#define SLE_TX_IND_LEN_5G  75
typedef struct {
    uint32_t base_slot;           /* 32 */
    uint32_t start_offset_us;     /* 24: from the carrying frame's start */
    uint16_t group_period_slots;  /* 16, scheduling slots */
    uint16_t event_period_slots;  /* 16 */
    uint16_t intra_event_gap_us;  /* 16 */
    uint16_t inter_event_gap_us;  /* 16 */
    uint8_t event_count;          /* 8 */
    uint8_t peer_id[6];           /* 48 */
    uint8_t peer_id_type;         /* 3 */
    uint8_t sleep_clock_accuracy; /* 3 */
    uint8_t first_second;         /* 1 */
    uint8_t rsv0;                 /* 1 */
    uint8_t first_frame_type;     /* 4 */
    uint8_t second_frame_type;    /* 4 */
    uint8_t first_crc_type;       /* 1: 0 CRC24, 1 CRC32 */
    uint8_t second_crc_type;      /* 1 */
    uint8_t first_feedback;       /* 6 */
    uint8_t second_feedback;      /* 3 */
    uint8_t sched_slot;           /* 3: 0..4 = 25..125 us */
    uint8_t rsv1;                 /* 2 */
    uint32_t first_lid;           /* 24 */
    uint32_t second_lid;          /* 24 */
    uint8_t first_bw, second_bw, first_pilot, second_pilot; /* 2 each */
    uint16_t first_pdu_max;       /* 11 */
    uint16_t second_pdu_max;      /* 11 */
    uint16_t first_max_time_offset;  /* 9, raw field value */
    uint16_t second_max_time_offset; /* 9 */
    uint32_t first_crc_init;      /* 32 */
    uint32_t second_crc_init;     /* 32 */
    uint16_t latency_groups;      /* 16 */
    uint16_t timeout_10ms;        /* 16 */
    uint8_t hop_map[25];          /* bit n = RF channel n (2402+n MHz) */
    uint8_t hop_map_len;          /* 10 (2.4 GHz) or 25 */
} sle_tx_indication_t;

sle_acc_status_t sle_tx_indication_parse(const uint8_t *p, size_t n, sle_tx_indication_t *out);
size_t sle_tx_indication_build(const sle_tx_indication_t *in, uint8_t *out, size_t cap);
/* 25/50/75/100/125 us, or 0 for a reserved code. */
uint32_t sle_sched_slot_us(uint8_t code);

/* ---- TLV 0x03 access request information (Table 8/9) ------------------- */
typedef struct {
    uint8_t present;           /* bit i: field i present, in Table 8 order */
    uint8_t gt;                /* 2 */
    uint8_t frame_struct;      /* 4 */
    uint8_t bandwidth;         /* 3 */
    uint16_t mcs;              /* 13 */
    uint8_t pilot;             /* 4 */
    uint8_t sched_slot;        /* 5 */
    uint8_t switch_delay;      /* 4 */
    uint8_t crc;               /* 2 */
    uint8_t pad;               /* zero padding to the byte boundary */
} sle_access_req_info_t;

sle_acc_status_t sle_access_req_info_parse(const uint8_t *p, size_t n, sle_access_req_info_t *out);
size_t sle_access_req_info_build(const sle_access_req_info_t *in, uint8_t *out, size_t cap);

/* ---- TLV 0x04 access response information (Fig. 8/Table 10) ------------ */
#define SLE_ACCESS_RSP_MAX_UNITS 4
typedef struct {
    uint8_t peer_id[6];
    uint8_t rsp_type;          /* 3: 0 agree */
    uint8_t peer_id_type;      /* 3 */
    uint8_t repeat;            /* 2: 0 none, 1 once (first unit), 2 each unit */
    uint8_t has_capability;
    uint8_t capability[6];     /* same bit layout as access request info */
} sle_access_rsp_unit_t;

typedef struct {
    uint8_t count;             /* 6 */
    uint8_t rsv;               /* 2 */
    sle_access_rsp_unit_t unit[SLE_ACCESS_RSP_MAX_UNITS];
} sle_access_rsp_info_t;

sle_acc_status_t sle_access_rsp_info_parse(const uint8_t *p, size_t n, sle_access_rsp_info_t *out);
size_t sle_access_rsp_info_build(const sle_access_rsp_info_t *in, uint8_t *out, size_t cap);

/* ---- Complete access request / response payloads ----------------------- */
/* Request: structure 0x15 (local id, peer id, data), TLV 0x01 then 0x03,
 * as sent by the WS63 client. Returns payload length or 0. */
size_t sle_access_request_build(const uint8_t local_id[6], const uint8_t peer_id[6],
                                const sle_tx_indication_t *txi,
                                const sle_access_req_info_t *req,
                                uint8_t *out, size_t cap);
/* Response: structure 0x11 (local id, data), TLV 0x04. */
size_t sle_access_response_build(const uint8_t local_id[6], const sle_access_rsp_info_t *rsp,
                                 uint8_t *out, size_t cap);

/* A1 frame bits from the sync word (preamble not included): whitening seed =
 * physical channel number, CRC24 seed 0x555555. Returns bits or 0. */
size_t sle_access_encode_frame(uint8_t *out_bits, size_t cap_bits, const uint8_t *payload,
                               size_t len, uint8_t phys_channel, uint8_t btype, uint8_t ptype);

#ifdef __cplusplus
}
#endif
#endif /* SLE_ACCESS_H */
