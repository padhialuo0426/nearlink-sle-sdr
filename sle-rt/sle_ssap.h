/* sle_ssap.h - NearLink/SLE SSAP (Service Access Protocol) PDU codec, portable C11.
 *
 * SSAP rides the SLE link's connection-oriented data channel on the fixed
 * transport-channel id TCID_SLE_SMTC = 0x0A (FACT:
 * communication_nearlink_service/services/stack/src/cp/bsl/sle/cm/interface/
 * cm_trans_channel_api.h L45). This file only encodes/decodes SSAP PDUs; it
 * does not touch the SLE link/connection layer (see sle_link.h) or carry the
 * TCID itself - that belongs to whatever transport glue moves bytes to/from
 * the connection.
 *
 * Field layouts are taken from the ASCII diagrams and struct/macro
 * definitions in two independently-shipped, non-identical stacks that both
 * implement the same over-the-air protocol (see review in
 * logs/p2-20260925/oh-ssap-pairing-review.md, sec. 3-4):
 *   - OH  = communication_nearlink_service/services/stack/src/cp/bsl/sle/
 *           servm/ssap/include/inner/ssap_pkt.h (PDU byte/bit layout, opcodes,
 *           error codes) and .../ssap/include/ssap_type.h (UUID/handle
 *           constants) - line numbers cited per field below.
 *   - WS63 = bearpi-pico_h3863/include/middleware/services/bts/sle/
 *           sle_ssap_stru.h, sle_ssap_client.h, sle_ssap_server.h (public
 *           API-level structs; confirms field semantics, not wire bytes).
 * No OH source is copied verbatim; every struct here is re-derived from the
 * field diagrams/macros and re-expressed with explicit byte offsets.
 *
 * Every multi-byte integer field in an SSAP PDU is a plain byte-aligned
 * little-endian integer (FACT: all OH PDU structs are
 * __attribute__((packed)) native-endian structs built on a little-endian
 * target; e.g. SSAP_PduExchangePkt_S.msgMtu/msgVersion, ssap_pkt.h L245-246).
 * The one-byte "ctrl" field that follows msgCode in every PDU is bit-packed;
 * this project treats bit 0 of that byte as the first C bitfield member
 * (LSB-first), which is FACT for the `fragment` sub-field specifically
 * (SSAP_CTRL_FRAG_MASK = 0x03, ssap_type.h L167, independent of any compiler
 * bitfield-layout assumption) and INFERENCE (medium-high confidence, GCC/
 * clang little-endian bitfield allocation, first-declared member = LSB) for
 * every other named sub-field in the same byte - each such field is
 * commented FACT or INFERENCE individually at its accessor.
 *
 * No dynamic allocation. All buffers are caller-supplied. Reentrant.
 */
#ifndef SLE_SSAP_H
#define SLE_SSAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SLE_SSAP_OK = 0,
    SLE_SSAP_TRUNCATED = -1,     /* buffer shorter than the PDU requires */
    SLE_SSAP_TRAILING = -2,      /* extra bytes after a fixed-length PDU */
    SLE_SSAP_RANGE = -3,         /* a field value does not fit its width */
    SLE_SSAP_CAPACITY = -4,      /* output buffer or item table too small */
    SLE_SSAP_BAD_LENGTH = -5,    /* length disagrees with what the opcode allows */
    SLE_SSAP_BAD_OPCODE = -6,    /* msgCode not in 0x01..0x14 / wrong decoder called */
} sle_ssap_status_t;

/* ---- Opcodes (FACT: ssap_type.h L128-150, SSAP_MsgCode_E) --------------- */
typedef enum {
    SLE_SSAP_ERROR_RSP                 = 0x01,
    SLE_SSAP_EXCHANGE_INFO_REQ         = 0x02,
    SLE_SSAP_EXCHANGE_INFO_RSP         = 0x03,
    SLE_SSAP_FIND_STRUCTURE_REQ        = 0x04,
    SLE_SSAP_FIND_STRUCTURE_RSP        = 0x05,
    SLE_SSAP_FIND_STRUCTURE_BY_UUID_REQ = 0x06,
    SLE_SSAP_FIND_STRUCTURE_BY_UUID_RSP = 0x07,
    SLE_SSAP_READ_REQ                  = 0x08,
    SLE_SSAP_READ_RSP                  = 0x09,
    SLE_SSAP_READ_BY_UUID_REQ          = 0x0A,
    SLE_SSAP_READ_BY_UUID_RSP          = 0x0B,
    SLE_SSAP_WRITE_CMD                 = 0x0C,
    SLE_SSAP_WRITE_REQ                 = 0x0D,
    SLE_SSAP_WRITE_RSP                 = 0x0E,
    SLE_SSAP_VALUE_NTF                 = 0x0F,
    SLE_SSAP_VALUE_IND                 = 0x10,
    SLE_SSAP_VALUE_ACK                 = 0x11,
    SLE_SSAP_CALL_METHOD_CMD           = 0x12,
    SLE_SSAP_CALL_METHOD_REQ           = 0x13,
    SLE_SSAP_CALL_METHOD_RSP           = 0x14,
} sle_ssap_opcode_t;

/* Error codes (FACT: ssap_type.h L199-222, SSAP_PduErrCode_E). */
typedef enum {
    SLE_SSAP_ERRCODE_SUCCESS = 0x00,
    SLE_SSAP_ERRCODE_INVALID_PDU,
    SLE_SSAP_ERRCODE_UNSUPPORT_PDU,
    SLE_SSAP_ERRCODE_UNKNOWN,
    SLE_SSAP_ERRCODE_INVALID_HANDLE,
    SLE_SSAP_ERRCODE_NO_RESOURCE,
    SLE_SSAP_ERRCODE_FORBID_READ,
    SLE_SSAP_ERRCODE_FORBID_WRITE,
    SLE_SSAP_ERRCODE_UNAUTHENTICATED,
    SLE_SSAP_ERRCODE_UNAUTHORIZED,
    SLE_SSAP_ERRCODE_UNENCRYPTED,
    SLE_SSAP_ERRCODE_ITEM_INEXIST,
    SLE_SSAP_ERRCODE_METHOD_ACCESS,
    SLE_SSAP_ERRCODE_DATA_TYPE,
    SLE_SSAP_ERRCODE_DATA_LENGTH,
    SLE_SSAP_ERRCODE_DATA_RANGE,
    SLE_SSAP_ERRCODE_SERVER_FRAG,
    SLE_SSAP_ERRCODE_ITEM_OVER_LIMIT,
    SLE_SSAP_ERRCODE_TIMEOUT = 0xB0,   /* application-defined, ssap_type.h L220 */
} sle_ssap_errcode_t;

/* Fragment sub-field, always the low 2 bits of ctrl when present (FACT:
 * SSAP_CTRL_FRAG_MASK = 0x03, ssap_type.h L162-167). Not every opcode's ctrl
 * byte carries this sub-field - see the whitelist in
 * sle_ssap_opcode_is_frag_capable(), taken verbatim (renamed) from
 * ssap_manager.c SSAP_IsFragPkt() L190-217. */
enum {
    SLE_SSAP_FRAG_BEGIN   = 0x0,
    SLE_SSAP_FRAG_MID     = 0x1,
    SLE_SSAP_FRAG_END     = 0x2,
    SLE_SSAP_FRAG_NONE    = 0x3,   /* single, complete PDU */
};
#define SLE_SSAP_CTRL_FRAG_MASK 0x03u

/* WRITE_CMD/WRITE_REQ ctrl "oper" sub-field, bits 3-4 (FACT:
 * SSAP_CTRL_WRITE_OPER_SHIFT = 3, ssap_type.h L168-175). */
enum {
    SLE_SSAP_WRITE_INSTANT = 0x0,  /* write immediately */
    SLE_SSAP_WRITE_PART    = 0x1,  /* partial value, more fragments follow */
    SLE_SSAP_WRITE_CANCEL  = 0x2,  /* cancel an in-progress fragmented write */
};
#define SLE_SSAP_CTRL_WRITE_OPER_SHIFT 3u
#define SLE_SSAP_CTRL_WRITE_OPER_MASK (0x03u << SLE_SSAP_CTRL_WRITE_OPER_SHIFT)

/* WRITE_RSP ctrl "result" sub-field, bits 2-3 (INFERENCE: declaration order
 * after fragment:2 in SSAP_PduWriteRsp_S.ctrl, ssap_pkt.h L481-492; values
 * are FACT from SSAP_CTRL_WRITE_SUCCESS/PART/CANCEL = 0/1/2). */
enum {
    SLE_SSAP_WRITE_RESULT_SUCCESS = 0x0,
    SLE_SSAP_WRITE_RESULT_PART    = 0x1,
    SLE_SSAP_WRITE_RESULT_CANCEL  = 0x2,
};

/* FIND_STRUCTURE_(BY_UUID_)REQ ctrl.findType (FACT: ssap_type.h L237-244,
 * SSAP_FindType_E; matches WS63 ssap_find_type_t, sle_ssap_stru.h L69-80). */
typedef enum {
    SLE_SSAP_FIND_TYPE_SERVICE_STRUCTURE = 0x00,
    SLE_SSAP_FIND_TYPE_PRIMARY_SERVICE   = 0x01,
    SLE_SSAP_FIND_TYPE_REFERENCE_SERVICE = 0x02,
    SLE_SSAP_FIND_TYPE_PROPERTY          = 0x03,
    SLE_SSAP_FIND_TYPE_METHOD            = 0x04,
    SLE_SSAP_FIND_TYPE_EVENT             = 0x05,
} sle_ssap_find_type_t;

/* FIND_STRUCTURE_(BY_UUID_)REQ ctrl.itemType (FACT: ssap_type.h L246-250,
 * SSAP_FindItemType_E). Also reused as FIND_STRUCTURE_RSP ctrl.itemType
 * (FACT: ssap_pkt.h L280-288, SSAP_PduFindStructRsp_S.ctrl). */
typedef enum {
    SLE_SSAP_ITEM_TYPE_STANDARD = 0x00,
    SLE_SSAP_ITEM_TYPE_CUSTOM   = 0x01,
    SLE_SSAP_ITEM_TYPE_MIX      = 0x02,
} sle_ssap_item_type_t;

/* ---- UUIDs --------------------------------------------------------------
 * A "standard" UUID is 2 bytes; a "custom"/vendor UUID is 16 bytes with the
 * 2-byte standard value embedded at byte offset 14..15 of the 16-byte form
 * (FACT: SSAP_UUID16_LEN=2, SSAP_UUID128_LEN=16, SSAP_UUID_STD_BASE_OFFSET=14,
 * ssap_type.h L35-37; WS63 sle_uuid_t{len,uuid[16]} agrees on the 16-byte
 * container, sle_ssap_stru.h L143-152).
 *
 * Byte order of that embedded 16-bit value on the wire: the official WS63
 * sample uses vendor base 37BEA880-FC70-11EA-B720-00000000xxxx with service
 * xxxx=0x2222 and property xxxx=0x2323 (logs/p2-20260925/
 * official-samples-analysis.md sec.4/5). Both sample values happen to have
 * identical high and low bytes (0x22/0x22 and 0x23/0x23), so this sample
 * CANNOT distinguish big- from little-endian placement at offset 14..15 -
 * this is a real ambiguity, not resolved by available evidence.
 * INFERENCE (medium confidence): this file defaults to big-endian / "string
 * order" (byte[14]=high byte, byte[15]=low byte), matching the natural
 * left-to-right byte order a UUID string is normally parsed into and the
 * order the base UUID's own bytes already appear in above (e.g. 0xFC,0x70
 * for "FC70", not reversed). Flip SLE_SSAP_UUID_STD_BE to 0 to try the
 * opposite convention once real traffic is captured; every caller must go
 * through sle_ssap_uuid16_to128()/128_to16() so one edit here is enough. */
#define SLE_SSAP_UUID_STD_BE 1

#define SLE_SSAP_UUID16_LEN 2
#define SLE_SSAP_UUID128_LEN 16
#define SLE_SSAP_UUID_STD_OFFSET 14

/* Vendor base used by the official sle_uart sample: 37BEA880-FC70-11EA-B720-
 * 00000000xxxx (FACT: logs/p2-20260925/official-samples-analysis.md sec.4-5,
 * derived from the sample's advertised/queried UUIDs). Bytes 0..13 fixed,
 * bytes 14..15 carry the "standard" 16-bit id per SLE_SSAP_UUID_STD_BE. */
extern const uint8_t sle_ssap_vendor_base_uuid[SLE_SSAP_UUID128_LEN];

typedef struct {
    uint8_t len;                       /* SLE_SSAP_UUID16_LEN or _128_LEN */
    uint8_t bytes[SLE_SSAP_UUID128_LEN];
} sle_ssap_uuid_t;

void sle_ssap_uuid16(uint16_t std, sle_ssap_uuid_t *out);
/* Embeds `std` into a copy of `base` (16 bytes) at SLE_SSAP_UUID_STD_OFFSET. */
void sle_ssap_uuid128(const uint8_t base[SLE_SSAP_UUID128_LEN], uint16_t std,
                      sle_ssap_uuid_t *out);
/* Convenience: vendor-base 128-bit UUID as used by the official sample. */
void sle_ssap_uuid128_vendor(uint16_t std, sle_ssap_uuid_t *out);
/* Extracts the "standard" 16-bit value: for a 2-byte UUID this is simply
 * the little-endian value; for a 16-byte UUID it is the offset-14..15 value
 * per SLE_SSAP_UUID_STD_BE, regardless of whether `u` is really a
 * standard-derived UUID - caller decides if that is meaningful. */
uint16_t sle_ssap_uuid128_std_part(const sle_ssap_uuid_t *u);
int sle_ssap_uuid_equal(const sle_ssap_uuid_t *a, const sle_ssap_uuid_t *b);

/* ---- Common PDU header --------------------------------------------------
 * Every PDU starts msgCode(1) ctrl(1) (FACT: SSAP_PDU_BASE_LEN=2,
 * ssap_type.h L35). */
#define SLE_SSAP_HEADER_LEN 2u
#define SLE_SSAP_HANDLE_LEN 2u

/* Whitelist of opcodes whose ctrl low 2 bits are the fragment indicator
 * (FACT, ported 1:1 from the switch in ssap_manager.c SSAP_IsFragPkt(),
 * L198-216: ERROR_RSP, EXCHANGE_INFO_*, FIND_STRUCTURE_REQ and
 * FIND_STRUCTURE_BY_UUID_REQ, READ_BY_UUID_REQ are explicitly NOT
 * fragmentable - only the opcodes listed in that switch are). */
int sle_ssap_opcode_is_frag_capable(uint8_t msg_code);
/* True if ctrl's low 2 bits are not SLE_SSAP_FRAG_NONE, for a frag-capable
 * opcode with at least SLE_SSAP_HEADER_LEN bytes (mirrors SSAP_IsFragPkt()). */
int sle_ssap_is_frag_pkt(const uint8_t *pdu, size_t len);

/* ==== 0x01 ERROR_RSP =======================================================
 * FACT: ssap_pkt.h L182-197, SSAP_PduErrRsp_S (fixed 6 bytes; ctrl reserved).
 *   msgCode(1)=0x01 | ctrl(1, reserved=0) | msgCodeReq(1) | errHandle(2 LE) | errorCode(1)
 */
#define SLE_SSAP_ERROR_RSP_LEN 6u
typedef struct {
    uint8_t req_msg_code;
    uint16_t err_handle;
    uint8_t error_code;
} sle_ssap_error_rsp_t;

size_t sle_ssap_error_rsp_build(const sle_ssap_error_rsp_t *in, uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_error_rsp_parse(const uint8_t *p, size_t n, sle_ssap_error_rsp_t *out);

/* ==== 0x02/0x03 EXCHANGE_INFO_REQ/RSP =====================================
 * FACT: ssap_pkt.h L224-247, SSAP_PduExchangePkt_S (fixed 6 bytes,
 * SSAP_EXCHANGE_INFO_PKT_LEN, ssap_type.h... actually ssap_pkt.h L26).
 *   msgCode(1) | ctrl(1, bitfield below) | msgMtu(2 LE) | msgVersion(2 LE)
 * ctrl bit layout (LSB-first): mtu:1 version:1 extMsgCtrl:1 reliable:1
 * fragment:1 multiProcessing:1 resv:2 (INFERENCE for exact bit *positions*
 * of each named flag beyond bit0, per the file header's general note; FACT
 * that these 6 flags + 2 resv bits are the complete set and pack into one
 * byte, ssap_pkt.h L236-244).
 * NOTE: this PDU's own field named "fragment" is a presence *flag*
 * ("do the mtu/version fields apply"), unrelated to the ACK/reassembly
 * fragment sub-field elsewhere - EXCHANGE_INFO is explicitly NOT in the
 * SSAP_IsFragPkt() whitelist (FACT, ssap_manager.c L196-217).
 */
#define SLE_SSAP_EXCHANGE_INFO_LEN 6u
typedef struct {
    uint8_t mtu_present;
    uint8_t version_present;
    uint8_t ext_msg_ctrl;
    uint8_t reliable;
    uint8_t fragment_capable;
    uint8_t multi_processing;
    uint16_t mtu;
    uint16_t version;
} sle_ssap_exchange_info_t;

size_t sle_ssap_exchange_info_build(uint8_t msg_code, const sle_ssap_exchange_info_t *in,
                                    uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_exchange_info_parse(const uint8_t *p, size_t n,
                                               sle_ssap_exchange_info_t *out);

/* ==== 0x04/0x06 FIND_STRUCTURE_REQ / FIND_STRUCTURE_BY_UUID_REQ ===========
 * FACT: ssap_pkt.h L250-270, SSAP_PduFindStructReq_S.
 *   msgCode(1) | ctrl(1) | startHandle(2 LE) | endHandle(2 LE) | uuid[2 or 16]
 * ctrl (LSB-first): findType:3 itemType:2 rspMode:1 resv:2 (FACT for the
 * field set and widths, ssap_pkt.h L261-266; findType=PROPERTY(0b011) in
 * the low 3 bits is corroborated by the official sample's observed request,
 * logs/p2-20260925/official-samples-analysis.md sec.5).
 * uuid[] is present (2 bytes if itemType=STANDARD, 16 if CUSTOM) for
 * FIND_STRUCTURE_BY_UUID_REQ (0x06); FIND_STRUCTURE_REQ (0x04) omits it
 * (queries every structure of findType in the handle range) - INFERENCE
 * from the "BY_UUID" opcode name and the fact FIND_STRUCTURE_REQ has no
 * length macro requiring a uuid, only SSAP_FIND_STRUCTURE_STD/CUS_LEN which
 * describe an RSP *item*, not this REQ.
 */
typedef struct {
    sle_ssap_find_type_t find_type;
    sle_ssap_item_type_t item_type;
    uint8_t rsp_mode;              /* 0 = single response, 1 = multiple */
    uint16_t start_handle;
    uint16_t end_handle;
    sle_ssap_uuid_t uuid;          /* only used/emitted for BY_UUID_REQ */
} sle_ssap_find_structure_req_t;

size_t sle_ssap_find_structure_req_build(uint8_t msg_code,
                                         const sle_ssap_find_structure_req_t *in,
                                         uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_find_structure_req_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                                    sle_ssap_find_structure_req_t *out);

/* ==== 0x05/0x07 FIND_STRUCTURE_RSP / FIND_STRUCTURE_BY_UUID_RSP ===========
 * FACT: ssap_pkt.h L272-293, SSAP_PduFindStructRsp_S.
 *   msgCode(1) | ctrl(1) | data[]  (opaque list of found-item records)
 * ctrl (LSB-first): fragment:2 itemType:2 resv:4 (FACT: fragment low bits
 * per SSAP_CTRL_FRAG_MASK; itemType widths from SSAP_PduFindStructRsp_S.ctrl
 * ssap_pkt.h L282-286).
 *
 * The envelope (this build/parse pair) only frames the opaque item list;
 * see sle_ssap_find_item_*() below for the per-item records that go in
 * `data` for opcode 0x04/0x05 (SSAP_FIND_STRUCTURE_*), and
 * sle_ssap_find_property_item_*() for the property-only records used by
 * 0x06/0x07 (SSAP_FIND_STRUCTURE_BY_UUID_*) responses.
 */
typedef struct {
    uint8_t fragment;               /* SLE_SSAP_FRAG_* */
    sle_ssap_item_type_t item_type;
    const uint8_t *data;            /* borrowed pointer into caller's buffer on parse */
    size_t data_len;
} sle_ssap_find_structure_rsp_t;

size_t sle_ssap_find_structure_rsp_build(uint8_t msg_code,
                                         const sle_ssap_find_structure_rsp_t *in,
                                         uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_find_structure_rsp_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                                    sle_ssap_find_structure_rsp_t *out);

/* Generic "structure" item, used inside FIND_STRUCTURE_RSP (0x05) `data`
 * when ctrl.itemType selects that record shape. FACT (lengths only):
 * SSAP_FIND_STRUCTURE_BASE_LNE/STD_LEN/CUS_LEN, ssap_pkt.h L57-61 ->
 * handle(2)+type(1)+descriptorCount(1) [+uuid(2/16)] [+operation(4 LE)].
 * INFERENCE (field order): ssap_pkt.h has no explicit struct for this item,
 * only size macros; the order below (handle, type, descriptorCount, uuid,
 * operation) follows the macros' own left-to-right addition order
 * (SSAP_FIND_STRUCTURE_BASE_LNE first, then "+ UUID_LEN + OPERATION_LEN"),
 * medium confidence. */
typedef struct {
    uint16_t handle;
    uint8_t item_type;               /* NLSTK_SsapItemType_E, ssap_type.h L73-89 */
    uint8_t descriptor_count;
    sle_ssap_uuid_t uuid;
    uint32_t operation;               /* SSAP_Operation bitmask, ssap_type.h L91-108 */
} sle_ssap_find_structure_item_t;

size_t sle_ssap_find_structure_item_build(const sle_ssap_find_structure_item_t *in,
                                          int std_uuid, uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_find_structure_item_parse(const uint8_t *p, size_t n, int std_uuid,
                                                     sle_ssap_find_structure_item_t *out,
                                                     size_t *consumed);

/* Property item, used inside FIND_STRUCTURE_BY_UUID_RSP (0x07) `data` when
 * find_type was PROPERTY. FACT (lengths only): SSAP_FIND_PROPERTY_BASE_LEN/
 * STD_LEN/CUS_LEN, ssap_pkt.h L48-52 -> handle(2)+operation(4 LE)+
 * descriptorCount(1) [+uuid(2/16)]. INFERENCE (field order): no explicit
 * struct; order below (handle, uuid, operation, descriptorCount) follows
 * the high-level SSAP_FindPropertyInfo_S field order (ssap_type.h L298-305:
 * handle, uuid, isStdUuid, operation, descriptorCount, descriptors), medium
 * confidence - this disagrees with the pure left-to-right macro-addition
 * order used for sle_ssap_find_structure_item_t above (uuid before
 * operation there too, so actually consistent for uuid-before-operation;
 * the difference is descriptorCount placement, kept last here to match
 * SSAP_FindPropertyInfo_S). Matches the official sample: FIND_STRUCTURE_
 * BY_UUID_REQ for service 0x2222 returns a property item with handle=2
 * (logs/p2-20260925/official-samples-analysis.md sec.5). */
typedef struct {
    uint16_t handle;
    sle_ssap_uuid_t uuid;
    uint32_t operation;
    uint8_t descriptor_count;
} sle_ssap_find_property_item_t;

size_t sle_ssap_find_property_item_build(const sle_ssap_find_property_item_t *in,
                                         int std_uuid, uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_find_property_item_parse(const uint8_t *p, size_t n, int std_uuid,
                                                    sle_ssap_find_property_item_t *out,
                                                    size_t *consumed);

/* ==== 0x08 READ_REQ ========================================================
 * FACT: ssap_pkt.h L296-318, SSAP_PduReadReq_S / Ssap_PduReadReqItem_S.
 *   msgCode(1) | ctrl(1: fragment:2 resv:6) | items[]  (each: handle(2 LE) type(1))
 * SSAP_TYPE_DATA=0 is "value in the data field"; other values match a
 * descriptor type (FACT, ssap_pkt.h L317, ssap_type.h L127-135).
 * READ_REQ is NOT in the SSAP_IsFragPkt() opcode whitelist (FACT,
 * ssap_manager.c L198-212 lists READ_RSP/READ_BY_UUID_RSP but not
 * READ_REQ), so its ctrl.fragment field, while present in the struct, is
 * never treated as a fragmentation indicator by the stack; kept for layout
 * fidelity only.
 */
typedef struct {
    uint16_t handle;
    uint8_t type;
} sle_ssap_read_item_t;

#define SLE_SSAP_READ_REQ_MAX_ITEMS 32
typedef struct {
    uint8_t fragment;
    sle_ssap_read_item_t item[SLE_SSAP_READ_REQ_MAX_ITEMS];
    size_t n_item;
} sle_ssap_read_req_t;

size_t sle_ssap_read_req_build(const sle_ssap_read_req_t *in, uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_read_req_parse(const uint8_t *p, size_t n, sle_ssap_read_req_t *out);

/* ==== 0x09 READ_RSP ========================================================
 * FACT: ssap_pkt.h L320-346, SSAP_PduReadRsp_S / SSAP_PduReadRspItem_S.
 *   msgCode(1) | ctrl(1) | items[]
 * ctrl (LSB-first): fragment:2 multi:1 error:1 resv:4 (FACT for fragment
 * bits; multi/error bit *positions* INFERENCE from declaration order, but
 * corroborated for READ_BY_UUID_RSP's identical layout by
 * SSAP_READ_BY_UUID_RSP_MULTI_CONTROL=4(bit2)/_ERR_CONTROL=8(bit3),
 * ssap_type.h L89-91, which are exact FACTs for that sibling PDU).
 * multi=0: items is a single raw value, length implied by PDU length.
 * multi=1: items is a sequence of {length:15 LE|success:1, value[length]}
 * (FACT: length occupies the low 15 bits because
 * SSAP_READ_RSP_ITEM_LEN_MAX=32767=0x7FFF, ssap_type.h L87; success is then
 * the remaining top bit, bit 15).
 */
#define SLE_SSAP_READ_RSP_MAX_ITEMS 8
#define SLE_SSAP_READ_RSP_ITEM_MAX_LEN 256
typedef struct {
    uint8_t success;                 /* 1 = ok, 0 = failed (value holds an error code byte) */
    uint16_t length;
    uint8_t value[SLE_SSAP_READ_RSP_ITEM_MAX_LEN];
} sle_ssap_read_rsp_item_t;

typedef struct {
    uint8_t fragment;
    uint8_t multi;
    uint8_t error;
    sle_ssap_read_rsp_item_t item[SLE_SSAP_READ_RSP_MAX_ITEMS];
    size_t n_item;                   /* used only when multi=1 */
    /* single-value mode (multi=0): raw payload */
    uint8_t single_value[SLE_SSAP_READ_RSP_ITEM_MAX_LEN];
    uint16_t single_len;
} sle_ssap_read_rsp_t;

size_t sle_ssap_read_rsp_build(const sle_ssap_read_rsp_t *in, uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_read_rsp_parse(const uint8_t *p, size_t n, sle_ssap_read_rsp_t *out);

/* ==== 0x0A READ_BY_UUID_REQ ================================================
 * FACT: ssap_pkt.h L348-368, SSAP_PduReadByUuidReq_S.
 *   msgCode(1) | ctrl(1: uuidType:1 resv:7) | handleStart(2 LE) |
 *   handleEnd(2 LE) | dataType(1) | uuid[2 or 16]
 */
typedef struct {
    uint8_t uuid_type;                /* 0 = standard, 1 = custom (FACT, L361) */
    uint16_t handle_start;
    uint16_t handle_end;
    uint8_t data_type;
    sle_ssap_uuid_t uuid;
} sle_ssap_read_by_uuid_req_t;

size_t sle_ssap_read_by_uuid_req_build(const sle_ssap_read_by_uuid_req_t *in,
                                       uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_read_by_uuid_req_parse(const uint8_t *p, size_t n,
                                                  sle_ssap_read_by_uuid_req_t *out);

/* ==== 0x0B READ_BY_UUID_RSP ================================================
 * FACT: ssap_pkt.h L370-402, SSAP_PduReadByUuidRsp_S and friends.
 *   msgCode(1) | ctrl(1) | items[]
 * ctrl (LSB-first): fragment:2 multi:1 error:1 resv:4 (see READ_RSP note;
 * bit positions for multi/error here are FACT via
 * SSAP_READ_BY_UUID_RSP_MULTI_CONTROL=4 / _ERR_CONTROL=8, ssap_type.h L89-90).
 * multi=0,error=0: single item {handle(2 LE), value[]} (length implied).
 * multi=1: items are {handle(2 LE), length:15|success:1 (2 LE), value[]}.
 */
#define SLE_SSAP_READ_BY_UUID_RSP_MULTI_CONTROL 4u  /* FACT bit2, ssap_type.h L89 */
#define SLE_SSAP_READ_BY_UUID_RSP_ERR_CONTROL 8u    /* FACT bit3, ssap_type.h L90 */

typedef struct {
    uint16_t handle;
    uint8_t success;
    uint16_t length;
    uint8_t value[SLE_SSAP_READ_RSP_ITEM_MAX_LEN];
} sle_ssap_read_by_uuid_rsp_item_t;

typedef struct {
    uint8_t fragment;
    uint8_t multi;
    uint8_t error;
    sle_ssap_read_by_uuid_rsp_item_t item[SLE_SSAP_READ_RSP_MAX_ITEMS];
    size_t n_item;
} sle_ssap_read_by_uuid_rsp_t;

size_t sle_ssap_read_by_uuid_rsp_build(const sle_ssap_read_by_uuid_rsp_t *in,
                                       uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_read_by_uuid_rsp_parse(const uint8_t *p, size_t n,
                                                  sle_ssap_read_by_uuid_rsp_t *out);

/* ==== 0x0C WRITE_CMD / 0x0D WRITE_REQ ======================================
 * FACT: ssap_pkt.h L404-459, SSAP_PduWriteCmd_S / SSAP_PduWriteReq_S and
 * their *Item_S.
 *   msgCode(1) | ctrl(1) | items[]  (single mode: handle(2 LE) type(1) value[])
 * ctrl (LSB-first) WRITE_CMD: fragment:2 multi:1 oper:2 recv:3 (FACT for
 * fragment/oper via SSAP_CTRL_FRAG_MASK / _WRITE_OPER_SHIFT+MASK; multi bit
 * position INFERENCE from declaration order).
 * ctrl (LSB-first) WRITE_REQ: fragment:2 multi:1 oper:2 verify:1 resv:2
 * (same FACT/INFERENCE split; verify=1 means "server must echo the
 * original value back in WRITE_RSP", FACT ssap_pkt.h L448).
 * multi=1 mode uses SSAP_PduWriteMultiItem_S: handle(2 LE) subItemCount(1)
 * then subItemCount * {type(1) len(2 LE) value[len]} (FACT, ssap_pkt.h
 * L461-471).
 */
typedef struct {
    uint16_t handle;
    uint8_t type;
    const uint8_t *value;
    uint16_t value_len;
} sle_ssap_write_item_t;

typedef struct {
    uint8_t fragment;
    uint8_t multi;                    /* 0 = single item below, 1 = not supported by this API */
    uint8_t oper;                     /* SLE_SSAP_WRITE_* */
    uint8_t recv;                     /* WRITE_CMD only, 3 reserved bits, kept for round-trip */
    uint8_t verify;                   /* WRITE_REQ only */
    sle_ssap_write_item_t item;
} sle_ssap_write_t;

size_t sle_ssap_write_build(uint8_t msg_code, const sle_ssap_write_t *in,
                            uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_write_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                       sle_ssap_write_t *out);

/* ==== 0x0E WRITE_RSP ========================================================
 * FACT: ssap_pkt.h L473-508, SSAP_PduWriteRsp_S and friends.
 *   msgCode(1) | ctrl(1) | items[]
 * ctrl (LSB-first): fragment:2 result:2 resv:4 (FACT fragment bits; result
 * bit position INFERENCE from declaration order, values FACT: 0 success /
 * 1 part / 2 cancel, SSAP_CTRL_WRITE_SUCCESS/PART/CANCEL ssap_type.h
 * L171-173).
 * Two payload shapes exist and are disambiguated only by what the client
 * knows it asked for (verify flag on the original WRITE_REQ):
 *   - verify echo: {handle(2 LE) type(1) value[]}  (SSAP_PduWriteRspItem_S)
 *   - error report: {errorNum(1), errorNum * {handle(2 LE) errorCode(1)}}
 *     (SSAP_PduWriteRspErrorInfo_S/_Item_S)
 * This API exposes the plain "no items" success case (items[] empty, the
 * common WRITE_CMD-less-verify / WRITE_REQ-without-verify response,
 * SSAP_WRITE_RSP_PDU_LEN = SSAP_PDU_BASE_LEN, ssap_type.h L100) plus the
 * error-report shape; the verify-echo shape reuses sle_ssap_write_item_t.
 */
typedef struct {
    uint8_t fragment;
    uint8_t result;                   /* SLE_SSAP_WRITE_RESULT_* */
    uint8_t has_error_list;
    uint8_t error_count;
#define SLE_SSAP_WRITE_RSP_MAX_ERRORS 8
    uint16_t error_handle[SLE_SSAP_WRITE_RSP_MAX_ERRORS];
    uint8_t error_code[SLE_SSAP_WRITE_RSP_MAX_ERRORS];
    uint8_t has_echo;
    sle_ssap_write_item_t echo;
} sle_ssap_write_rsp_t;

size_t sle_ssap_write_rsp_build(const sle_ssap_write_rsp_t *in, uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_write_rsp_parse(const uint8_t *p, size_t n, sle_ssap_write_rsp_t *out);

/* ==== 0x0F VALUE_NTF / 0x10 VALUE_IND ======================================
 * FACT: ssap_pkt.h L510-535, SSAP_PduValue_S / SSAP_PduValueItem_S.
 *   msgCode(1) | ctrl(1) | items[]  (each: handle(2 LE) length(2 LE) value[length])
 * ctrl (LSB-first): fragment:2 type:1 resv:5 (FACT fragment bits; type bit
 * position INFERENCE from declaration order; type=0 property / 1 event,
 * FACT values ssap_pkt.h L524).
 */
typedef struct {
    uint16_t handle;
    uint16_t length;
    const uint8_t *value;
} sle_ssap_value_item_t;

typedef struct {
    uint8_t fragment;
    uint8_t is_event;                 /* ctrl.type: 0 property, 1 event */
    sle_ssap_value_item_t item;
} sle_ssap_value_t;

size_t sle_ssap_value_build(uint8_t msg_code, const sle_ssap_value_t *in,
                            uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_value_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                       sle_ssap_value_t *out);

/* ==== 0x11 VALUE_ACK ========================================================
 * FACT: ssap_pkt.h L537-556, SSAP_PduValueAck_S.
 *   msgCode(1) | ctrl(1) | result(1)
 * ctrl (LSB-first): fragment:2 type:1 resv:5 (same split as VALUE_NTF/IND).
 * result: 0 = receive failed, 1 = receive success (FACT, ssap_type.h L66-67,
 * SSAP_ACK_RECV_FAIL/SUCCESS).
 */
#define SLE_SSAP_VALUE_ACK_LEN 3u
typedef struct {
    uint8_t fragment;
    uint8_t is_event;
    uint8_t result;                   /* SLE_SSAP_ACK_* */
} sle_ssap_value_ack_t;
enum { SLE_SSAP_ACK_RECV_FAIL = 0, SLE_SSAP_ACK_RECV_SUCCESS = 1 };

size_t sle_ssap_value_ack_build(const sle_ssap_value_ack_t *in, uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_value_ack_parse(const uint8_t *p, size_t n, sle_ssap_value_ack_t *out);

/* ==== 0x12 CALL_METHOD_CMD / 0x13 CALL_METHOD_REQ ==========================
 * FACT: ssap_pkt.h L558-579, SSAP_PduCallMethod_S.
 *   msgCode(1) | ctrl(1: fragment:2 resv:6) | handle(2 LE) | param[]
 */
#define SLE_SSAP_CALL_METHOD_MAX_PARAM 256
typedef struct {
    uint8_t fragment;
    uint16_t handle;
    uint8_t param[SLE_SSAP_CALL_METHOD_MAX_PARAM];
    uint16_t param_len;
} sle_ssap_call_method_t;

size_t sle_ssap_call_method_build(uint8_t msg_code, const sle_ssap_call_method_t *in,
                                  uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_call_method_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                             sle_ssap_call_method_t *out);

/* ==== 0x14 CALL_METHOD_RSP ==================================================
 * FACT: ssap_pkt.h L581-599, SSAP_PduCallMethodRsp_S.
 *   msgCode(1) | ctrl(1: fragment:2 resv:6) | result[]
 */
#define SLE_SSAP_CALL_METHOD_RSP_MAX_RESULT 256
typedef struct {
    uint8_t fragment;
    uint8_t result[SLE_SSAP_CALL_METHOD_RSP_MAX_RESULT];
    uint16_t result_len;
} sle_ssap_call_method_rsp_t;

size_t sle_ssap_call_method_rsp_build(const sle_ssap_call_method_rsp_t *in,
                                      uint8_t *out, size_t cap);
sle_ssap_status_t sle_ssap_call_method_rsp_parse(const uint8_t *p, size_t n,
                                                 sle_ssap_call_method_rsp_t *out);

/* ---- Fragmentation / reassembly -------------------------------------------
 * Ported (renamed, de-allocated) from ssap_manager.c SSAP_ReassemFragment()/
 * SSAP_ReassemStart()/SSAP_ReassemContinue() (L219-400+) and SSAP_IsFragPkt()
 * (L190-217): only whitelisted opcodes fragment; BEGIN resets the
 * reassembled ctrl byte to SLE_SSAP_FRAG_NONE (and for WRITE_CMD/WRITE_REQ
 * also clears the oper sub-field back to SLE_SSAP_WRITE_INSTANT, FACT
 * ssap_manager.c L291-295); MID/END append payload after the 2-byte header;
 * WRITE_CMD/WRITE_REQ with oper=CANCEL aborts an in-progress reassembly
 * (FACT, ssap_manager.c L371-381); a fragment larger than the caller's
 * declared MTU is dropped (FACT, ssap_manager.c L384-394).
 * The original is heap-backed and grows a buffer; this port instead takes
 * one fixed caller-supplied buffer per link and returns CAPACITY if it is
 * too small, in place of the original's grow-or-drop behaviour.
 */
typedef enum {
    SLE_SSAP_REASSEM_WAIT = 0,        /* fragment buffered, need more */
    SLE_SSAP_REASSEM_COMPLETE,        /* out_len valid, ctx reset */
    SLE_SSAP_REASSEM_DROP,            /* malformed/out-of-sequence, ctx reset */
    SLE_SSAP_REASSEM_CANCEL,          /* write-cancel received, ctx reset, no PDU to deliver */
} sle_ssap_reassem_result_t;

typedef struct {
    uint8_t *buf;          /* caller-owned scratch buffer, holds the full PDU header included */
    size_t cap;
    size_t len;             /* bytes currently in buf; 0 when idle */
    uint8_t op;              /* opcode being reassembled */
    uint8_t active;
    uint32_t mtu;            /* per-fragment size limit; 0 = no limit */
} sle_ssap_reassem_ctx_t;

void sle_ssap_reassem_init(sle_ssap_reassem_ctx_t *ctx, uint8_t *buf, size_t cap, uint32_t mtu);
void sle_ssap_reassem_reset(sle_ssap_reassem_ctx_t *ctx);
/* Feeds one received PDU (header + payload). On COMPLETE, ctx->buf[0..*out_len)
 * holds the reassembled PDU with ctrl's fragment bits set to
 * SLE_SSAP_FRAG_NONE, ready for the opcode-specific parser above. */
sle_ssap_reassem_result_t sle_ssap_reassem_feed(sle_ssap_reassem_ctx_t *ctx,
                                                const uint8_t *pdu, size_t pdu_len,
                                                size_t *out_len);

/* ---- Fragmentation (sender side) -------------------------------------------
 * Splits `payload` (the PDU's post-header bytes) into <= mtu-sized frames,
 * each carrying the 2-byte header with ctrl's low 2 bits set to BEGIN/MID/
 * END, or NO_FRAG if it fits in one frame untouched. `ctrl_base` supplies
 * every other ctrl bit (already shifted into position by the caller's
 * opcode-specific builder); its low 2 bits are overwritten. */
size_t sle_ssap_frag_count(size_t payload_len, size_t mtu);
sle_ssap_status_t sle_ssap_frag_build(uint8_t msg_code, uint8_t ctrl_base,
                                      const uint8_t *payload, size_t payload_len,
                                      size_t mtu, size_t frag_index,
                                      uint8_t *out, size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* SLE_SSAP_H */
