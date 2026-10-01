/* sle_ssap.c - see sle_ssap.h. */
#include "sle_ssap.h"

#include <string.h>

/* ---- little-endian byte helpers ----------------------------------------- */
static void put_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static uint16_t get_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* ---- UUIDs ---------------------------------------------------------------
 * Vendor base 37BEA880-FC70-11EA-B720-00000000xxxx, bytes in the natural
 * left-to-right string order (FACT of the string; see sle_ssap.h for the
 * byte-order discussion at offset 14..15). */
const uint8_t sle_ssap_vendor_base_uuid[SLE_SSAP_UUID128_LEN] = {
    0x37, 0xBE, 0xA8, 0x80, 0xFC, 0x70, 0x11, 0xEA,
    0xB7, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

void sle_ssap_uuid16(uint16_t std, sle_ssap_uuid_t *out)
{
    memset(out, 0, sizeof(*out));
    out->len = SLE_SSAP_UUID16_LEN;
    put_u16le(out->bytes, std); /* 16-bit standard UUID is little-endian on
                                    the wire like any other SSAP scalar field
                                    (FACT: SSAP_FIND_PRIMARY_SERVICE_STD_LEN
                                    et al. just append SSAP_UUID16_LEN, and
                                    every other 2-byte SSAP field in
                                    ssap_pkt.h is little-endian). */
}

void sle_ssap_uuid128(const uint8_t base[SLE_SSAP_UUID128_LEN], uint16_t std,
                      sle_ssap_uuid_t *out)
{
    out->len = SLE_SSAP_UUID128_LEN;
    memcpy(out->bytes, base, SLE_SSAP_UUID128_LEN);
#if SLE_SSAP_UUID_STD_BE
    out->bytes[SLE_SSAP_UUID_STD_OFFSET] = (uint8_t)(std >> 8);
    out->bytes[SLE_SSAP_UUID_STD_OFFSET + 1] = (uint8_t)(std & 0xFF);
#else
    out->bytes[SLE_SSAP_UUID_STD_OFFSET] = (uint8_t)(std & 0xFF);
    out->bytes[SLE_SSAP_UUID_STD_OFFSET + 1] = (uint8_t)(std >> 8);
#endif
}

void sle_ssap_uuid128_vendor(uint16_t std, sle_ssap_uuid_t *out)
{
    sle_ssap_uuid128(sle_ssap_vendor_base_uuid, std, out);
}

uint16_t sle_ssap_uuid128_std_part(const sle_ssap_uuid_t *u)
{
    if (u->len == SLE_SSAP_UUID16_LEN) return get_u16le(u->bytes);
#if SLE_SSAP_UUID_STD_BE
    return (uint16_t)(((uint16_t)u->bytes[SLE_SSAP_UUID_STD_OFFSET] << 8) |
                       u->bytes[SLE_SSAP_UUID_STD_OFFSET + 1]);
#else
    return (uint16_t)(((uint16_t)u->bytes[SLE_SSAP_UUID_STD_OFFSET + 1] << 8) |
                       u->bytes[SLE_SSAP_UUID_STD_OFFSET]);
#endif
}

int sle_ssap_uuid_equal(const sle_ssap_uuid_t *a, const sle_ssap_uuid_t *b)
{
    return a->len == b->len && memcmp(a->bytes, b->bytes, a->len) == 0;
}

/* ---- header / fragment whitelist ----------------------------------------- */
int sle_ssap_opcode_is_frag_capable(uint8_t msg_code)
{
    /* FACT: ssap_manager.c SSAP_IsFragPkt() L198-212 switch, ported verbatim. */
    switch (msg_code) {
    case SLE_SSAP_FIND_STRUCTURE_RSP:
    case SLE_SSAP_FIND_STRUCTURE_BY_UUID_RSP:
    case SLE_SSAP_READ_REQ:
    case SLE_SSAP_READ_RSP:
    case SLE_SSAP_READ_BY_UUID_RSP:
    case SLE_SSAP_WRITE_CMD:
    case SLE_SSAP_WRITE_REQ:
    case SLE_SSAP_WRITE_RSP:
    case SLE_SSAP_VALUE_NTF:
    case SLE_SSAP_VALUE_IND:
    case SLE_SSAP_VALUE_ACK:
    case SLE_SSAP_CALL_METHOD_CMD:
    case SLE_SSAP_CALL_METHOD_REQ:
    case SLE_SSAP_CALL_METHOD_RSP:
        return 1;
    default:
        return 0;
    }
}

int sle_ssap_is_frag_pkt(const uint8_t *pdu, size_t len)
{
    if (pdu == NULL || len < SLE_SSAP_HEADER_LEN) return 0;
    if (!sle_ssap_opcode_is_frag_capable(pdu[0])) return 0;
    return (pdu[1] & SLE_SSAP_CTRL_FRAG_MASK) != SLE_SSAP_FRAG_NONE;
}

/* ==== 0x01 ERROR_RSP ======================================================= */
size_t sle_ssap_error_rsp_build(const sle_ssap_error_rsp_t *in, uint8_t *out, size_t cap)
{
    if (cap < SLE_SSAP_ERROR_RSP_LEN) return 0;
    out[0] = SLE_SSAP_ERROR_RSP;
    out[1] = 0; /* ctrl reserved, FACT ssap_pkt.h L193 */
    out[2] = in->req_msg_code;
    put_u16le(out + 3, in->err_handle);
    out[5] = in->error_code;
    return SLE_SSAP_ERROR_RSP_LEN;
}

sle_ssap_status_t sle_ssap_error_rsp_parse(const uint8_t *p, size_t n, sle_ssap_error_rsp_t *out)
{
    if (n < SLE_SSAP_ERROR_RSP_LEN) return SLE_SSAP_TRUNCATED;
    if (p[0] != SLE_SSAP_ERROR_RSP) return SLE_SSAP_BAD_OPCODE;
    out->req_msg_code = p[2];
    out->err_handle = get_u16le(p + 3);
    out->error_code = p[5];
    return n == SLE_SSAP_ERROR_RSP_LEN ? SLE_SSAP_OK : SLE_SSAP_TRAILING;
}

/* ==== 0x02/0x03 EXCHANGE_INFO_REQ/RSP ====================================== */
size_t sle_ssap_exchange_info_build(uint8_t msg_code, const sle_ssap_exchange_info_t *in,
                                    uint8_t *out, size_t cap)
{
    if (msg_code != SLE_SSAP_EXCHANGE_INFO_REQ && msg_code != SLE_SSAP_EXCHANGE_INFO_RSP)
        return 0;
    if (cap < SLE_SSAP_EXCHANGE_INFO_LEN) return 0;
    out[0] = msg_code;
    uint8_t ctrl = (uint8_t)((in->mtu_present & 1u) |
                             ((in->version_present & 1u) << 1) |
                             ((in->ext_msg_ctrl & 1u) << 2) |
                             ((in->reliable & 1u) << 3) |
                             ((in->fragment_capable & 1u) << 4) |
                             ((in->multi_processing & 1u) << 5));
    out[1] = ctrl;
    put_u16le(out + 2, in->mtu);
    put_u16le(out + 4, in->version);
    return SLE_SSAP_EXCHANGE_INFO_LEN;
}

sle_ssap_status_t sle_ssap_exchange_info_parse(const uint8_t *p, size_t n,
                                               sle_ssap_exchange_info_t *out)
{
    if (n < SLE_SSAP_EXCHANGE_INFO_LEN) return SLE_SSAP_TRUNCATED;
    if (p[0] != SLE_SSAP_EXCHANGE_INFO_REQ && p[0] != SLE_SSAP_EXCHANGE_INFO_RSP)
        return SLE_SSAP_BAD_OPCODE;
    uint8_t ctrl = p[1];
    out->mtu_present = ctrl & 1u;
    out->version_present = (ctrl >> 1) & 1u;
    out->ext_msg_ctrl = (ctrl >> 2) & 1u;
    out->reliable = (ctrl >> 3) & 1u;
    out->fragment_capable = (ctrl >> 4) & 1u;
    out->multi_processing = (ctrl >> 5) & 1u;
    out->mtu = get_u16le(p + 2);
    out->version = get_u16le(p + 4);
    return n == SLE_SSAP_EXCHANGE_INFO_LEN ? SLE_SSAP_OK : SLE_SSAP_TRAILING;
}

/* ==== 0x04/0x06 FIND_STRUCTURE_REQ / FIND_STRUCTURE_BY_UUID_REQ =========== */
size_t sle_ssap_find_structure_req_build(uint8_t msg_code,
                                         const sle_ssap_find_structure_req_t *in,
                                         uint8_t *out, size_t cap)
{
    if (msg_code != SLE_SSAP_FIND_STRUCTURE_REQ && msg_code != SLE_SSAP_FIND_STRUCTURE_BY_UUID_REQ)
        return 0;
    size_t uuid_len = 0;
    int with_uuid = (msg_code == SLE_SSAP_FIND_STRUCTURE_BY_UUID_REQ);
    if (with_uuid) {
        uuid_len = in->item_type == SLE_SSAP_ITEM_TYPE_CUSTOM ? SLE_SSAP_UUID128_LEN
                                                               : SLE_SSAP_UUID16_LEN;
    }
    size_t total = 6 + uuid_len;
    if (cap < total) return 0;
    out[0] = msg_code;
    out[1] = (uint8_t)(((uint8_t)in->find_type & 0x07u) |
                       (((uint8_t)in->item_type & 0x03u) << 3) |
                       ((in->rsp_mode & 1u) << 5));
    put_u16le(out + 2, in->start_handle);
    put_u16le(out + 4, in->end_handle);
    if (with_uuid) memcpy(out + 6, in->uuid.bytes, uuid_len);
    return total;
}

sle_ssap_status_t sle_ssap_find_structure_req_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                                    sle_ssap_find_structure_req_t *out)
{
    if (msg_code != SLE_SSAP_FIND_STRUCTURE_REQ && msg_code != SLE_SSAP_FIND_STRUCTURE_BY_UUID_REQ)
        return SLE_SSAP_BAD_OPCODE;
    if (n < 6) return SLE_SSAP_TRUNCATED;
    if (p[0] != msg_code) return SLE_SSAP_BAD_OPCODE;
    memset(out, 0, sizeof(*out));
    uint8_t ctrl = p[1];
    out->find_type = (sle_ssap_find_type_t)(ctrl & 0x07u);
    out->item_type = (sle_ssap_item_type_t)((ctrl >> 3) & 0x03u);
    out->rsp_mode = (ctrl >> 5) & 1u;
    out->start_handle = get_u16le(p + 2);
    out->end_handle = get_u16le(p + 4);
    if (msg_code == SLE_SSAP_FIND_STRUCTURE_REQ) {
        return n == 6 ? SLE_SSAP_OK : SLE_SSAP_TRAILING;
    }
    size_t uuid_len = out->item_type == SLE_SSAP_ITEM_TYPE_CUSTOM ? SLE_SSAP_UUID128_LEN
                                                                   : SLE_SSAP_UUID16_LEN;
    if (n < 6 + uuid_len) return SLE_SSAP_TRUNCATED;
    out->uuid.len = (uint8_t)uuid_len;
    memcpy(out->uuid.bytes, p + 6, uuid_len);
    return n == 6 + uuid_len ? SLE_SSAP_OK : SLE_SSAP_TRAILING;
}

/* ==== 0x05/0x07 FIND_STRUCTURE_RSP / FIND_STRUCTURE_BY_UUID_RSP =========== */
size_t sle_ssap_find_structure_rsp_build(uint8_t msg_code,
                                         const sle_ssap_find_structure_rsp_t *in,
                                         uint8_t *out, size_t cap)
{
    if (msg_code != SLE_SSAP_FIND_STRUCTURE_RSP && msg_code != SLE_SSAP_FIND_STRUCTURE_BY_UUID_RSP)
        return 0;
    if (cap < SLE_SSAP_HEADER_LEN + in->data_len) return 0;
    out[0] = msg_code;
    out[1] = (uint8_t)((in->fragment & 0x03u) | (((uint8_t)in->item_type & 0x03u) << 2));
    if (in->data_len > 0) memcpy(out + 2, in->data, in->data_len);
    return SLE_SSAP_HEADER_LEN + in->data_len;
}

sle_ssap_status_t sle_ssap_find_structure_rsp_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                                    sle_ssap_find_structure_rsp_t *out)
{
    if (msg_code != SLE_SSAP_FIND_STRUCTURE_RSP && msg_code != SLE_SSAP_FIND_STRUCTURE_BY_UUID_RSP)
        return SLE_SSAP_BAD_OPCODE;
    if (n < SLE_SSAP_HEADER_LEN) return SLE_SSAP_TRUNCATED;
    if (p[0] != msg_code) return SLE_SSAP_BAD_OPCODE;
    out->fragment = p[1] & 0x03u;
    out->item_type = (sle_ssap_item_type_t)((p[1] >> 2) & 0x03u);
    out->data = p + SLE_SSAP_HEADER_LEN;
    out->data_len = n - SLE_SSAP_HEADER_LEN;
    return SLE_SSAP_OK;
}

/* find-structure item (0x05 payload record) */
size_t sle_ssap_find_structure_item_build(const sle_ssap_find_structure_item_t *in,
                                          int std_uuid, uint8_t *out, size_t cap)
{
    size_t uuid_len = std_uuid ? SLE_SSAP_UUID16_LEN : SLE_SSAP_UUID128_LEN;
    size_t total = 2 + 1 + 1 + uuid_len + 4;
    if (cap < total) return 0;
    size_t i = 0;
    put_u16le(out + i, in->handle); i += 2;
    out[i++] = in->item_type;
    out[i++] = in->descriptor_count;
    memcpy(out + i, in->uuid.bytes, uuid_len); i += uuid_len;
    put_u32le(out + i, in->operation); i += 4;
    return i;
}

sle_ssap_status_t sle_ssap_find_structure_item_parse(const uint8_t *p, size_t n, int std_uuid,
                                                     sle_ssap_find_structure_item_t *out,
                                                     size_t *consumed)
{
    size_t uuid_len = std_uuid ? SLE_SSAP_UUID16_LEN : SLE_SSAP_UUID128_LEN;
    size_t total = 2 + 1 + 1 + uuid_len + 4;
    if (n < total) return SLE_SSAP_TRUNCATED;
    size_t i = 0;
    out->handle = get_u16le(p + i); i += 2;
    out->item_type = p[i++];
    out->descriptor_count = p[i++];
    out->uuid.len = (uint8_t)uuid_len;
    memcpy(out->uuid.bytes, p + i, uuid_len); i += uuid_len;
    out->operation = get_u32le(p + i); i += 4;
    if (consumed) *consumed = i;
    return SLE_SSAP_OK;
}

/* find-property item (0x07 payload record) */
size_t sle_ssap_find_property_item_build(const sle_ssap_find_property_item_t *in,
                                         int std_uuid, uint8_t *out, size_t cap)
{
    size_t uuid_len = std_uuid ? SLE_SSAP_UUID16_LEN : SLE_SSAP_UUID128_LEN;
    size_t total = 2 + uuid_len + 4 + 1;
    if (cap < total) return 0;
    size_t i = 0;
    put_u16le(out + i, in->handle); i += 2;
    memcpy(out + i, in->uuid.bytes, uuid_len); i += uuid_len;
    put_u32le(out + i, in->operation); i += 4;
    out[i++] = in->descriptor_count;
    return i;
}

sle_ssap_status_t sle_ssap_find_property_item_parse(const uint8_t *p, size_t n, int std_uuid,
                                                    sle_ssap_find_property_item_t *out,
                                                    size_t *consumed)
{
    size_t uuid_len = std_uuid ? SLE_SSAP_UUID16_LEN : SLE_SSAP_UUID128_LEN;
    size_t total = 2 + uuid_len + 4 + 1;
    if (n < total) return SLE_SSAP_TRUNCATED;
    size_t i = 0;
    out->handle = get_u16le(p + i); i += 2;
    out->uuid.len = (uint8_t)uuid_len;
    memcpy(out->uuid.bytes, p + i, uuid_len); i += uuid_len;
    out->operation = get_u32le(p + i); i += 4;
    out->descriptor_count = p[i++];
    if (consumed) *consumed = i;
    return SLE_SSAP_OK;
}

/* ==== 0x08 READ_REQ ========================================================= */
size_t sle_ssap_read_req_build(const sle_ssap_read_req_t *in, uint8_t *out, size_t cap)
{
    size_t total = SLE_SSAP_HEADER_LEN + in->n_item * 3;
    if (cap < total) return 0;
    if (in->n_item > SLE_SSAP_READ_REQ_MAX_ITEMS) return 0;
    out[0] = SLE_SSAP_READ_REQ;
    out[1] = (uint8_t)(in->fragment & 0x03u);
    size_t i = SLE_SSAP_HEADER_LEN;
    for (size_t k = 0; k < in->n_item; k++) {
        put_u16le(out + i, in->item[k].handle); i += 2;
        out[i++] = in->item[k].type;
    }
    return i;
}

sle_ssap_status_t sle_ssap_read_req_parse(const uint8_t *p, size_t n, sle_ssap_read_req_t *out)
{
    if (n < SLE_SSAP_HEADER_LEN) return SLE_SSAP_TRUNCATED;
    if (p[0] != SLE_SSAP_READ_REQ) return SLE_SSAP_BAD_OPCODE;
    size_t rest = n - SLE_SSAP_HEADER_LEN;
    if (rest % 3 != 0) return SLE_SSAP_BAD_LENGTH;
    size_t count = rest / 3;
    if (count > SLE_SSAP_READ_REQ_MAX_ITEMS) return SLE_SSAP_CAPACITY;
    out->fragment = p[1] & 0x03u;
    out->n_item = count;
    size_t i = SLE_SSAP_HEADER_LEN;
    for (size_t k = 0; k < count; k++) {
        out->item[k].handle = get_u16le(p + i); i += 2;
        out->item[k].type = p[i++];
    }
    return SLE_SSAP_OK;
}

/* ==== 0x09 READ_RSP ========================================================= */
size_t sle_ssap_read_rsp_build(const sle_ssap_read_rsp_t *in, uint8_t *out, size_t cap)
{
    out[0] = SLE_SSAP_READ_RSP;
    uint8_t ctrl = (uint8_t)((in->fragment & 0x03u) | ((in->multi & 1u) << 2) |
                             ((in->error & 1u) << 3));
    size_t i = SLE_SSAP_HEADER_LEN;
    if (!in->multi) {
        if (cap < i + in->single_len) return 0;
        if (i + in->single_len < i) return 0;
        memcpy(out + i, in->single_value, in->single_len);
        i += in->single_len;
    } else {
        for (size_t k = 0; k < in->n_item; k++) {
            if (cap < i + 2 + in->item[k].length) return 0;
            uint16_t raw = (uint16_t)((in->item[k].length & 0x7FFFu) |
                                      ((in->item[k].success & 1u) << 15));
            put_u16le(out + i, raw); i += 2;
            memcpy(out + i, in->item[k].value, in->item[k].length);
            i += in->item[k].length;
        }
    }
    if (cap < SLE_SSAP_HEADER_LEN) return 0;
    out[1] = ctrl;
    return i;
}

sle_ssap_status_t sle_ssap_read_rsp_parse(const uint8_t *p, size_t n, sle_ssap_read_rsp_t *out)
{
    if (n < SLE_SSAP_HEADER_LEN) return SLE_SSAP_TRUNCATED;
    if (p[0] != SLE_SSAP_READ_RSP) return SLE_SSAP_BAD_OPCODE;
    memset(out, 0, sizeof(*out));
    uint8_t ctrl = p[1];
    out->fragment = ctrl & 0x03u;
    out->multi = (ctrl >> 2) & 1u;
    out->error = (ctrl >> 3) & 1u;
    size_t i = SLE_SSAP_HEADER_LEN;
    if (!out->multi) {
        size_t len = n - i;
        if (len > SLE_SSAP_READ_RSP_ITEM_MAX_LEN) return SLE_SSAP_CAPACITY;
        memcpy(out->single_value, p + i, len);
        out->single_len = (uint16_t)len;
        return SLE_SSAP_OK;
    }
    while (i < n) {
        if (i + 2 > n) return SLE_SSAP_TRUNCATED;
        uint16_t raw = get_u16le(p + i); i += 2;
        uint16_t length = raw & 0x7FFFu;
        uint8_t success = (uint8_t)((raw >> 15) & 1u);
        if (i + length > n) return SLE_SSAP_TRUNCATED;
        if (out->n_item >= SLE_SSAP_READ_RSP_MAX_ITEMS) return SLE_SSAP_CAPACITY;
        if (length > SLE_SSAP_READ_RSP_ITEM_MAX_LEN) return SLE_SSAP_CAPACITY;
        sle_ssap_read_rsp_item_t *it = &out->item[out->n_item++];
        it->success = success;
        it->length = length;
        memcpy(it->value, p + i, length);
        i += length;
    }
    return SLE_SSAP_OK;
}

/* ==== 0x0A READ_BY_UUID_REQ ================================================= */
size_t sle_ssap_read_by_uuid_req_build(const sle_ssap_read_by_uuid_req_t *in,
                                       uint8_t *out, size_t cap)
{
    size_t uuid_len = in->uuid_type ? SLE_SSAP_UUID128_LEN : SLE_SSAP_UUID16_LEN;
    size_t total = 7 + uuid_len;
    if (cap < total) return 0;
    out[0] = SLE_SSAP_READ_BY_UUID_REQ;
    out[1] = (uint8_t)(in->uuid_type & 1u);
    put_u16le(out + 2, in->handle_start);
    put_u16le(out + 4, in->handle_end);
    out[6] = in->data_type;
    memcpy(out + 7, in->uuid.bytes, uuid_len);
    return total;
}

sle_ssap_status_t sle_ssap_read_by_uuid_req_parse(const uint8_t *p, size_t n,
                                                  sle_ssap_read_by_uuid_req_t *out)
{
    if (n < 7) return SLE_SSAP_TRUNCATED;
    if (p[0] != SLE_SSAP_READ_BY_UUID_REQ) return SLE_SSAP_BAD_OPCODE;
    out->uuid_type = p[1] & 1u;
    out->handle_start = get_u16le(p + 2);
    out->handle_end = get_u16le(p + 4);
    out->data_type = p[6];
    size_t uuid_len = out->uuid_type ? SLE_SSAP_UUID128_LEN : SLE_SSAP_UUID16_LEN;
    if (n < 7 + uuid_len) return SLE_SSAP_TRUNCATED;
    out->uuid.len = (uint8_t)uuid_len;
    memcpy(out->uuid.bytes, p + 7, uuid_len);
    return n == 7 + uuid_len ? SLE_SSAP_OK : SLE_SSAP_TRAILING;
}

/* ==== 0x0B READ_BY_UUID_RSP ================================================= */
size_t sle_ssap_read_by_uuid_rsp_build(const sle_ssap_read_by_uuid_rsp_t *in,
                                       uint8_t *out, size_t cap)
{
    out[0] = SLE_SSAP_READ_BY_UUID_RSP;
    uint8_t ctrl = (uint8_t)((in->fragment & 0x03u) | ((in->multi & 1u) << 2) |
                             ((in->error & 1u) << 3));
    size_t i = SLE_SSAP_HEADER_LEN;
    if (!in->multi) {
        if (in->n_item != 1) return 0;
        const sle_ssap_read_by_uuid_rsp_item_t *it = &in->item[0];
        if (cap < i + 2 + it->length) return 0;
        put_u16le(out + i, it->handle); i += 2;
        memcpy(out + i, it->value, it->length); i += it->length;
    } else {
        for (size_t k = 0; k < in->n_item; k++) {
            const sle_ssap_read_by_uuid_rsp_item_t *it = &in->item[k];
            if (cap < i + 4 + it->length) return 0;
            put_u16le(out + i, it->handle); i += 2;
            uint16_t raw = (uint16_t)((it->length & 0x7FFFu) | ((it->success & 1u) << 15));
            put_u16le(out + i, raw); i += 2;
            memcpy(out + i, it->value, it->length); i += it->length;
        }
    }
    if (cap < SLE_SSAP_HEADER_LEN) return 0;
    out[1] = ctrl;
    return i;
}

sle_ssap_status_t sle_ssap_read_by_uuid_rsp_parse(const uint8_t *p, size_t n,
                                                  sle_ssap_read_by_uuid_rsp_t *out)
{
    if (n < SLE_SSAP_HEADER_LEN) return SLE_SSAP_TRUNCATED;
    if (p[0] != SLE_SSAP_READ_BY_UUID_RSP) return SLE_SSAP_BAD_OPCODE;
    memset(out, 0, sizeof(*out));
    uint8_t ctrl = p[1];
    out->fragment = ctrl & 0x03u;
    out->multi = (ctrl >> 2) & 1u;
    out->error = (ctrl >> 3) & 1u;
    size_t i = SLE_SSAP_HEADER_LEN;
    if (!out->multi) {
        if (i + 2 > n) return SLE_SSAP_TRUNCATED;
        sle_ssap_read_by_uuid_rsp_item_t *it = &out->item[0];
        it->handle = get_u16le(p + i); i += 2;
        size_t len = n - i;
        if (len > SLE_SSAP_READ_RSP_ITEM_MAX_LEN) return SLE_SSAP_CAPACITY;
        it->success = 1;
        it->length = (uint16_t)len;
        memcpy(it->value, p + i, len);
        out->n_item = 1;
        return SLE_SSAP_OK;
    }
    while (i < n) {
        if (i + 4 > n) return SLE_SSAP_TRUNCATED;
        if (out->n_item >= SLE_SSAP_READ_RSP_MAX_ITEMS) return SLE_SSAP_CAPACITY;
        sle_ssap_read_by_uuid_rsp_item_t *it = &out->item[out->n_item];
        it->handle = get_u16le(p + i); i += 2;
        uint16_t raw = get_u16le(p + i); i += 2;
        it->length = raw & 0x7FFFu;
        it->success = (uint8_t)((raw >> 15) & 1u);
        if (i + it->length > n) return SLE_SSAP_TRUNCATED;
        if (it->length > SLE_SSAP_READ_RSP_ITEM_MAX_LEN) return SLE_SSAP_CAPACITY;
        memcpy(it->value, p + i, it->length); i += it->length;
        out->n_item++;
    }
    return SLE_SSAP_OK;
}

/* ==== 0x0C WRITE_CMD / 0x0D WRITE_REQ ======================================= */
size_t sle_ssap_write_build(uint8_t msg_code, const sle_ssap_write_t *in,
                            uint8_t *out, size_t cap)
{
    if (msg_code != SLE_SSAP_WRITE_CMD && msg_code != SLE_SSAP_WRITE_REQ) return 0;
    size_t total = SLE_SSAP_HEADER_LEN + 3 + in->item.value_len;
    if (cap < total) return 0;
    out[0] = msg_code;
    uint8_t ctrl = (uint8_t)((in->fragment & 0x03u) | ((in->multi & 1u) << 2) |
                             ((in->oper & 0x03u) << SLE_SSAP_CTRL_WRITE_OPER_SHIFT));
    if (msg_code == SLE_SSAP_WRITE_CMD) {
        ctrl = (uint8_t)(ctrl | ((in->recv & 0x07u) << 5));
    } else {
        ctrl = (uint8_t)(ctrl | ((in->verify & 1u) << 5));
    }
    out[1] = ctrl;
    size_t i = SLE_SSAP_HEADER_LEN;
    put_u16le(out + i, in->item.handle); i += 2;
    out[i++] = in->item.type;
    if (in->item.value_len > 0) memcpy(out + i, in->item.value, in->item.value_len);
    i += in->item.value_len;
    return i;
}

sle_ssap_status_t sle_ssap_write_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                       sle_ssap_write_t *out)
{
    if (msg_code != SLE_SSAP_WRITE_CMD && msg_code != SLE_SSAP_WRITE_REQ) return SLE_SSAP_BAD_OPCODE;
    if (n < SLE_SSAP_HEADER_LEN + 3) return SLE_SSAP_TRUNCATED;
    if (p[0] != msg_code) return SLE_SSAP_BAD_OPCODE;
    memset(out, 0, sizeof(*out));
    uint8_t ctrl = p[1];
    out->fragment = ctrl & 0x03u;
    out->multi = (ctrl >> 2) & 1u;
    out->oper = (ctrl >> SLE_SSAP_CTRL_WRITE_OPER_SHIFT) & 0x03u;
    if (msg_code == SLE_SSAP_WRITE_CMD) {
        out->recv = (ctrl >> 5) & 0x07u;
    } else {
        out->verify = (ctrl >> 5) & 1u;
    }
    if (out->multi) return SLE_SSAP_BAD_LENGTH; /* multi-item write not supported by this API */
    size_t i = SLE_SSAP_HEADER_LEN;
    out->item.handle = get_u16le(p + i); i += 2;
    out->item.type = p[i++];
    out->item.value = p + i;
    out->item.value_len = (uint16_t)(n - i);
    return SLE_SSAP_OK;
}

/* ==== 0x0E WRITE_RSP ========================================================= */
size_t sle_ssap_write_rsp_build(const sle_ssap_write_rsp_t *in, uint8_t *out, size_t cap)
{
    out[0] = SLE_SSAP_WRITE_RSP;
    uint8_t ctrl = (uint8_t)((in->fragment & 0x03u) | ((in->result & 0x03u) << 2));
    size_t i = SLE_SSAP_HEADER_LEN;
    if (in->has_error_list) {
        if (cap < i + 1 + (size_t)in->error_count * 3) return 0;
        out[i++] = in->error_count;
        for (uint8_t k = 0; k < in->error_count; k++) {
            put_u16le(out + i, in->error_handle[k]); i += 2;
            out[i++] = in->error_code[k];
        }
    } else if (in->has_echo) {
        if (cap < i + 3 + in->echo.value_len) return 0;
        put_u16le(out + i, in->echo.handle); i += 2;
        out[i++] = in->echo.type;
        memcpy(out + i, in->echo.value, in->echo.value_len);
        i += in->echo.value_len;
    }
    if (cap < SLE_SSAP_HEADER_LEN) return 0;
    out[1] = ctrl;
    return i;
}

sle_ssap_status_t sle_ssap_write_rsp_parse(const uint8_t *p, size_t n, sle_ssap_write_rsp_t *out)
{
    if (n < SLE_SSAP_HEADER_LEN) return SLE_SSAP_TRUNCATED;
    if (p[0] != SLE_SSAP_WRITE_RSP) return SLE_SSAP_BAD_OPCODE;
    memset(out, 0, sizeof(*out));
    uint8_t ctrl = p[1];
    out->fragment = ctrl & 0x03u;
    out->result = (ctrl >> 2) & 0x03u;
    size_t rest = n - SLE_SSAP_HEADER_LEN;
    if (rest == 0) return SLE_SSAP_OK; /* plain success, no items */
    /* Heuristic disambiguation (the wire format alone cannot tell the two
     * shapes apart without knowing what the client asked for): treat the
     * remainder as an error list when it exactly matches
     * 1 + errorNum*3 for some errorNum <= SLE_SSAP_WRITE_RSP_MAX_ERRORS,
     * otherwise treat it as a verify-echo item. */
    uint8_t maybe_count = p[SLE_SSAP_HEADER_LEN];
    if (rest == (size_t)1 + (size_t)maybe_count * 3 && maybe_count <= SLE_SSAP_WRITE_RSP_MAX_ERRORS) {
        out->has_error_list = 1;
        out->error_count = maybe_count;
        size_t i = SLE_SSAP_HEADER_LEN + 1;
        for (uint8_t k = 0; k < maybe_count; k++) {
            out->error_handle[k] = get_u16le(p + i); i += 2;
            out->error_code[k] = p[i++];
        }
        return SLE_SSAP_OK;
    }
    if (rest < 3) return SLE_SSAP_TRUNCATED;
    out->has_echo = 1;
    size_t i = SLE_SSAP_HEADER_LEN;
    out->echo.handle = get_u16le(p + i); i += 2;
    out->echo.type = p[i++];
    out->echo.value = p + i;
    out->echo.value_len = (uint16_t)(n - i);
    return SLE_SSAP_OK;
}

/* ==== 0x0F VALUE_NTF / 0x10 VALUE_IND ======================================= */
size_t sle_ssap_value_build(uint8_t msg_code, const sle_ssap_value_t *in,
                            uint8_t *out, size_t cap)
{
    if (msg_code != SLE_SSAP_VALUE_NTF && msg_code != SLE_SSAP_VALUE_IND) return 0;
    size_t total = SLE_SSAP_HEADER_LEN + 4 + in->item.length;
    if (cap < total) return 0;
    out[0] = msg_code;
    out[1] = (uint8_t)((in->fragment & 0x03u) | ((in->is_event & 1u) << 2));
    size_t i = SLE_SSAP_HEADER_LEN;
    put_u16le(out + i, in->item.handle); i += 2;
    put_u16le(out + i, in->item.length); i += 2;
    if (in->item.length > 0) memcpy(out + i, in->item.value, in->item.length);
    i += in->item.length;
    return i;
}

sle_ssap_status_t sle_ssap_value_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                       sle_ssap_value_t *out)
{
    if (msg_code != SLE_SSAP_VALUE_NTF && msg_code != SLE_SSAP_VALUE_IND) return SLE_SSAP_BAD_OPCODE;
    if (n < SLE_SSAP_HEADER_LEN + 4) return SLE_SSAP_TRUNCATED;
    if (p[0] != msg_code) return SLE_SSAP_BAD_OPCODE;
    uint8_t ctrl = p[1];
    out->fragment = ctrl & 0x03u;
    out->is_event = (ctrl >> 2) & 1u;
    size_t i = SLE_SSAP_HEADER_LEN;
    out->item.handle = get_u16le(p + i); i += 2;
    out->item.length = get_u16le(p + i); i += 2;
    if (i + out->item.length != n) {
        return i + out->item.length > n ? SLE_SSAP_TRUNCATED : SLE_SSAP_TRAILING;
    }
    out->item.value = p + i;
    return SLE_SSAP_OK;
}

/* ==== 0x11 VALUE_ACK ========================================================= */
size_t sle_ssap_value_ack_build(const sle_ssap_value_ack_t *in, uint8_t *out, size_t cap)
{
    if (cap < SLE_SSAP_VALUE_ACK_LEN) return 0;
    out[0] = SLE_SSAP_VALUE_ACK;
    out[1] = (uint8_t)((in->fragment & 0x03u) | ((in->is_event & 1u) << 2));
    out[2] = in->result;
    return SLE_SSAP_VALUE_ACK_LEN;
}

sle_ssap_status_t sle_ssap_value_ack_parse(const uint8_t *p, size_t n, sle_ssap_value_ack_t *out)
{
    if (n < SLE_SSAP_VALUE_ACK_LEN) return SLE_SSAP_TRUNCATED;
    if (p[0] != SLE_SSAP_VALUE_ACK) return SLE_SSAP_BAD_OPCODE;
    out->fragment = p[1] & 0x03u;
    out->is_event = (p[1] >> 2) & 1u;
    out->result = p[2];
    return n == SLE_SSAP_VALUE_ACK_LEN ? SLE_SSAP_OK : SLE_SSAP_TRAILING;
}

/* ==== 0x12 CALL_METHOD_CMD / 0x13 CALL_METHOD_REQ =========================== */
size_t sle_ssap_call_method_build(uint8_t msg_code, const sle_ssap_call_method_t *in,
                                  uint8_t *out, size_t cap)
{
    if (msg_code != SLE_SSAP_CALL_METHOD_CMD && msg_code != SLE_SSAP_CALL_METHOD_REQ) return 0;
    size_t total = SLE_SSAP_HEADER_LEN + 2 + in->param_len;
    if (cap < total) return 0;
    out[0] = msg_code;
    out[1] = (uint8_t)(in->fragment & 0x03u);
    size_t i = SLE_SSAP_HEADER_LEN;
    put_u16le(out + i, in->handle); i += 2;
    if (in->param_len > 0) memcpy(out + i, in->param, in->param_len);
    i += in->param_len;
    return i;
}

sle_ssap_status_t sle_ssap_call_method_parse(uint8_t msg_code, const uint8_t *p, size_t n,
                                             sle_ssap_call_method_t *out)
{
    if (msg_code != SLE_SSAP_CALL_METHOD_CMD && msg_code != SLE_SSAP_CALL_METHOD_REQ)
        return SLE_SSAP_BAD_OPCODE;
    if (n < SLE_SSAP_HEADER_LEN + 2) return SLE_SSAP_TRUNCATED;
    if (p[0] != msg_code) return SLE_SSAP_BAD_OPCODE;
    memset(out, 0, sizeof(*out));
    out->fragment = p[1] & 0x03u;
    size_t i = SLE_SSAP_HEADER_LEN;
    out->handle = get_u16le(p + i); i += 2;
    size_t len = n - i;
    if (len > SLE_SSAP_CALL_METHOD_MAX_PARAM) return SLE_SSAP_CAPACITY;
    memcpy(out->param, p + i, len);
    out->param_len = (uint16_t)len;
    return SLE_SSAP_OK;
}

/* ==== 0x14 CALL_METHOD_RSP =================================================== */
size_t sle_ssap_call_method_rsp_build(const sle_ssap_call_method_rsp_t *in,
                                      uint8_t *out, size_t cap)
{
    size_t total = SLE_SSAP_HEADER_LEN + in->result_len;
    if (cap < total) return 0;
    out[0] = SLE_SSAP_CALL_METHOD_RSP;
    out[1] = (uint8_t)(in->fragment & 0x03u);
    if (in->result_len > 0) memcpy(out + SLE_SSAP_HEADER_LEN, in->result, in->result_len);
    return total;
}

sle_ssap_status_t sle_ssap_call_method_rsp_parse(const uint8_t *p, size_t n,
                                                 sle_ssap_call_method_rsp_t *out)
{
    if (n < SLE_SSAP_HEADER_LEN) return SLE_SSAP_TRUNCATED;
    if (p[0] != SLE_SSAP_CALL_METHOD_RSP) return SLE_SSAP_BAD_OPCODE;
    memset(out, 0, sizeof(*out));
    out->fragment = p[1] & 0x03u;
    size_t len = n - SLE_SSAP_HEADER_LEN;
    if (len > SLE_SSAP_CALL_METHOD_RSP_MAX_RESULT) return SLE_SSAP_CAPACITY;
    memcpy(out->result, p + SLE_SSAP_HEADER_LEN, len);
    out->result_len = (uint16_t)len;
    return SLE_SSAP_OK;
}

/* ---- Reassembly (receiver side) -------------------------------------------
 * Ports ssap_manager.c SSAP_ReassemFragment/Start/Continue (see header
 * comment for exact line numbers) onto one fixed caller buffer. */
void sle_ssap_reassem_init(sle_ssap_reassem_ctx_t *ctx, uint8_t *buf, size_t cap, uint32_t mtu)
{
    ctx->buf = buf;
    ctx->cap = cap;
    ctx->len = 0;
    ctx->op = 0;
    ctx->active = 0;
    ctx->mtu = mtu;
}

void sle_ssap_reassem_reset(sle_ssap_reassem_ctx_t *ctx)
{
    ctx->len = 0;
    ctx->op = 0;
    ctx->active = 0;
}

sle_ssap_reassem_result_t sle_ssap_reassem_feed(sle_ssap_reassem_ctx_t *ctx,
                                                const uint8_t *pdu, size_t pdu_len,
                                                size_t *out_len)
{
    if (ctx == NULL || pdu == NULL || pdu_len < SLE_SSAP_HEADER_LEN) {
        return SLE_SSAP_REASSEM_DROP;
    }
    uint8_t op = pdu[0];
    uint8_t ctrl = pdu[1];

    /* Write-cancel aborts any in-progress reassembly (FACT, ssap_manager.c
     * L371-381: only WRITE_REQ/WRITE_CMD carry the oper sub-field). */
    if ((op == SLE_SSAP_WRITE_REQ || op == SLE_SSAP_WRITE_CMD) &&
        ((ctrl & SLE_SSAP_CTRL_WRITE_OPER_MASK) ==
         (SLE_SSAP_WRITE_CANCEL << SLE_SSAP_CTRL_WRITE_OPER_SHIFT))) {
        sle_ssap_reassem_reset(ctx);
        return SLE_SSAP_REASSEM_CANCEL;
    }

    uint8_t frag_type = ctrl & SLE_SSAP_CTRL_FRAG_MASK;

    /* Per-fragment MTU guard (FACT, ssap_manager.c L384-394). */
    if (ctx->mtu != 0 && pdu_len > ctx->mtu) {
        sle_ssap_reassem_reset(ctx);
        return SLE_SSAP_REASSEM_DROP;
    }

    if (frag_type == SLE_SSAP_FRAG_BEGIN) {
        /* Drop any unfinished previous reassembly (FACT, ssap_manager.c
         * L284-290). */
        sle_ssap_reassem_reset(ctx);
        if (pdu_len > ctx->cap) return SLE_SSAP_REASSEM_DROP;
        uint8_t new_ctrl = (uint8_t)((ctrl & (uint8_t)~SLE_SSAP_CTRL_FRAG_MASK) | SLE_SSAP_FRAG_NONE);
        if (op == SLE_SSAP_WRITE_REQ || op == SLE_SSAP_WRITE_CMD) {
            new_ctrl = (uint8_t)(new_ctrl & (uint8_t)~SLE_SSAP_CTRL_WRITE_OPER_MASK);
        }
        memcpy(ctx->buf, pdu, pdu_len);
        ctx->buf[1] = new_ctrl;
        ctx->len = pdu_len;
        ctx->op = op;
        ctx->active = 1;
        return SLE_SSAP_REASSEM_WAIT;
    }

    if (frag_type == SLE_SSAP_FRAG_MID || frag_type == SLE_SSAP_FRAG_END) {
        if (!ctx->active || ctx->op != op) {
            sle_ssap_reassem_reset(ctx);
            return SLE_SSAP_REASSEM_DROP;
        }
        size_t append_len = pdu_len - SLE_SSAP_HEADER_LEN;
        if (ctx->len + append_len > ctx->cap) {
            sle_ssap_reassem_reset(ctx);
            return SLE_SSAP_REASSEM_DROP;
        }
        memcpy(ctx->buf + ctx->len, pdu + SLE_SSAP_HEADER_LEN, append_len);
        ctx->len += append_len;
        if (frag_type == SLE_SSAP_FRAG_MID) return SLE_SSAP_REASSEM_WAIT;
        if (out_len) *out_len = ctx->len;
        size_t final_len = ctx->len;
        (void)final_len;
        ctx->active = 0; /* completed; caller must consume ctx->buf before next feed */
        return SLE_SSAP_REASSEM_COMPLETE;
    }

    /* SLE_SSAP_FRAG_NONE reaching this API means the caller mis-routed a
     * complete, non-fragmented PDU here; nothing to reassemble. */
    return SLE_SSAP_REASSEM_DROP;
}

/* ---- Fragmentation (sender side) ------------------------------------------- */
size_t sle_ssap_frag_count(size_t payload_len, size_t mtu)
{
    if (mtu <= SLE_SSAP_HEADER_LEN) return 0;
    size_t per_frag = mtu - SLE_SSAP_HEADER_LEN;
    if (payload_len <= per_frag) return 1;
    size_t n = payload_len / per_frag;
    if (payload_len % per_frag != 0) n++;
    return n;
}

sle_ssap_status_t sle_ssap_frag_build(uint8_t msg_code, uint8_t ctrl_base,
                                      const uint8_t *payload, size_t payload_len,
                                      size_t mtu, size_t frag_index,
                                      uint8_t *out, size_t cap, size_t *out_len)
{
    if (mtu <= SLE_SSAP_HEADER_LEN) return SLE_SSAP_RANGE;
    size_t per_frag = mtu - SLE_SSAP_HEADER_LEN;
    size_t total_frags = sle_ssap_frag_count(payload_len, mtu);
    if (frag_index >= total_frags) return SLE_SSAP_RANGE;

    uint8_t frag_type;
    if (total_frags == 1) {
        frag_type = SLE_SSAP_FRAG_NONE;
    } else if (frag_index == 0) {
        frag_type = SLE_SSAP_FRAG_BEGIN;
    } else if (frag_index == total_frags - 1) {
        frag_type = SLE_SSAP_FRAG_END;
    } else {
        frag_type = SLE_SSAP_FRAG_MID;
    }

    size_t offset = frag_index * per_frag;
    size_t chunk = payload_len - offset;
    if (chunk > per_frag) chunk = per_frag;

    if (cap < SLE_SSAP_HEADER_LEN + chunk) return SLE_SSAP_CAPACITY;
    out[0] = msg_code;
    out[1] = (uint8_t)((ctrl_base & (uint8_t)~SLE_SSAP_CTRL_FRAG_MASK) | frag_type);
    memcpy(out + SLE_SSAP_HEADER_LEN, payload + offset, chunk);
    if (out_len) *out_len = SLE_SSAP_HEADER_LEN + chunk;
    return SLE_SSAP_OK;
}
