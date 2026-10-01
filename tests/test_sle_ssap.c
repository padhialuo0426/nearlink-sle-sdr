/* Unit tests for sle_ssap.c: round-trip every opcode against hand-built byte
 * vectors derived from the field diagrams cited in sle_ssap.h/ssap_pkt.h,
 * negative tests (truncated/trailing/bad length), and a scenario test
 * replaying the official sle_uart sample's client flow (see
 * logs/p2-20260925/official-samples-analysis.md sec.4-5: MTU 520, service
 * UUID 0x2222, property UUID 0x2323, handle=2, WRITE_REQ, VALUE_NTF). */
#include "sle_ssap.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { \
    if (!(cond)) { g_fail++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

/* ==== 0x01 ERROR_RSP =========================================================
 * Vector: 01 00 08 02 00 05
 *   msgCode=0x01 | ctrl=0x00 (reserved) | msgCodeReq=0x08 (READ_REQ) |
 *   errHandle=0x0002 LE | errorCode=0x05 (NO_RESOURCE, ssap_pkt.h L205)
 */
static void test_error_rsp(void)
{
    static const uint8_t vec[] = { 0x01, 0x00, 0x08, 0x02, 0x00, 0x05 };
    sle_ssap_error_rsp_t out;
    CHECK(sle_ssap_error_rsp_parse(vec, sizeof vec, &out) == SLE_SSAP_OK, "error_rsp parse");
    CHECK(out.req_msg_code == SLE_SSAP_READ_REQ, "req_msg_code");
    CHECK(out.err_handle == 2, "err_handle");
    CHECK(out.error_code == SLE_SSAP_ERRCODE_NO_RESOURCE, "error_code");

    uint8_t buf[16];
    size_t n = sle_ssap_error_rsp_build(&out, buf, sizeof buf);
    CHECK(n == sizeof vec && memcmp(buf, vec, n) == 0, "error_rsp rebuild");

    /* negative: truncated (missing errorCode byte) */
    CHECK(sle_ssap_error_rsp_parse(vec, sizeof vec - 1, &out) == SLE_SSAP_TRUNCATED, "truncated");
    /* negative: trailing byte */
    uint8_t trail[7]; memcpy(trail, vec, 6); trail[6] = 0xAA;
    CHECK(sle_ssap_error_rsp_parse(trail, sizeof trail, &out) == SLE_SSAP_TRAILING, "trailing");
    /* negative: wrong opcode */
    uint8_t bad[6]; memcpy(bad, vec, 6); bad[0] = SLE_SSAP_WRITE_RSP;
    CHECK(sle_ssap_error_rsp_parse(bad, sizeof bad, &out) == SLE_SSAP_BAD_OPCODE, "bad opcode");
}

/* ==== 0x02/0x03 EXCHANGE_INFO_REQ/RSP =======================================
 * Vector (REQ, mtu=520=0x0208, version=0x0301=SSAP_VERSION_1_3):
 *   02 03 08 02 01 03
 *   msgCode=0x02 | ctrl=0x03 (mtu=1,version=1, rest 0) | mtu=0x0208 LE |
 *   version=0x0301 LE
 */
static void test_exchange_info(void)
{
    static const uint8_t vec[] = { 0x02, 0x03, 0x08, 0x02, 0x01, 0x03 };
    sle_ssap_exchange_info_t out;
    CHECK(sle_ssap_exchange_info_parse(vec, sizeof vec, &out) == SLE_SSAP_OK, "exchange parse");
    CHECK(out.mtu_present == 1 && out.version_present == 1, "presence bits");
    CHECK(out.ext_msg_ctrl == 0 && out.reliable == 0 && out.fragment_capable == 0 &&
          out.multi_processing == 0, "other bits zero");
    CHECK(out.mtu == 520, "mtu");
    CHECK(out.version == 0x0301, "version");

    uint8_t buf[16];
    size_t n = sle_ssap_exchange_info_build(SLE_SSAP_EXCHANGE_INFO_REQ, &out, buf, sizeof buf);
    CHECK(n == sizeof vec && memcmp(buf, vec, n) == 0, "exchange rebuild");

    /* RSP variant: mtu=208=0x00D0 (as the official server reported) */
    sle_ssap_exchange_info_t rsp = { 1, 1, 0, 0, 0, 0, 208, 0x0301 };
    n = sle_ssap_exchange_info_build(SLE_SSAP_EXCHANGE_INFO_RSP, &rsp, buf, sizeof buf);
    static const uint8_t vec_rsp[] = { 0x03, 0x03, 0xD0, 0x00, 0x01, 0x03 };
    CHECK(n == sizeof vec_rsp && memcmp(buf, vec_rsp, n) == 0, "exchange rsp rebuild");
    CHECK(sle_ssap_exchange_info_build(0x99, &rsp, buf, sizeof buf) == 0, "bad opcode build rejected");

    /* negative: truncated */
    CHECK(sle_ssap_exchange_info_parse(vec, 5, &out) == SLE_SSAP_TRUNCATED, "truncated");
    /* negative: trailing */
    uint8_t trail[7]; memcpy(trail, vec, 6); trail[6] = 0;
    CHECK(sle_ssap_exchange_info_parse(trail, sizeof trail, &out) == SLE_SSAP_TRAILING, "trailing");
}

/* ==== 0x04/0x06 FIND_STRUCTURE_REQ / FIND_STRUCTURE_BY_UUID_REQ =============
 * Vector A (0x04, no uuid): find_type=PROPERTY(0b011), item_type=STD(0b00),
 * rsp_mode=0, start=0x0001, end=0xFFFF:
 *   04 03 01 00 FF FF
 * Vector B (0x06, custom/vendor UUID for service 0x2222):
 *   06 1B 01 00 FF FF <16-byte uuid>
 *   ctrl = findType(0b011=3) | itemType(0b01=1)<<3 | rspMode(0)<<5 = 0x03|0x08=0x0B?
 *   Wait: findType=PROPERTY per the official sample's actual FIND_STRUCTURE_
 *   BY_UUID_REQ is for the *service* (find_type=PRIMARY_SERVICE=0b001) when
 *   discovering the service by its UUID; property discovery (findType=
 *   PROPERTY) then runs within the service's handle range. Use
 *   PRIMARY_SERVICE here to match "find service 0x2222" in the scenario
 *   test below; this unit test independently exercises itemType=CUSTOM.
 */
static void test_find_structure_req(void)
{
    static const uint8_t vecA[] = { 0x04, 0x03, 0x01, 0x00, 0xFF, 0xFF };
    sle_ssap_find_structure_req_t out;
    CHECK(sle_ssap_find_structure_req_parse(SLE_SSAP_FIND_STRUCTURE_REQ, vecA, sizeof vecA, &out)
          == SLE_SSAP_OK, "find_structure_req parse");
    CHECK(out.find_type == SLE_SSAP_FIND_TYPE_PROPERTY, "find_type");
    CHECK(out.item_type == SLE_SSAP_ITEM_TYPE_STANDARD, "item_type");
    CHECK(out.rsp_mode == 0, "rsp_mode");
    CHECK(out.start_handle == 1 && out.end_handle == 0xFFFF, "handles");

    uint8_t buf[32];
    size_t n = sle_ssap_find_structure_req_build(SLE_SSAP_FIND_STRUCTURE_REQ, &out, buf, sizeof buf);
    CHECK(n == sizeof vecA && memcmp(buf, vecA, n) == 0, "find_structure_req rebuild");

    /* 0x06 with a custom 16-byte UUID: ctrl = findType(1=PRIMARY_SERVICE) |
     * itemType(1=CUSTOM)<<3 | rspMode(0)<<5 = 0x01 | 0x08 = 0x09 */
    sle_ssap_find_structure_req_t reqB = { 0 };
    reqB.find_type = SLE_SSAP_FIND_TYPE_PRIMARY_SERVICE;
    reqB.item_type = SLE_SSAP_ITEM_TYPE_CUSTOM;
    reqB.rsp_mode = 0;
    reqB.start_handle = 1;
    reqB.end_handle = 0xFFFF;
    sle_ssap_uuid128_vendor(0x2222, &reqB.uuid);
    n = sle_ssap_find_structure_req_build(SLE_SSAP_FIND_STRUCTURE_BY_UUID_REQ, &reqB, buf, sizeof buf);
    CHECK(n == 6 + 16, "find_structure_by_uuid_req len");
    CHECK(buf[0] == 0x06 && buf[1] == 0x09, "find_structure_by_uuid_req header");
    CHECK(buf[6 + 14] == 0x22 && buf[6 + 15] == 0x22, "uuid std bytes (0x2222 -> 22 22)");

    sle_ssap_find_structure_req_t parsedB;
    CHECK(sle_ssap_find_structure_req_parse(SLE_SSAP_FIND_STRUCTURE_BY_UUID_REQ, buf, n, &parsedB)
          == SLE_SSAP_OK, "find_structure_by_uuid_req parse");
    CHECK(sle_ssap_uuid_equal(&parsedB.uuid, &reqB.uuid), "uuid round-trip");
    CHECK(sle_ssap_uuid128_std_part(&parsedB.uuid) == 0x2222, "std part extraction");

    /* negative: truncated header */
    CHECK(sle_ssap_find_structure_req_parse(SLE_SSAP_FIND_STRUCTURE_REQ, vecA, 5, &out)
          == SLE_SSAP_TRUNCATED, "truncated header");
    /* negative: BY_UUID_REQ missing uuid bytes */
    CHECK(sle_ssap_find_structure_req_parse(SLE_SSAP_FIND_STRUCTURE_BY_UUID_REQ, buf, 6, &out)
          == SLE_SSAP_TRUNCATED, "truncated uuid");
    /* negative: wrong opcode for this parser */
    CHECK(sle_ssap_find_structure_req_parse(SLE_SSAP_WRITE_CMD, vecA, sizeof vecA, &out)
          == SLE_SSAP_BAD_OPCODE, "wrong opcode");
}

/* ==== 0x05/0x07 FIND_STRUCTURE_RSP / FIND_STRUCTURE_BY_UUID_RSP + items ===== */
static void test_find_structure_rsp(void)
{
    /* One property item: handle=2, uuid=std 0x2323, operation=READ|WRITE
     * (0x01|0x04=0x05), descriptor_count=0. */
    sle_ssap_find_property_item_t item = { 0 };
    item.handle = 2;
    sle_ssap_uuid16(0x2323, &item.uuid);
    item.operation = 0x00000005u;
    item.descriptor_count = 0;

    uint8_t item_buf[32];
    size_t item_len = sle_ssap_find_property_item_build(&item, /*std_uuid=*/1, item_buf, sizeof item_buf);
    /* handle(2) uuid(2) operation(4) descCount(1) = 9 */
    CHECK(item_len == 9, "property item len");
    static const uint8_t item_expect[] = {
        0x02, 0x00,             /* handle=2 LE */
        0x23, 0x23,             /* uuid16 = 0x2323 LE */
        0x05, 0x00, 0x00, 0x00, /* operation LE */
        0x00,                   /* descriptor_count */
    };
    CHECK(memcmp(item_buf, item_expect, sizeof item_expect) == 0, "property item bytes");

    sle_ssap_find_property_item_t parsed_item;
    size_t consumed = 0;
    CHECK(sle_ssap_find_property_item_parse(item_buf, item_len, 1, &parsed_item, &consumed)
          == SLE_SSAP_OK, "property item parse");
    CHECK(consumed == item_len, "property item consumed");
    CHECK(parsed_item.handle == 2 && parsed_item.operation == 0x05, "property item fields");

    /* Wrap in the FIND_STRUCTURE_BY_UUID_RSP envelope: ctrl = fragment(NO_FRAG=3) |
     * itemType(STD=0)<<2 = 0x03 */
    sle_ssap_find_structure_rsp_t env = { 0 };
    env.fragment = SLE_SSAP_FRAG_NONE;
    env.item_type = SLE_SSAP_ITEM_TYPE_STANDARD;
    env.data = item_buf;
    env.data_len = item_len;

    uint8_t buf[32];
    size_t n = sle_ssap_find_structure_rsp_build(SLE_SSAP_FIND_STRUCTURE_BY_UUID_RSP, &env, buf, sizeof buf);
    CHECK(n == 2 + item_len, "envelope len");
    CHECK(buf[0] == 0x07 && buf[1] == 0x03, "envelope header");

    sle_ssap_find_structure_rsp_t parsed_env;
    CHECK(sle_ssap_find_structure_rsp_parse(SLE_SSAP_FIND_STRUCTURE_BY_UUID_RSP, buf, n, &parsed_env)
          == SLE_SSAP_OK, "envelope parse");
    CHECK(parsed_env.data_len == item_len && memcmp(parsed_env.data, item_buf, item_len) == 0,
          "envelope payload");

    /* negative: envelope truncated below header */
    CHECK(sle_ssap_find_structure_rsp_parse(SLE_SSAP_FIND_STRUCTURE_BY_UUID_RSP, buf, 1, &parsed_env)
          == SLE_SSAP_TRUNCATED, "envelope truncated");
    /* negative: item truncated */
    CHECK(sle_ssap_find_property_item_parse(item_buf, item_len - 1, 1, &parsed_item, &consumed)
          == SLE_SSAP_TRUNCATED, "item truncated");

    /* structure item (generic 0x05 record): handle=1, item_type=STD_PRIMARY_SERVICE(0),
     * descriptor_count=0, uuid=std 0x2222, operation=BROADCAST(0x20) */
    sle_ssap_find_structure_item_t sitem = { 0 };
    sitem.handle = 1;
    sitem.item_type = 0;
    sitem.descriptor_count = 0;
    sle_ssap_uuid16(0x2222, &sitem.uuid);
    sitem.operation = 0x20;
    uint8_t sbuf[32];
    size_t slen = sle_ssap_find_structure_item_build(&sitem, 1, sbuf, sizeof sbuf);
    /* handle(2) item_type(1) descCount(1) uuid(2) operation(4) = 10 */
    CHECK(slen == 10, "structure item len");
    sle_ssap_find_structure_item_t sparsed;
    CHECK(sle_ssap_find_structure_item_parse(sbuf, slen, 1, &sparsed, &consumed) == SLE_SSAP_OK,
          "structure item parse");
    CHECK(sparsed.handle == 1 && sparsed.operation == 0x20, "structure item fields");
}

/* ==== 0x08 READ_REQ / 0x09 READ_RSP ========================================= */
static void test_read(void)
{
    /* READ_REQ: two items {handle=2,type=0} {handle=3,type=0} */
    sle_ssap_read_req_t req = { 0 };
    req.fragment = SLE_SSAP_FRAG_NONE;
    req.n_item = 2;
    req.item[0].handle = 2; req.item[0].type = 0;
    req.item[1].handle = 3; req.item[1].type = 0;
    uint8_t buf[64];
    size_t n = sle_ssap_read_req_build(&req, buf, sizeof buf);
    static const uint8_t req_expect[] = {
        0x08, 0x03,
        0x02, 0x00, 0x00,
        0x03, 0x00, 0x00,
    };
    CHECK(n == sizeof req_expect && memcmp(buf, req_expect, n) == 0, "read_req bytes");

    sle_ssap_read_req_t parsed_req;
    CHECK(sle_ssap_read_req_parse(buf, n, &parsed_req) == SLE_SSAP_OK, "read_req parse");
    CHECK(parsed_req.n_item == 2 && parsed_req.item[1].handle == 3, "read_req fields");
    /* negative: length not a multiple of item size (3) */
    CHECK(sle_ssap_read_req_parse(buf, n - 1, &parsed_req) == SLE_SSAP_BAD_LENGTH, "read_req bad len");

    /* READ_RSP single value: value = {0xAA,0xBB} */
    sle_ssap_read_rsp_t rsp = { 0 };
    rsp.fragment = SLE_SSAP_FRAG_NONE;
    rsp.multi = 0;
    rsp.single_value[0] = 0xAA; rsp.single_value[1] = 0xBB; rsp.single_len = 2;
    n = sle_ssap_read_rsp_build(&rsp, buf, sizeof buf);
    static const uint8_t rsp_expect[] = { 0x09, 0x03, 0xAA, 0xBB };
    CHECK(n == sizeof rsp_expect && memcmp(buf, rsp_expect, n) == 0, "read_rsp single bytes");
    sle_ssap_read_rsp_t parsed_rsp;
    CHECK(sle_ssap_read_rsp_parse(buf, n, &parsed_rsp) == SLE_SSAP_OK, "read_rsp single parse");
    CHECK(parsed_rsp.single_len == 2 && parsed_rsp.single_value[1] == 0xBB, "read_rsp single fields");

    /* READ_RSP multi value: one item, success=1, length=2, value={0x01,0x02} */
    sle_ssap_read_rsp_t rspm = { 0 };
    rspm.fragment = SLE_SSAP_FRAG_NONE;
    rspm.multi = 1;
    rspm.n_item = 1;
    rspm.item[0].success = 1;
    rspm.item[0].length = 2;
    rspm.item[0].value[0] = 0x01; rspm.item[0].value[1] = 0x02;
    n = sle_ssap_read_rsp_build(&rspm, buf, sizeof buf);
    /* ctrl = fragment(3) | multi(1)<<2 = 0x03|0x04 = 0x07 */
    static const uint8_t rspm_expect[] = { 0x09, 0x07, 0x02, 0x80, 0x01, 0x02 };
    /* raw = length(2) | success(1)<<15 = 0x0002 | 0x8000 = 0x8002 LE -> 02 80 */
    CHECK(n == sizeof rspm_expect && memcmp(buf, rspm_expect, n) == 0, "read_rsp multi bytes");
    sle_ssap_read_rsp_t parsed_rspm;
    CHECK(sle_ssap_read_rsp_parse(buf, n, &parsed_rspm) == SLE_SSAP_OK, "read_rsp multi parse");
    CHECK(parsed_rspm.n_item == 1 && parsed_rspm.item[0].success == 1 &&
          parsed_rspm.item[0].length == 2 && parsed_rspm.item[0].value[1] == 0x02,
          "read_rsp multi fields");

    /* negative: multi item truncated mid-value */
    CHECK(sle_ssap_read_rsp_parse(buf, n - 1, &parsed_rspm) == SLE_SSAP_TRUNCATED,
          "read_rsp multi truncated");
}

/* ==== 0x0A READ_BY_UUID_REQ / 0x0B READ_BY_UUID_RSP ========================= */
static void test_read_by_uuid(void)
{
    sle_ssap_read_by_uuid_req_t req = { 0 };
    req.uuid_type = 0;
    req.handle_start = 1;
    req.handle_end = 0xFFFF;
    req.data_type = 0;
    sle_ssap_uuid16(0x2323, &req.uuid);
    uint8_t buf[64];
    size_t n = sle_ssap_read_by_uuid_req_build(&req, buf, sizeof buf);
    static const uint8_t expect[] = {
        0x0A, 0x00, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x23, 0x23,
    };
    CHECK(n == sizeof expect && memcmp(buf, expect, n) == 0, "read_by_uuid_req bytes");

    sle_ssap_read_by_uuid_req_t parsed;
    CHECK(sle_ssap_read_by_uuid_req_parse(buf, n, &parsed) == SLE_SSAP_OK, "read_by_uuid_req parse");
    CHECK(sle_ssap_uuid128_std_part(&parsed.uuid) == 0x2323, "read_by_uuid_req uuid");
    /* negative: truncated uuid */
    CHECK(sle_ssap_read_by_uuid_req_parse(buf, n - 1, &parsed) == SLE_SSAP_TRUNCATED,
          "read_by_uuid_req truncated");

    /* RSP single: handle=2, value={0x11} */
    sle_ssap_read_by_uuid_rsp_t rsp = { 0 };
    rsp.fragment = SLE_SSAP_FRAG_NONE;
    rsp.multi = 0;
    rsp.n_item = 1;
    rsp.item[0].handle = 2;
    rsp.item[0].success = 1;
    rsp.item[0].length = 1;
    rsp.item[0].value[0] = 0x11;
    n = sle_ssap_read_by_uuid_rsp_build(&rsp, buf, sizeof buf);
    static const uint8_t rsp_expect[] = { 0x0B, 0x03, 0x02, 0x00, 0x11 };
    CHECK(n == sizeof rsp_expect && memcmp(buf, rsp_expect, n) == 0, "read_by_uuid_rsp single bytes");
    sle_ssap_read_by_uuid_rsp_t parsed_rsp;
    CHECK(sle_ssap_read_by_uuid_rsp_parse(buf, n, &parsed_rsp) == SLE_SSAP_OK,
          "read_by_uuid_rsp single parse");
    CHECK(parsed_rsp.n_item == 1 && parsed_rsp.item[0].handle == 2 &&
          parsed_rsp.item[0].value[0] == 0x11, "read_by_uuid_rsp single fields");
}

/* ==== 0x0C WRITE_CMD / 0x0D WRITE_REQ / 0x0E WRITE_RSP ====================== */
static void test_write(void)
{
    /* WRITE_REQ: handle=2, type=0, value={0xDE,0xAD}, oper=INSTANT, verify=0 */
    uint8_t value[] = { 0xDE, 0xAD };
    sle_ssap_write_t w = { 0 };
    w.fragment = SLE_SSAP_FRAG_NONE;
    w.oper = SLE_SSAP_WRITE_INSTANT;
    w.item.handle = 2;
    w.item.type = 0;
    w.item.value = value;
    w.item.value_len = sizeof value;
    uint8_t buf[64];
    size_t n = sle_ssap_write_build(SLE_SSAP_WRITE_REQ, &w, buf, sizeof buf);
    static const uint8_t expect[] = { 0x0D, 0x03, 0x02, 0x00, 0x00, 0xDE, 0xAD };
    CHECK(n == sizeof expect && memcmp(buf, expect, n) == 0, "write_req bytes");

    sle_ssap_write_t parsed;
    CHECK(sle_ssap_write_parse(SLE_SSAP_WRITE_REQ, buf, n, &parsed) == SLE_SSAP_OK, "write_req parse");
    CHECK(parsed.item.handle == 2 && parsed.item.value_len == 2 &&
          parsed.item.value[0] == 0xDE && parsed.item.value[1] == 0xAD, "write_req fields");
    CHECK(parsed.oper == SLE_SSAP_WRITE_INSTANT && parsed.verify == 0, "write_req ctrl");

    /* WRITE_CMD variant, same payload, no verify bit (recv field instead) */
    n = sle_ssap_write_build(SLE_SSAP_WRITE_CMD, &w, buf, sizeof buf);
    CHECK(buf[0] == 0x0C && buf[1] == 0x03, "write_cmd header");

    /* WRITE_REQ with verify=1: ctrl = fragment(3)|oper(0)<<3|verify(1)<<5 = 0x03|0x20=0x23 */
    w.verify = 1;
    n = sle_ssap_write_build(SLE_SSAP_WRITE_REQ, &w, buf, sizeof buf);
    CHECK(buf[1] == 0x23, "write_req verify bit");

    /* negative: truncated below fixed item header */
    CHECK(sle_ssap_write_parse(SLE_SSAP_WRITE_REQ, buf, 4, &parsed) == SLE_SSAP_TRUNCATED,
          "write_req truncated");
    /* negative: wrong opcode */
    CHECK(sle_ssap_write_parse(SLE_SSAP_READ_REQ, buf, n, &parsed) == SLE_SSAP_BAD_OPCODE,
          "write_req wrong opcode");

    /* WRITE_RSP plain success: no items */
    sle_ssap_write_rsp_t wr = { 0 };
    wr.fragment = SLE_SSAP_FRAG_NONE;
    wr.result = SLE_SSAP_WRITE_RESULT_SUCCESS;
    n = sle_ssap_write_rsp_build(&wr, buf, sizeof buf);
    static const uint8_t wr_expect[] = { 0x0E, 0x03 };
    CHECK(n == sizeof wr_expect && memcmp(buf, wr_expect, n) == 0, "write_rsp plain bytes");
    sle_ssap_write_rsp_t parsed_wr;
    CHECK(sle_ssap_write_rsp_parse(buf, n, &parsed_wr) == SLE_SSAP_OK, "write_rsp plain parse");
    CHECK(!parsed_wr.has_echo && !parsed_wr.has_error_list, "write_rsp plain shape");

    /* WRITE_RSP error list: one error {handle=5, code=SLE_SSAP_ERRCODE_INVALID_HANDLE} */
    sle_ssap_write_rsp_t wre = { 0 };
    wre.fragment = SLE_SSAP_FRAG_NONE;
    wre.has_error_list = 1;
    wre.error_count = 1;
    wre.error_handle[0] = 5;
    wre.error_code[0] = SLE_SSAP_ERRCODE_INVALID_HANDLE;
    n = sle_ssap_write_rsp_build(&wre, buf, sizeof buf);
    static const uint8_t wre_expect[] = { 0x0E, 0x03, 0x01, 0x05, 0x00, 0x04 };
    CHECK(n == sizeof wre_expect && memcmp(buf, wre_expect, n) == 0, "write_rsp error bytes");
    sle_ssap_write_rsp_t parsed_wre;
    CHECK(sle_ssap_write_rsp_parse(buf, n, &parsed_wre) == SLE_SSAP_OK, "write_rsp error parse");
    CHECK(parsed_wre.has_error_list && parsed_wre.error_count == 1 &&
          parsed_wre.error_handle[0] == 5 && parsed_wre.error_code[0] == SLE_SSAP_ERRCODE_INVALID_HANDLE,
          "write_rsp error fields");
}

/* ==== 0x0F VALUE_NTF / 0x10 VALUE_IND / 0x11 VALUE_ACK ====================== */
static void test_value(void)
{
    uint8_t data[] = { 0x01, 0x02, 0x03 };
    sle_ssap_value_t v = { 0 };
    v.fragment = SLE_SSAP_FRAG_NONE;
    v.is_event = 0;
    v.item.handle = 2;
    v.item.length = sizeof data;
    v.item.value = data;
    uint8_t buf[64];
    size_t n = sle_ssap_value_build(SLE_SSAP_VALUE_NTF, &v, buf, sizeof buf);
    static const uint8_t expect[] = { 0x0F, 0x03, 0x02, 0x00, 0x03, 0x00, 0x01, 0x02, 0x03 };
    CHECK(n == sizeof expect && memcmp(buf, expect, n) == 0, "value_ntf bytes");

    sle_ssap_value_t parsed;
    CHECK(sle_ssap_value_parse(SLE_SSAP_VALUE_NTF, buf, n, &parsed) == SLE_SSAP_OK, "value_ntf parse");
    CHECK(parsed.item.handle == 2 && parsed.item.length == 3 &&
          memcmp(parsed.item.value, data, 3) == 0, "value_ntf fields");

    /* VALUE_IND, is_event=1: ctrl = fragment(3)|1<<2 = 0x07 */
    n = sle_ssap_value_build(SLE_SSAP_VALUE_IND, &v, buf, sizeof buf);
    CHECK(buf[0] == 0x10, "value_ind opcode");
    v.is_event = 1;
    n = sle_ssap_value_build(SLE_SSAP_VALUE_IND, &v, buf, sizeof buf);
    CHECK(buf[1] == 0x07, "value_ind event ctrl bit");

    /* negative: length field says more than is present */
    uint8_t bad[9]; memcpy(bad, expect, sizeof expect); bad[4] = 0x09; /* length=9 but only 3 bytes follow */
    CHECK(sle_ssap_value_parse(SLE_SSAP_VALUE_NTF, bad, sizeof bad, &parsed) == SLE_SSAP_TRUNCATED,
          "value_ntf bad length");

    /* VALUE_ACK: result=SUCCESS, is_event=0 */
    sle_ssap_value_ack_t ack = { SLE_SSAP_FRAG_NONE, 0, SLE_SSAP_ACK_RECV_SUCCESS };
    n = sle_ssap_value_ack_build(&ack, buf, sizeof buf);
    static const uint8_t ack_expect[] = { 0x11, 0x03, 0x01 };
    CHECK(n == sizeof ack_expect && memcmp(buf, ack_expect, n) == 0, "value_ack bytes");
    sle_ssap_value_ack_t parsed_ack;
    CHECK(sle_ssap_value_ack_parse(buf, n, &parsed_ack) == SLE_SSAP_OK, "value_ack parse");
    CHECK(parsed_ack.result == SLE_SSAP_ACK_RECV_SUCCESS, "value_ack field");
    CHECK(sle_ssap_value_ack_parse(buf, n - 1, &parsed_ack) == SLE_SSAP_TRUNCATED, "value_ack truncated");
}

/* ==== 0x12/0x13 CALL_METHOD_CMD/REQ / 0x14 CALL_METHOD_RSP ================== */
static void test_call_method(void)
{
    uint8_t param[] = { 0x7A, 0x7B };
    sle_ssap_call_method_t cm = { 0 };
    cm.fragment = SLE_SSAP_FRAG_NONE;
    cm.handle = 4;
    memcpy(cm.param, param, sizeof param);
    cm.param_len = sizeof param;
    uint8_t buf[64];
    size_t n = sle_ssap_call_method_build(SLE_SSAP_CALL_METHOD_REQ, &cm, buf, sizeof buf);
    static const uint8_t expect[] = { 0x13, 0x03, 0x04, 0x00, 0x7A, 0x7B };
    CHECK(n == sizeof expect && memcmp(buf, expect, n) == 0, "call_method_req bytes");

    sle_ssap_call_method_t parsed;
    CHECK(sle_ssap_call_method_parse(SLE_SSAP_CALL_METHOD_REQ, buf, n, &parsed) == SLE_SSAP_OK,
          "call_method_req parse");
    CHECK(parsed.handle == 4 && parsed.param_len == 2 && parsed.param[1] == 0x7B,
          "call_method_req fields");

    n = sle_ssap_call_method_build(SLE_SSAP_CALL_METHOD_CMD, &cm, buf, sizeof buf);
    CHECK(buf[0] == 0x12, "call_method_cmd opcode");

    sle_ssap_call_method_rsp_t rsp = { 0 };
    rsp.fragment = SLE_SSAP_FRAG_NONE;
    rsp.result[0] = 0x5A;
    rsp.result_len = 1;
    n = sle_ssap_call_method_rsp_build(&rsp, buf, sizeof buf);
    static const uint8_t rsp_expect[] = { 0x14, 0x03, 0x5A };
    CHECK(n == sizeof rsp_expect && memcmp(buf, rsp_expect, n) == 0, "call_method_rsp bytes");
    sle_ssap_call_method_rsp_t parsed_rsp;
    CHECK(sle_ssap_call_method_rsp_parse(buf, n, &parsed_rsp) == SLE_SSAP_OK, "call_method_rsp parse");
    CHECK(parsed_rsp.result_len == 1 && parsed_rsp.result[0] == 0x5A, "call_method_rsp fields");

    /* negative: truncated below handle */
    CHECK(sle_ssap_call_method_parse(SLE_SSAP_CALL_METHOD_REQ, buf, 3, &parsed) == SLE_SSAP_TRUNCATED,
          "call_method_req truncated");
}

/* ==== Fragmentation / reassembly ============================================
 * Build a 10-byte VALUE_NTF payload split across an mtu of 6 bytes/frame
 * (4 payload bytes per frame after the 2-byte header), reassemble it, and
 * confirm the whitelist + write-cancel + MTU-guard behaviours. */
static void test_fragmentation(void)
{
    uint8_t payload[10];
    for (int i = 0; i < 10; i++) payload[i] = (uint8_t)(0x30 + i);

    size_t mtu = 6;
    size_t nfrag = sle_ssap_frag_count(sizeof payload, mtu);
    CHECK(nfrag == 3, "frag_count"); /* ceil(10/4) = 3 */

    uint8_t reassem_buf[64];
    sle_ssap_reassem_ctx_t ctx;
    sle_ssap_reassem_init(&ctx, reassem_buf, sizeof reassem_buf, mtu);

    uint8_t frag[16];
    size_t frag_len = 0, out_len = 0;
    sle_ssap_reassem_result_t r;

    for (size_t i = 0; i < nfrag; i++) {
        CHECK(sle_ssap_frag_build(SLE_SSAP_VALUE_NTF, 0x00, payload, sizeof payload, mtu, i,
                                  frag, sizeof frag, &frag_len) == SLE_SSAP_OK, "frag_build ok");
        uint8_t expect_type = (i == 0) ? SLE_SSAP_FRAG_BEGIN
                             : (i == nfrag - 1) ? SLE_SSAP_FRAG_END : SLE_SSAP_FRAG_MID;
        CHECK((frag[1] & SLE_SSAP_CTRL_FRAG_MASK) == expect_type, "frag ctrl type");
        r = sle_ssap_reassem_feed(&ctx, frag, frag_len, &out_len);
        if (i < nfrag - 1) {
            CHECK(r == SLE_SSAP_REASSEM_WAIT, "reassem wait");
        } else {
            CHECK(r == SLE_SSAP_REASSEM_COMPLETE, "reassem complete");
        }
    }
    CHECK(out_len == SLE_SSAP_HEADER_LEN + sizeof payload, "reassem total len");
    CHECK((reassem_buf[1] & SLE_SSAP_CTRL_FRAG_MASK) == SLE_SSAP_FRAG_NONE, "reassem ctrl restored");
    CHECK(memcmp(reassem_buf + SLE_SSAP_HEADER_LEN, payload, sizeof payload) == 0, "reassem payload");

    /* whitelist: EXCHANGE_INFO_REQ must never be treated as fragmentable */
    CHECK(!sle_ssap_opcode_is_frag_capable(SLE_SSAP_EXCHANGE_INFO_REQ), "exchange not frag capable");
    CHECK(sle_ssap_opcode_is_frag_capable(SLE_SSAP_VALUE_NTF), "value_ntf frag capable");
    uint8_t not_frag_pkt[2] = { SLE_SSAP_EXCHANGE_INFO_REQ, 0x00 };
    CHECK(!sle_ssap_is_frag_pkt(not_frag_pkt, sizeof not_frag_pkt), "exchange is_frag_pkt false");

    /* MTU guard: a fragment larger than ctx->mtu is dropped, context reset */
    sle_ssap_reassem_init(&ctx, reassem_buf, sizeof reassem_buf, /*mtu=*/4);
    uint8_t oversize[6] = { SLE_SSAP_VALUE_NTF, SLE_SSAP_FRAG_BEGIN, 1, 2, 3, 4 };
    r = sle_ssap_reassem_feed(&ctx, oversize, sizeof oversize, &out_len);
    CHECK(r == SLE_SSAP_REASSEM_DROP, "oversize frag dropped");

    /* write-cancel aborts reassembly */
    sle_ssap_reassem_init(&ctx, reassem_buf, sizeof reassem_buf, 0);
    uint8_t begin[4] = { SLE_SSAP_WRITE_REQ, SLE_SSAP_FRAG_BEGIN, 0xAA, 0xBB };
    r = sle_ssap_reassem_feed(&ctx, begin, sizeof begin, &out_len);
    CHECK(r == SLE_SSAP_REASSEM_WAIT, "write begin waits");
    uint8_t cancel_ctrl = (uint8_t)(SLE_SSAP_FRAG_MID |
                                    (SLE_SSAP_WRITE_CANCEL << SLE_SSAP_CTRL_WRITE_OPER_SHIFT));
    uint8_t cancel[3] = { SLE_SSAP_WRITE_REQ, cancel_ctrl, 0xCC };
    r = sle_ssap_reassem_feed(&ctx, cancel, sizeof cancel, &out_len);
    CHECK(r == SLE_SSAP_REASSEM_CANCEL, "write cancel");
    CHECK(!ctx.active && ctx.len == 0, "ctx reset after cancel");

    /* mid/end without begin -> drop */
    sle_ssap_reassem_init(&ctx, reassem_buf, sizeof reassem_buf, 0);
    uint8_t mid_orphan[4] = { SLE_SSAP_VALUE_NTF, SLE_SSAP_FRAG_MID, 1, 2 };
    r = sle_ssap_reassem_feed(&ctx, mid_orphan, sizeof mid_orphan, &out_len);
    CHECK(r == SLE_SSAP_REASSEM_DROP, "orphan mid dropped");

    /* capacity: buffer too small for the reassembled PDU */
    uint8_t tiny_buf[5];
    sle_ssap_reassem_ctx_t tiny_ctx;
    sle_ssap_reassem_init(&tiny_ctx, tiny_buf, sizeof tiny_buf, 0);
    for (size_t i = 0; i < nfrag; i++) {
        sle_ssap_frag_build(SLE_SSAP_VALUE_NTF, 0x00, payload, sizeof payload, mtu, i,
                            frag, sizeof frag, &frag_len);
        r = sle_ssap_reassem_feed(&tiny_ctx, frag, frag_len, &out_len);
        if (r == SLE_SSAP_REASSEM_DROP) break;
    }
    CHECK(r == SLE_SSAP_REASSEM_DROP, "capacity overflow dropped");
}

/* ==== UUID helpers =========================================================== */
static void test_uuid(void)
{
    sle_ssap_uuid_t u16;
    sle_ssap_uuid16(0x1234, &u16);
    CHECK(u16.len == 2 && u16.bytes[0] == 0x34 && u16.bytes[1] == 0x12, "uuid16 LE");

    sle_ssap_uuid_t u128;
    sle_ssap_uuid128_vendor(0x2323, &u128);
    CHECK(u128.len == 16, "uuid128 len");
    static const uint8_t base_prefix[14] = {
        0x37, 0xBE, 0xA8, 0x80, 0xFC, 0x70, 0x11, 0xEA, 0xB7, 0x20, 0x00, 0x00, 0x00, 0x00,
    };
    CHECK(memcmp(u128.bytes, base_prefix, 14) == 0, "vendor base prefix preserved");
    CHECK(u128.bytes[14] == 0x23 && u128.bytes[15] == 0x23, "std part at offset 14..15");
    CHECK(sle_ssap_uuid128_std_part(&u128) == 0x2323, "std part round trip");

    sle_ssap_uuid_t a, b;
    sle_ssap_uuid16(0x0001, &a);
    sle_ssap_uuid16(0x0001, &b);
    CHECK(sle_ssap_uuid_equal(&a, &b), "uuid_equal true");
    sle_ssap_uuid16(0x0002, &b);
    CHECK(!sle_ssap_uuid_equal(&a, &b), "uuid_equal false");
}

/* ==== Scenario: official sle_uart sample client flow ========================
 * Replays, in order, the four PDUs the review doc's "E310 最小 PDU 清单"
 * lists for an SSAP client against the unmodified WS63 sle_uart server
 * (logs/p2-20260925/official-samples-analysis.md sec.5):
 *   1. EXCHANGE_INFO_REQ, mtu=520
 *   2. FIND_STRUCTURE_BY_UUID_REQ, find_type=PRIMARY_SERVICE, uuid=svc 0x2222
 *   3. WRITE_REQ to handle=2
 *   4. VALUE_NTF from the server on handle=2
 */
static void test_scenario_official_sample(void)
{
    uint8_t buf[64];
    size_t n;

    /* 1. EXCHANGE_INFO_REQ mtu=520 */
    sle_ssap_exchange_info_t exch = { 1, 1, 0, 0, 0, 0, 520, SLE_SSAP_EXCHANGE_INFO_REQ == 0 ? 0 : 0x0301 };
    n = sle_ssap_exchange_info_build(SLE_SSAP_EXCHANGE_INFO_REQ, &exch, buf, sizeof buf);
    CHECK(n == 6, "scenario exchange len");
    sle_ssap_exchange_info_t exch_parsed;
    CHECK(sle_ssap_exchange_info_parse(buf, n, &exch_parsed) == SLE_SSAP_OK, "scenario exchange parse");
    CHECK(exch_parsed.mtu == 520, "scenario exchange mtu");

    /* 2. FIND_STRUCTURE_BY_UUID_REQ for service 0x2222, whole handle range */
    sle_ssap_find_structure_req_t find = { 0 };
    find.find_type = SLE_SSAP_FIND_TYPE_PRIMARY_SERVICE;
    find.item_type = SLE_SSAP_ITEM_TYPE_CUSTOM;
    find.rsp_mode = 0;
    find.start_handle = 1;
    find.end_handle = 0xFFFF;
    sle_ssap_uuid128_vendor(0x2222, &find.uuid);
    n = sle_ssap_find_structure_req_build(SLE_SSAP_FIND_STRUCTURE_BY_UUID_REQ, &find, buf, sizeof buf);
    CHECK(n == 22, "scenario find len");
    sle_ssap_find_structure_req_t find_parsed;
    CHECK(sle_ssap_find_structure_req_parse(SLE_SSAP_FIND_STRUCTURE_BY_UUID_REQ, buf, n, &find_parsed)
          == SLE_SSAP_OK, "scenario find parse");
    CHECK(sle_ssap_uuid128_std_part(&find_parsed.uuid) == 0x2222, "scenario find uuid");

    /* Synthesize the server's FIND_STRUCTURE_BY_UUID_RSP: one property item,
     * handle=2, uuid=std 0x2323 (property), operation=READ|WRITE|NOTIFY. */
    sle_ssap_find_property_item_t prop = { 0 };
    prop.handle = 2;
    sle_ssap_uuid16(0x2323, &prop.uuid);
    prop.operation = 0x01 | 0x04 | 0x08; /* READ | WRITE | NOTIFY */
    prop.descriptor_count = 0;
    uint8_t item_buf[32];
    size_t item_len = sle_ssap_find_property_item_build(&prop, 1, item_buf, sizeof item_buf);
    sle_ssap_find_structure_rsp_t rsp_env = { SLE_SSAP_FRAG_NONE, SLE_SSAP_ITEM_TYPE_STANDARD,
                                              item_buf, item_len };
    uint8_t rsp_buf[64];
    n = sle_ssap_find_structure_rsp_build(SLE_SSAP_FIND_STRUCTURE_BY_UUID_RSP, &rsp_env, rsp_buf,
                                          sizeof rsp_buf);
    sle_ssap_find_structure_rsp_t rsp_parsed;
    CHECK(sle_ssap_find_structure_rsp_parse(SLE_SSAP_FIND_STRUCTURE_BY_UUID_RSP, rsp_buf, n,
                                            &rsp_parsed) == SLE_SSAP_OK, "scenario find rsp parse");
    sle_ssap_find_property_item_t prop_parsed;
    size_t consumed = 0;
    CHECK(sle_ssap_find_property_item_parse(rsp_parsed.data, rsp_parsed.data_len, 1, &prop_parsed,
                                            &consumed) == SLE_SSAP_OK, "scenario prop item parse");
    CHECK(prop_parsed.handle == 2, "scenario resolved handle=2");

    /* 3. WRITE_REQ to handle=2 */
    uint8_t wval[] = { 0x01 };
    sle_ssap_write_t w = { 0 };
    w.fragment = SLE_SSAP_FRAG_NONE;
    w.oper = SLE_SSAP_WRITE_INSTANT;
    w.item.handle = prop_parsed.handle;
    w.item.type = 0;
    w.item.value = wval;
    w.item.value_len = sizeof wval;
    n = sle_ssap_write_build(SLE_SSAP_WRITE_REQ, &w, buf, sizeof buf);
    static const uint8_t write_expect[] = { 0x0D, 0x03, 0x02, 0x00, 0x00, 0x01 };
    CHECK(n == sizeof write_expect && memcmp(buf, write_expect, n) == 0, "scenario write bytes");

    /* 4. VALUE_NTF from server on handle=2 */
    uint8_t nval[] = { 0x99 };
    sle_ssap_value_t ntf = { 0 };
    ntf.fragment = SLE_SSAP_FRAG_NONE;
    ntf.is_event = 0;
    ntf.item.handle = 2;
    ntf.item.length = sizeof nval;
    ntf.item.value = nval;
    n = sle_ssap_value_build(SLE_SSAP_VALUE_NTF, &ntf, buf, sizeof buf);
    static const uint8_t ntf_expect[] = { 0x0F, 0x03, 0x02, 0x00, 0x01, 0x00, 0x99 };
    CHECK(n == sizeof ntf_expect && memcmp(buf, ntf_expect, n) == 0, "scenario ntf bytes");
    sle_ssap_value_t ntf_parsed;
    CHECK(sle_ssap_value_parse(SLE_SSAP_VALUE_NTF, buf, n, &ntf_parsed) == SLE_SSAP_OK,
          "scenario ntf parse");
    CHECK(ntf_parsed.item.handle == 2 && ntf_parsed.item.value[0] == 0x99, "scenario ntf fields");
}

int main(void)
{
    test_error_rsp();
    test_exchange_info();
    test_find_structure_req();
    test_find_structure_rsp();
    test_read();
    test_read_by_uuid();
    test_write();
    test_value();
    test_call_method();
    test_fragmentation();
    test_uuid();
    test_scenario_official_sample();

    if (g_fail == 0) {
        printf("All SSAP tests passed.\n");
        return 0;
    }
    fprintf(stderr, "%d SSAP test failures.\n", g_fail);
    return 1;
}
