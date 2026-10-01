#include "sle_ssap_server.h"
#include "sle_ssap.h"
#include <string.h>

void sle_ssap_server_clear(sle_ssap_server *s) {
  if (s) {
    volatile uint8_t *p = (volatile uint8_t *)s;
    for (size_t i = 0; i < sizeof *s; i++)
      p[i] = 0;
  }
}
int sle_ssap_server_init(sle_ssap_server *s, uint16_t mtu) {
  if (!s)
    return SLE_SSAP_SERVER_ARGUMENT;
  sle_ssap_server_clear(s);
  if (mtu < 23 || mtu > 1024)
    return SLE_SSAP_SERVER_ARGUMENT;
  s->local_mtu = mtu;
  return 0;
}
static void wrap(uint8_t *out, const uint8_t *p, size_t n) {
  out[0] = 10;
  out[1] = 0;
  out[2] = (uint8_t)n;
  out[3] = (uint8_t)(n >> 8);
  memcpy(out + 4, p, n);
}
int sle_ssap_server_rx(sle_ssap_server *s, int encrypted, const uint8_t *in,
                      size_t n, uint8_t *out, size_t cap, size_t *out_len) {
  if (out_len)
    *out_len = 0;
  if (!s || !in || !out || !out_len)
    return SLE_SSAP_SERVER_ARGUMENT;
  if (!encrypted || s->local_mtu < 23)
    return SLE_SSAP_SERVER_STATE;
  if (n < 6 || n > SLE_SSAP_SERVER_SDU_MAX || in[0] != 10 || in[1] ||
      ((size_t)in[2] | (size_t)in[3] << 8) != n - 4)
    return SLE_SSAP_SERVER_FORMAT;
  const uint8_t *p = in + 4;
  size_t pn = n - 4;
  uint8_t reply[SLE_SSAP_SERVER_SDU_MAX];
  size_t rn = 0;
  int action = 0;
  uint16_t mtu = s->mtu;
  const uint8_t *value = NULL;
  size_t vn = 0;
  if (p[0] == SLE_SSAP_EXCHANGE_INFO_REQ) {
    sle_ssap_exchange_info_t x;
    if (s->negotiated)
      return SLE_SSAP_SERVER_STATE;
    if (sle_ssap_exchange_info_parse(p, pn, &x) || !x.mtu_present || x.mtu < 23)
      return SLE_SSAP_SERVER_FORMAT;
    mtu = x.mtu < s->local_mtu ? x.mtu : s->local_mtu;
    sle_ssap_exchange_info_t rsp = {
        .mtu_present = 1, .version_present = 1, .mtu = mtu, .version = 1};
    rn = sle_ssap_exchange_info_build(SLE_SSAP_EXCHANGE_INFO_RSP, &rsp, reply,
                                      sizeof reply);
    action = 1;
  } else {
    if (!s->negotiated)
      return SLE_SSAP_SERVER_STATE;
    if (pn > s->mtu)
      return SLE_SSAP_SERVER_FORMAT;
    if (p[0] == SLE_SSAP_FIND_STRUCTURE_REQ) {
      sle_ssap_find_structure_req_t f;
      if (sle_ssap_find_structure_req_parse(p[0], p, pn, &f))
        return SLE_SSAP_SERVER_FORMAT;
      if (f.find_type != SLE_SSAP_FIND_TYPE_PROPERTY ||
          (f.item_type != SLE_SSAP_ITEM_TYPE_STANDARD &&
           f.item_type != SLE_SSAP_ITEM_TYPE_MIX) ||
          f.rsp_mode || f.start_handle > 2 || f.end_handle < 2)
        return SLE_SSAP_SERVER_UNSUPPORTED;
      /* Exact 12-byte property response from authenticated official server
       * g_runtime-official-default-a: handle2, UUID2323, operation09, descriptor0101.
       */
      static const uint8_t property[] = {5, 3, 2, 0, 0x23, 0x23,
                                         9, 0, 0, 0, 1,    1};
      /* 1.10.108 clients ask MIX (ctrl 0x13). Reply ctrl echoes itemType
       * (0x0b) and wraps the same record in group indicators {count:7,
       * type:1}: STD count 1, then CUS count 0 (ssaps_server_find.c
       * BuildMixPropertyPayload; client ssapc_discovery_service_rsp). */
      static const uint8_t mix[] = {5, 0x0b, 0x01, 2, 0, 0x23, 0x23,
                                    9, 0,    0,    0, 1, 1,    0x80};
      const uint8_t *r = f.item_type == SLE_SSAP_ITEM_TYPE_MIX ? mix : property;
      rn = f.item_type == SLE_SSAP_ITEM_TYPE_MIX ? sizeof mix : sizeof property;
      memcpy(reply, r, rn);
      action = 2;
    } else if (p[0] == SLE_SSAP_WRITE_REQ || p[0] == SLE_SSAP_WRITE_CMD) {
      sle_ssap_write_t w;
      if (!s->discovered)
        return SLE_SSAP_SERVER_STATE;
      if (sle_ssap_write_parse(p[0], p, pn, &w))
        return SLE_SSAP_SERVER_FORMAT;
      if (w.fragment != SLE_SSAP_FRAG_NONE || w.multi ||
          w.oper != SLE_SSAP_WRITE_INSTANT || w.item.handle != 2 ||
          w.item.type || w.item.value_len > SLE_SSAP_SERVER_VALUE_MAX)
        return SLE_SSAP_SERVER_UNSUPPORTED;
      value = w.item.value;
      vn = w.item.value_len;
      if (p[0] == SLE_SSAP_WRITE_REQ) {
        reply[0] = 14;
        reply[1] = 3;
        reply[2] = 2;
        reply[3] = reply[4] = 0;
        memcpy(reply + 5, value, vn);
        rn = 5 + vn;
      }
      action = 3;
    } else
      return SLE_SSAP_SERVER_UNSUPPORTED;
  }
  if ((rn && cap < rn + 4) || rn > mtu)
    return SLE_SSAP_SERVER_BUFFER;
  if (action == 3) {
    memmove(s->value, value, vn);
    if (vn < s->value_len)
      memset(s->value + vn, 0, s->value_len - vn);
    s->value_len = vn;
    s->writes++;
  }
  if (action == 1) {
    s->mtu = mtu;
    s->negotiated = 1;
  }
  if (action == 2)
    s->discovered = 1;
  if (rn) {
    wrap(out, reply, rn);
    *out_len = rn + 4;
  }
  return 0;
}
int sle_ssap_server_notify(sle_ssap_server *s, int encrypted, const uint8_t *v,
                          size_t n, uint8_t *out, size_t cap, size_t *out_len) {
  if (out_len)
    *out_len = 0;
  if (!s || (!v && n) || !out || !out_len)
    return SLE_SSAP_SERVER_ARGUMENT;
  if (!encrypted || !s->negotiated || !s->discovered)
    return SLE_SSAP_SERVER_STATE;
  if (n > SLE_SSAP_SERVER_VALUE_MAX || n + 6 > s->mtu)
    return SLE_SSAP_SERVER_UNSUPPORTED;
  if (cap < n + 10)
    return SLE_SSAP_SERVER_BUFFER;
  uint8_t msg[SLE_SSAP_SERVER_VALUE_MAX + 6] = {15, 3, 2, 0};
  msg[4] = (uint8_t)n;
  msg[5] = (uint8_t)(n >> 8);
  if (n)
    memcpy(msg + 6, v, n);
  wrap(out, msg, n + 6);
  *out_len = n + 10;
  s->notifications++;
  return 0;
}
