/* Minimal fixed-property server, full DTAP SDUs in/out. Owner must supply
 * authenticated, ARQ-deduplicated, link-reassembled input only. No DTAP/SSAP
 * upper-layer fragmentation. Output needs caller's link framing and CCM.
 * Discovery response mirrors the observed official WS63 property record;
 * compatibility with an actual client remains an RF acceptance item.
 */
#ifndef SLE_SSAP_SERVER_H
#define SLE_SSAP_SERVER_H
#include <stddef.h>
#include <stdint.h>
#define SLE_SSAP_SERVER_SDU_MAX 1028u
#define SLE_SSAP_SERVER_VALUE_MAX 512u
typedef struct {
  uint16_t local_mtu, mtu;
  int negotiated, discovered;
  uint8_t value[SLE_SSAP_SERVER_VALUE_MAX];
  size_t value_len;
  uint64_t writes, notifications;
} sle_ssap_server;
enum {
  SLE_SSAP_SERVER_OK = 0,
  SLE_SSAP_SERVER_ARGUMENT = -1,
  SLE_SSAP_SERVER_STATE = -2,
  SLE_SSAP_SERVER_FORMAT = -3,
  SLE_SSAP_SERVER_UNSUPPORTED = -4,
  SLE_SSAP_SERVER_BUFFER = -5
};
int sle_ssap_server_init(sle_ssap_server *s, uint16_t mtu);
void sle_ssap_server_clear(sle_ssap_server *s);
/* No state change on errors, no partial output. WRITE_CMD returns length0;
 * WRITE_REQ always echoes exact bytes as the observed WS63 profile does.
 * data/cap output may overlap input but not server state.
 */
int sle_ssap_server_rx(sle_ssap_server *s, int encrypted, const uint8_t *sdu,
                      size_t n, uint8_t *out, size_t cap, size_t *out_len);
int sle_ssap_server_notify(sle_ssap_server *s, int encrypted,
                          const uint8_t *value, size_t n, uint8_t *out,
                          size_t cap, size_t *out_len);
#endif
