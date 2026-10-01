/* sle_phy.c - see sle_phy.h. Ported bit-for-bit from
 * scripts/sle_frame_reference.py and
 * logs/e310/p2-connect-205712/analysis/sle_sync.py /
 * .../sle_conn_decode.py. */
#include "sle_phy.h"
#include <string.h>

/* ---------------------------------------------------------------------
 * CRC / whitening / bit-array primitives
 * ------------------------------------------------------------------- */

uint32_t sle_crc_bits(const uint8_t *bits, size_t n, unsigned width,
                       uint32_t poly, uint32_t init)
{
    uint32_t mask = (width >= 32) ? 0xFFFFFFFFu : ((1u << width) - 1u);
    uint32_t state = init & mask;
    for (size_t i = 0; i < n; i++) {
        uint32_t msb = (state >> (width - 1)) & 1u;
        uint32_t feedback = msb ^ (uint32_t)(bits[i] & 1u);
        state = ((state << 1) & mask);
        if (feedback) state ^= (poly & mask);
    }
    return state;
}

void sle_crc_to_bits(uint32_t state, unsigned width, uint8_t *out)
{
    /* Python: f"{state:0{width}b}" -> MSB first string, index 0 = MSB. */
    for (unsigned i = 0; i < width; i++) {
        unsigned shift = width - 1 - i;
        out[i] = (uint8_t)((state >> shift) & 1u);
    }
}

void sle_whitening_bits(uint8_t *out, size_t count, uint8_t seed)
{
    uint8_t state = (uint8_t)(seed & 0x7Fu);
    for (size_t i = 0; i < count; i++) {
        uint8_t bit = (uint8_t)((state >> 6) & 1u);
        out[i] = bit;
        state = (uint8_t)(((state << 1) & 0x7Fu) ^ (bit ? 0x11u : 0u));
    }
}

void sle_xor_bits(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)((a[i] & 1u) ^ (b[i] & 1u));
}

uint32_t sle_bits_to_u32_lsb(const uint8_t *bits, size_t n)
{
    uint32_t v = 0;
    for (size_t i = 0; i < n && i < 32; i++)
        v |= ((uint32_t)(bits[i] & 1u)) << i;
    return v;
}

void sle_u32_to_bits_lsb(uint32_t value, unsigned width, uint8_t *out)
{
    for (unsigned i = 0; i < width; i++)
        out[i] = (uint8_t)((value >> i) & 1u);
}

void sle_bytes_to_bits_lsb(const uint8_t *bytes, size_t nbytes, uint8_t *bits)
{
    for (size_t byte = 0; byte < nbytes; byte++)
        for (unsigned bit = 0; bit < 8; bit++)
            bits[byte * 8 + bit] = (uint8_t)((bytes[byte] >> bit) & 1u);
}

void sle_bits_to_bytes_lsb(const uint8_t *bits, size_t nbytes, uint8_t *bytes)
{
    for (size_t byte = 0; byte < nbytes; byte++) {
        uint8_t v = 0;
        for (unsigned bit = 0; bit < 8; bit++)
            v = (uint8_t)(v | (uint8_t)((bits[byte * 8 + bit] & 1u) << bit));
        bytes[byte] = v;
    }
}

/* ---------------------------------------------------------------------
 * Connection sync word (GB/T 46803.1 6.1.3.1): BCH(31,26), g=0o45 octal,
 * XORed with a 31-bit m-sequence (x^5+x^2+1 style, taps as in sle_sync.py),
 * plus a trailing 0 bit -> 32 bits total.
 * ------------------------------------------------------------------- */

static void mseq31(uint8_t out[31])
{
    uint8_t r[5] = {1, 1, 1, 1, 1};
    for (int i = 0; i < 31; i++) {
        out[i] = r[4];
        uint8_t fb = (uint8_t)(r[1] ^ r[4]);
        r[4] = r[3]; r[3] = r[2]; r[2] = r[1]; r[1] = r[0]; r[0] = fb;
    }
}

/* polymod(bits[0..len-1] low->high degree, g) -> low `deg` coefficients,
 * deg = bit_length(g)-1. Matches sle_sync.py polymod exactly (GF(2)). */
static void polymod(uint8_t *b, size_t len, unsigned g, uint8_t *rem_out)
{
    unsigned deg = 0;
    { unsigned t = g; while (t) { deg++; t >>= 1; } deg -= 1; }
    for (size_t i = len; i-- > deg; ) {
        if (b[i]) {
            for (unsigned j = 0; j <= deg; j++) {
                if ((g >> j) & 1u)
                    b[i - deg + j] = (uint8_t)(b[i - deg + j] ^ 1u);
            }
        }
    }
    for (unsigned k = 0; k < deg; k++) rem_out[k] = b[k];
}

#define SLE_SYNC_G 0045u /* octal 45 = decimal 37 = 0b100101, deg 5 */

void sle_sync_from_lid(uint32_t lid, uint8_t out[32])
{
    uint8_t p[31];
    mseq31(p);

    uint8_t a[24];
    for (int i = 0; i < 24; i++) a[i] = (uint8_t)((lid >> i) & 1u);

    /* at = [1,0] + a  (26 bits, low->high degree) */
    uint8_t at[26];
    at[0] = 1; at[1] = 0;
    memcpy(at + 2, a, 24);

    /* c = (0*5 ++ at) mod G, i.e. shift at up by 5 degrees then reduce */
    uint8_t padded[5 + 26];
    memset(padded, 0, 5);
    memcpy(padded + 5, at, 26);
    uint8_t c[5];
    polymod(padded, sizeof padded, SLE_SYNC_G, c);

    uint8_t s[31];
    memcpy(s, at, 26);
    memcpy(s + 26, c, 5);

    for (int i = 0; i < 31; i++) out[i] = (uint8_t)(s[i] ^ p[i]);
    out[31] = 0;
}

int sle_sync_check_window(const uint8_t w[32], uint32_t *lid_out)
{
    if (w[31] != 0) return 0;
    uint8_t p[31];
    mseq31(p);
    uint8_t s[31];
    for (int i = 0; i < 31; i++) s[i] = (uint8_t)(w[i] ^ p[i]);
    if (s[0] != 1 || s[1] != 0) return 0;

    uint8_t padded[5 + 26];
    memset(padded, 0, 5);
    memcpy(padded + 5, s, 26);
    uint8_t c[5];
    polymod(padded, sizeof padded, SLE_SYNC_G, c);
    for (int k = 0; k < 5; k++)
        if (c[k] != s[26 + k]) return 0;

    uint32_t lid = 0;
    for (int i = 0; i < 24; i++) lid |= ((uint32_t)s[2 + i]) << i;
    if (lid_out) *lid_out = lid;
    return 1;
}

/* ---------------------------------------------------------------------
 * Broadcast (A1) encode / decode
 * ------------------------------------------------------------------- */

size_t sle_encode_broadcast(uint8_t *out_bits, const uint8_t *payload,
                             size_t payload_len, uint8_t white_seed,
                             uint8_t broadcast_type, uint8_t packet_type,
                             uint8_t reserved)
{
    if (payload_len > SLE_MAX_PAYLOAD_BYTES) return 0;

    uint8_t info[SLE_HEADER_INFO_BITS];
    sle_u32_to_bits_lsb(broadcast_type, 3, info + 0);
    sle_u32_to_bits_lsb(packet_type, 3, info + 3);
    sle_u32_to_bits_lsb(reserved, 6, info + 6);
    sle_u32_to_bits_lsb((uint32_t)payload_len, 8, info + 12);

    uint32_t crc12 = sle_crc_bits(info, SLE_HEADER_INFO_BITS, 12,
                                   SLE_CRC12_POLY, SLE_BROADCAST_SYNC_WORD & 0xFFF);
    uint8_t crc12_bits[SLE_CRC12_BITS];
    sle_crc_to_bits(crc12, 12, crc12_bits);

    size_t payload_bits_n = payload_len * 8;
    uint8_t payload_bits[SLE_MAX_BROADCAST_PAYLOAD_BITS];
    sle_bytes_to_bits_lsb(payload, payload_len, payload_bits);

    uint32_t crc24 = sle_crc_bits(payload_bits, payload_bits_n, 24,
                                   SLE_CRC24_POLY, SLE_CRC24_INIT);
    uint8_t crc24_bits[SLE_CRC24_BITS];
    sle_crc_to_bits(crc24, 24, crc24_bits);

    size_t plain_n = SLE_HEADER_INFO_BITS + SLE_CRC12_BITS + payload_bits_n + SLE_CRC24_BITS;
    uint8_t plain[SLE_HEADER_BITS + SLE_MAX_BROADCAST_PAYLOAD_BITS + SLE_CRC24_BITS];
    size_t o = 0;
    memcpy(plain + o, info, SLE_HEADER_INFO_BITS); o += SLE_HEADER_INFO_BITS;
    memcpy(plain + o, crc12_bits, SLE_CRC12_BITS); o += SLE_CRC12_BITS;
    memcpy(plain + o, payload_bits, payload_bits_n); o += payload_bits_n;
    memcpy(plain + o, crc24_bits, SLE_CRC24_BITS); o += SLE_CRC24_BITS;

    uint8_t white[SLE_HEADER_BITS + SLE_MAX_BROADCAST_PAYLOAD_BITS + SLE_CRC24_BITS];
    sle_whitening_bits(white, plain_n, white_seed);

    for (int i = 0; i < 32; i++)
        out_bits[i] = (uint8_t)((SLE_BROADCAST_SYNC_WORD >> i) & 1u);
    sle_xor_bits(out_bits + 32, plain, white, plain_n);

    return 32 + plain_n;
}

sle_decode_status_t sle_decode_broadcast(const uint8_t *bits, size_t avail,
                                          uint8_t white_seed,
                                          const uint8_t sync_word_bits[32],
                                          sle_frame_t *out)
{
    memset(out, 0, sizeof(*out));
    out->kind = SLE_FRAME_BROADCAST;
    out->seed = white_seed;

    if (avail < SLE_SYNC_BITS + SLE_HEADER_BITS) return SLE_DECODE_NEED_MORE;
    for (int i = 0; i < 32; i++)
        if ((bits[i] & 1u) != (sync_word_bits[i] & 1u)) return SLE_DECODE_SYNC_MISMATCH;

    uint16_t crc12_init = (uint16_t)(sle_bits_to_u32_lsb(sync_word_bits, 32) & 0xFFF);
    out->crc12_init = crc12_init;

    uint8_t white_hdr[SLE_HEADER_BITS];
    sle_whitening_bits(white_hdr, SLE_HEADER_BITS, white_seed);
    uint8_t header[SLE_HEADER_BITS];
    sle_xor_bits(header, bits + 32, white_hdr, SLE_HEADER_BITS);

    uint8_t *info = header;
    uint8_t *crc12_rx = header + SLE_HEADER_INFO_BITS;

    out->broadcast_type = (uint8_t)sle_bits_to_u32_lsb(info + 0, 3);
    out->packet_type    = (uint8_t)sle_bits_to_u32_lsb(info + 3, 3);
    out->reserved       = (uint8_t)sle_bits_to_u32_lsb(info + 6, 6);
    out->length         = (uint16_t)sle_bits_to_u32_lsb(info + 12, 8);

    uint32_t crc12_calc = sle_crc_bits(info, SLE_HEADER_INFO_BITS, 12,
                                        SLE_CRC12_POLY, crc12_init);
    uint8_t crc12_calc_bits[SLE_CRC12_BITS];
    sle_crc_to_bits(crc12_calc, 12, crc12_calc_bits);
    out->crc12_ok = (memcmp(crc12_calc_bits, crc12_rx, SLE_CRC12_BITS) == 0);

    out->has_crc24 = 1; /* broadcast frames always carry CRC24, even len=0 */
    size_t needed = SLE_SYNC_BITS + SLE_HEADER_BITS + (size_t)out->length * 8 + SLE_CRC24_BITS;
    out->total_bits_from_sync = (uint16_t)needed;
    if (!out->crc12_ok) {
        /* length field may be garbage; still report what we can, but we
         * cannot trust needed size, so stop here. */
        return SLE_DECODE_CRC12_FAIL;
    }
    if (avail < needed) return SLE_DECODE_NEED_MORE;

    size_t body_bits_n = (size_t)out->length * 8 + SLE_CRC24_BITS;
    uint8_t white_body[SLE_HEADER_BITS + SLE_MAX_BROADCAST_PAYLOAD_BITS + SLE_CRC24_BITS];
    sle_whitening_bits(white_body, SLE_HEADER_BITS + body_bits_n, white_seed);
    uint8_t body[SLE_MAX_BROADCAST_PAYLOAD_BITS + SLE_CRC24_BITS];
    sle_xor_bits(body, bits + 32 + SLE_HEADER_BITS, white_body + SLE_HEADER_BITS, body_bits_n);

    uint8_t *payload_bits = body;
    uint8_t *crc24_rx = body + (size_t)out->length * 8;
    uint32_t crc24_calc = sle_crc_bits(payload_bits, (size_t)out->length * 8, 24,
                                        SLE_CRC24_POLY, SLE_CRC24_INIT);
    uint8_t crc24_calc_bits[SLE_CRC24_BITS];
    sle_crc_to_bits(crc24_calc, 24, crc24_calc_bits);
    out->crc24_ok = (memcmp(crc24_calc_bits, crc24_rx, SLE_CRC24_BITS) == 0);

    out->payload_len = out->length;
    sle_bits_to_bytes_lsb(payload_bits, out->payload_len, out->payload);

    return out->crc24_ok ? SLE_DECODE_OK : SLE_DECODE_CRC24_FAIL;
}

/* ---------------------------------------------------------------------
 * Connect (A2) encode / decode
 * ------------------------------------------------------------------- */

static void conn_info_bits(uint8_t out[SLE_HEADER_INFO_BITS], uint8_t pkt_type,
                            uint8_t empty, uint8_t sn, uint8_t nesn,
                            uint8_t flow, uint8_t mgmt_rx, uint16_t length,
                            uint8_t reserved2)
{
    size_t o = 0;
    sle_u32_to_bits_lsb(pkt_type, 2, out + o); o += 2;
    sle_u32_to_bits_lsb(empty, 1, out + o); o += 1;
    sle_u32_to_bits_lsb(sn, 1, out + o); o += 1;
    sle_u32_to_bits_lsb(nesn, 1, out + o); o += 1;
    sle_u32_to_bits_lsb(flow, 1, out + o); o += 1;
    sle_u32_to_bits_lsb(mgmt_rx, 1, out + o); o += 1;
    sle_u32_to_bits_lsb(reserved2, 2, out + o); o += 2;
    sle_u32_to_bits_lsb(length, 11, out + o); o += 11;
    (void)o;
}

size_t sle_encode_connect(uint8_t *out_bits, const uint8_t *payload,
                           size_t payload_len, uint8_t white_seed,
                           uint8_t pkt_type, uint8_t empty, uint8_t sn,
                           uint8_t nesn, uint8_t flow, uint8_t mgmt_rx,
                           uint8_t reserved2)
{
    (void)out_bits; (void)payload; (void)payload_len; (void)white_seed;
    (void)pkt_type; (void)empty; (void)sn; (void)nesn;
    (void)flow; (void)mgmt_rx; (void)reserved2;
    return 0; /* No LID or negotiated CRC init is available to this API. */
}

static uint8_t whiten_step(uint8_t *state)
{
    uint8_t bit = (uint8_t)((*state >> 6) & 1u);
    *state = (uint8_t)(((*state << 1) & 0x7fu) ^ (bit ? 0x11u : 0u));
    return bit;
}

static int connect_config_ok(const sle_connect_config_t *config)
{
    return config && config->lid <= 0xffffffu && config->white_seed <= 127u &&
           (config->crc_type == SLE_CRC_TYPE_24 || config->crc_type == SLE_CRC_TYPE_32) &&
           config->max_payload_bytes <= SLE_MAX_CONNECT_PAYLOAD_BYTES;
}

sle_decode_status_t sle_connect_config_validate(const sle_connect_config_t *config)
{
    if (!connect_config_ok(config)) return SLE_DECODE_BAD_CONFIG;
    if (config->crc_type == SLE_CRC_TYPE_32) return SLE_DECODE_UNSUPPORTED_CRC;
    return SLE_DECODE_OK;
}

static size_t connect_payload_limit(const sle_connect_config_t *config)
{
    return config->max_payload_bytes ? config->max_payload_bytes : SLE_MAX_CONNECT_PAYLOAD_BYTES;
}

static void parse_conn_info(const uint8_t info[SLE_HEADER_INFO_BITS], sle_frame_t *out)
{
    size_t o = 0;
    out->conn_pkt_type = (uint8_t)sle_bits_to_u32_lsb(info + o, 2); o += 2;
    out->conn_empty = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o++;
    out->conn_sn = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o++;
    out->conn_nesn = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o++;
    out->conn_flow = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o++;
    out->conn_mgmt_rx = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o++;
    out->conn_reserved = (uint8_t)sle_bits_to_u32_lsb(info + o, 2); o += 2;
    out->length = (uint16_t)sle_bits_to_u32_lsb(info + o, 11);
}

size_t sle_encode_connect_config(uint8_t *out_bits, size_t out_capacity_bits,
                                 const uint8_t *payload, size_t payload_len,
                                 const sle_connect_config_t *config,
                                 uint8_t pkt_type, uint8_t empty, uint8_t sn,
                                 uint8_t nesn, uint8_t flow, uint8_t mgmt_rx,
                                 uint8_t reserved2)
{
    if (!out_bits || !connect_config_ok(config) || config->crc_type != SLE_CRC_TYPE_24 ||
        payload_len > connect_payload_limit(config) ||
        (payload_len && !payload) || pkt_type > 3 || empty > 1 || sn > 1 ||
        nesn > 1 || flow > 1 || mgmt_rx > 1 || reserved2 > 3 ||
        (empty && payload_len != 0) || (!empty && payload_len == 0))
        return 0;
    size_t needed = SLE_SYNC_BITS + SLE_HEADER_BITS +
                    (empty ? 0 : payload_len * 8 + SLE_CRC24_BITS);
    if (out_capacity_bits < needed) return 0;

    uint8_t sync[SLE_SYNC_BITS];
    sle_sync_from_lid(config->lid, sync);
    memcpy(out_bits, sync, sizeof sync);
    uint8_t info[SLE_HEADER_INFO_BITS], crc12_bits[SLE_CRC12_BITS];
    conn_info_bits(info, pkt_type, empty, sn, nesn, flow, mgmt_rx,
                   (uint16_t)payload_len, reserved2);
    uint16_t crc12_init = (uint16_t)(sle_bits_to_u32_lsb(sync, 32) & 0xfffu);
    uint32_t crc12 = sle_crc_bits(info, SLE_HEADER_INFO_BITS, 12, SLE_CRC12_POLY, crc12_init);
    sle_crc_to_bits(crc12, 12, crc12_bits);
    uint8_t white_state = config->white_seed;
    size_t o = SLE_SYNC_BITS;
    for (size_t i = 0; i < SLE_HEADER_INFO_BITS; i++) out_bits[o++] = info[i] ^ whiten_step(&white_state);
    for (size_t i = 0; i < SLE_CRC12_BITS; i++) out_bits[o++] = crc12_bits[i] ^ whiten_step(&white_state);
    if (!empty) {
        uint8_t payload_bits[SLE_MAX_PAYLOAD_BITS];
        sle_bytes_to_bits_lsb(payload, payload_len, payload_bits);
        uint32_t crc24 = sle_crc_bits(payload_bits, payload_len * 8, 24,
                                      SLE_CRC24_POLY, config->crc_init & 0xffffffu);
        uint8_t crc24_bits[SLE_CRC24_BITS];
        sle_crc_to_bits(crc24, 24, crc24_bits);
        for (size_t i = 0; i < payload_len * 8; i++) out_bits[o++] = payload_bits[i] ^ whiten_step(&white_state);
        for (size_t i = 0; i < SLE_CRC24_BITS; i++) out_bits[o++] = crc24_bits[i] ^ whiten_step(&white_state);
    }
    return o;
}

sle_decode_status_t sle_decode_connect_config(const uint8_t *bits, size_t avail,
                                                const sle_connect_config_t *config,
                                                sle_frame_t *out)
{
    if (!out || !bits || !connect_config_ok(config)) return SLE_DECODE_BAD_CONFIG;
    memset(out, 0, sizeof *out);
    out->kind = SLE_FRAME_CONNECT;
    out->seed = config->white_seed;
    if (config->crc_type != SLE_CRC_TYPE_24) return SLE_DECODE_UNSUPPORTED_CRC;
    if (avail < SLE_SYNC_BITS + SLE_HEADER_BITS) return SLE_DECODE_NEED_MORE;
    uint8_t sync[SLE_SYNC_BITS];
    sle_sync_from_lid(config->lid, sync);
    if (memcmp(bits, sync, sizeof sync) != 0) return SLE_DECODE_SYNC_MISMATCH;
    out->crc12_init = (uint16_t)(sle_bits_to_u32_lsb(sync, 32) & 0xfffu);
    uint8_t white_state = config->white_seed;
    uint8_t header[SLE_HEADER_BITS];
    for (size_t i = 0; i < SLE_HEADER_BITS; i++) header[i] = (bits[SLE_SYNC_BITS + i] & 1u) ^ whiten_step(&white_state);
    uint32_t crc12 = sle_crc_bits(header, SLE_HEADER_INFO_BITS, 12,
                                  SLE_CRC12_POLY, out->crc12_init);
    uint8_t crc12_bits[SLE_CRC12_BITS];
    sle_crc_to_bits(crc12, 12, crc12_bits);
    if (memcmp(header + SLE_HEADER_INFO_BITS, crc12_bits, SLE_CRC12_BITS) != 0)
        return SLE_DECODE_CRC12_FAIL;
    out->crc12_ok = 1;
    parse_conn_info(header, out);
    if ((out->conn_empty && out->length != 0) || (!out->conn_empty && out->length == 0) ||
        out->length > connect_payload_limit(config)) return SLE_DECODE_BAD_LENGTH;
    if (out->conn_empty) {
        out->total_bits_from_sync = SLE_SYNC_BITS + SLE_HEADER_BITS;
        out->crc24_ok = 1;
        return SLE_DECODE_OK;
    }
    out->has_crc24 = 1;
    size_t needed = SLE_SYNC_BITS + SLE_HEADER_BITS + (size_t)out->length * 8 + SLE_CRC24_BITS;
    out->total_bits_from_sync = (uint16_t)needed;
    if (avail < needed) return SLE_DECODE_NEED_MORE;
    uint8_t body[SLE_MAX_PAYLOAD_BITS + SLE_CRC24_BITS];
    size_t body_n = (size_t)out->length * 8 + SLE_CRC24_BITS;
    for (size_t i = 0; i < body_n; i++)
        body[i] = (bits[SLE_SYNC_BITS + SLE_HEADER_BITS + i] & 1u) ^ whiten_step(&white_state);
    uint32_t crc24 = sle_crc_bits(body, (size_t)out->length * 8, 24,
                                  SLE_CRC24_POLY, config->crc_init & 0xffffffu);
    uint8_t crc24_bits[SLE_CRC24_BITS];
    sle_crc_to_bits(crc24, 24, crc24_bits);
    out->crc24_ok = memcmp(body + (size_t)out->length * 8, crc24_bits, SLE_CRC24_BITS) == 0;
    out->payload_len = out->length;
    sle_bits_to_bytes_lsb(body, out->payload_len, out->payload);
    return out->crc24_ok ? SLE_DECODE_OK : SLE_DECODE_CRC24_FAIL;
}

sle_decode_status_t sle_decode_connect(const uint8_t *bits, size_t avail,
                                        const uint8_t sync_word_bits[32],
                                        sle_frame_t *out)
{
    memset(out, 0, sizeof(*out));
    out->kind = SLE_FRAME_CONNECT;

    if (avail < SLE_SYNC_BITS + SLE_HEADER_BITS) return SLE_DECODE_NEED_MORE;
    for (int i = 0; i < 32; i++)
        if ((bits[i] & 1u) != (sync_word_bits[i] & 1u)) return SLE_DECODE_SYNC_MISMATCH;

    uint16_t crc12_init = (uint16_t)(sle_bits_to_u32_lsb(sync_word_bits, 32) & 0xFFF);
    out->crc12_init = crc12_init;

    /* Brute-force the 7-bit whitening seed 0..127 (matches
     * sle_conn_decode.py); accept the first seed whose header CRC12
     * passes. Connection-frame seeds observed so far always have bit6
     * set (>=64), but the reference script scans the full range. */
    int found = 0;
    uint8_t best_seed = 0;
    uint8_t header[SLE_HEADER_BITS];
    for (int seed = 0; seed < 128 && !found; seed++) {
        uint8_t white_hdr[SLE_HEADER_BITS];
        sle_whitening_bits(white_hdr, SLE_HEADER_BITS, (uint8_t)seed);
        uint8_t hdr[SLE_HEADER_BITS];
        sle_xor_bits(hdr, bits + 32, white_hdr, SLE_HEADER_BITS);
        uint32_t crc12_calc = sle_crc_bits(hdr, SLE_HEADER_INFO_BITS, 12,
                                            SLE_CRC12_POLY, crc12_init);
        uint8_t crc12_calc_bits[SLE_CRC12_BITS];
        sle_crc_to_bits(crc12_calc, 12, crc12_calc_bits);
        if (memcmp(crc12_calc_bits, hdr + SLE_HEADER_INFO_BITS, SLE_CRC12_BITS) == 0) {
            found = 1;
            best_seed = (uint8_t)seed;
            memcpy(header, hdr, SLE_HEADER_BITS);
        }
    }
    if (!found) {
        out->crc12_ok = 0;
        return SLE_DECODE_CRC12_FAIL;
    }
    out->seed = best_seed;
    out->crc12_ok = 1;

    uint8_t *info = header;
    size_t o = 0;
    out->conn_pkt_type  = (uint8_t)sle_bits_to_u32_lsb(info + o, 2); o += 2;
    out->conn_empty     = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o += 1;
    out->conn_sn        = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o += 1;
    out->conn_nesn      = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o += 1;
    out->conn_flow      = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o += 1;
    out->conn_mgmt_rx   = (uint8_t)sle_bits_to_u32_lsb(info + o, 1); o += 1;
    out->conn_reserved  = (uint8_t)sle_bits_to_u32_lsb(info + o, 2); o += 2;
    out->length         = (uint16_t)sle_bits_to_u32_lsb(info + o, 11); o += 11;

    if (out->conn_empty && out->length == 0) {
        /* Empty connect PDUs (as observed) omit CRC24 entirely. */
        out->has_crc24 = 0;
        out->crc24_ok = 1; /* nothing to fail */
        out->total_bits_from_sync = SLE_SYNC_BITS + SLE_HEADER_BITS;
        out->payload_len = 0;
        return SLE_DECODE_OK;
    }
    if (out->conn_empty || out->length == 0 ||
        out->length > SLE_MAX_CONNECT_PAYLOAD_BYTES) return SLE_DECODE_BAD_LENGTH;
    return SLE_DECODE_NEED_CONFIG;
}
