/* sle_phy.h - portable C99 SLE (星闪) frame-type-1 GFSK bit-layer library.
 *
 * Covers: CRC12/CRC24 (MSB-first shift-register, matching the Python
 * reference scripts/sle_frame_reference.py), 7-bit whitening LFSR,
 * broadcast (A1) and connection (A2) control-info parsing, connection
 * sync-word generation from a 24-bit logical link identifier per
 * GB/T 46803.1 6.1.3.1, and full frame encode/decode.
 *
 * Bits are represented "unpacked": one uint8_t per bit, value 0 or 1,
 * in the order bits are transmitted on air (LSB-first within each
 * multi-bit field, matching sle_frame_reference.py's ASCII-bit-string
 * convention exactly). This trades memory for direct, easily-audited
 * correspondence with the Python reference and with the bit-level
 * design in GB/T 46803.1. No dynamic allocation; all buffers are
 * caller-provided or fixed-size.
 *
 * Zero external dependencies beyond libc. No x86-specific intrinsics.
 * Hot loops (whitening/CRC) are written as simple scalar loops with
 * clear function boundaries so a NEON/SIMD variant can replace them
 * later without touching callers.
 */
#ifndef SLE_PHY_H
#define SLE_PHY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SLE_SYNC_BITS            32
#define SLE_HEADER_BITS          32   /* 20-bit info + 12-bit CRC12 */
#define SLE_HEADER_INFO_BITS     20
#define SLE_CRC12_BITS           12
#define SLE_CRC24_BITS           24
#define SLE_MAX_PAYLOAD_BYTES    255
#define SLE_MAX_CONNECT_PAYLOAD_BYTES 2047
#define SLE_MAX_BROADCAST_PAYLOAD_BITS (SLE_MAX_PAYLOAD_BYTES * 8)
#define SLE_MAX_PAYLOAD_BITS     (SLE_MAX_CONNECT_PAYLOAD_BYTES * 8)
#define SLE_MAX_FRAME_BITS       (SLE_SYNC_BITS + SLE_HEADER_BITS + \
                                   SLE_MAX_PAYLOAD_BITS + SLE_CRC24_BITS)

#define SLE_BROADCAST_SYNC_WORD  0x5A2BDA62u

#define SLE_CRC12_POLY 0x80Fu   /* D^12+D^11+D^3+D^2+D+1, MSB (D^12) implicit */
#define SLE_CRC24_POLY 0x65Bu   /* MSB (D^24) implicit */
#define SLE_CRC24_INIT 0x555555u /* broadcast-class seed */

/* -------------------------------------------------------------------- */
/* Bit-string helpers (arrays of 0/1 bytes)                              */
/* -------------------------------------------------------------------- */

/* MSB-first shift-register CRC over `n` input bits (each 0 or 1).
 * `width` is 12 or 24. Returns the final register value in the low
 * `width` bits (matches sle_frame_reference.crc_bits numerically). */
uint32_t sle_crc_bits(const uint8_t *bits, size_t n, unsigned width,
                       uint32_t poly, uint32_t init);

/* Write the `width`-bit value of `state` into `out`, MSB-first bit order
 * (bit 0 of out is the register's MSB), matching Python's f"{state:0{w}b}". */
void sle_crc_to_bits(uint32_t state, unsigned width, uint8_t *out);

/* 7-bit whitening LFSR (x^7+x^4+1, feedback mask 0x11), MSB (bit6) output
 * first. Generates `count` bits starting from `seed` (0..127). */
void sle_whitening_bits(uint8_t *out, size_t count, uint8_t seed);

/* out[i] = a[i] ^ b[i] for i in [0,n). out may alias a or b. */
void sle_xor_bits(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t n);

/* LSB-first integer <-> bit-array conversions (bit 0 is the LSB). */
uint32_t sle_bits_to_u32_lsb(const uint8_t *bits, size_t n);
void sle_u32_to_bits_lsb(uint32_t value, unsigned width, uint8_t *out);

/* Pack/unpack LSB-first-per-byte bit strings <-> bytes, matching
 * sle_frame_reference.lsb_byte_bits / bytes_from_lsb_bits. */
void sle_bytes_to_bits_lsb(const uint8_t *bytes, size_t nbytes, uint8_t *bits);
void sle_bits_to_bytes_lsb(const uint8_t *bits, size_t nbytes, uint8_t *bytes);

/* -------------------------------------------------------------------- */
/* Connection sync word (GB/T 46803.1 6.1.3.1)                           */
/* -------------------------------------------------------------------- */

/* Generate the 32-bit air-order sync word (bit[0] transmitted first) for
 * a 24-bit logical link identifier `lid`. out must hold 32 uint8_t.
 * lid = 0xFFFFFF reproduces the fixed broadcast sync 0x5A2BDA62. */
void sle_sync_from_lid(uint32_t lid, uint8_t out[32]);

/* Inverse: validate a 32-bit air-order window as a connection sync
 * codeword. Returns 1 and writes *lid_out if valid, else returns 0. */
int sle_sync_check_window(const uint8_t w[32], uint32_t *lid_out);

/* -------------------------------------------------------------------- */
/* Frame types and decode result                                        */
/* -------------------------------------------------------------------- */

typedef enum {
    SLE_FRAME_BROADCAST = 0, /* control info A1: 3+3+6+8 */
    SLE_FRAME_CONNECT   = 1  /* control info A2: 2+1+1+1+1+1+2+11 */
} sle_frame_kind_t;

typedef enum {
    SLE_DECODE_OK           = 0,
    SLE_DECODE_NEED_MORE    = 1,  /* not enough bits supplied yet */
    SLE_DECODE_SYNC_MISMATCH= 2,
    SLE_DECODE_CRC12_FAIL   = 3,
    SLE_DECODE_CRC24_FAIL   = 4,
    SLE_DECODE_BAD_LENGTH   = 5,
    SLE_DECODE_NEED_CONFIG  = 6, /* nonempty A2 requires link CRC settings */
    SLE_DECODE_UNSUPPORTED_CRC = 7,
    SLE_DECODE_BAD_CONFIG   = 8
} sle_decode_status_t;

typedef enum {
    SLE_CRC_TYPE_24 = 24,
    SLE_CRC_TYPE_32 = 32 /* deliberately unsupported until implemented */
} sle_crc_type_t;

typedef struct {
    uint32_t lid;              /* 24-bit logical link identifier */
    uint8_t white_seed;        /* full 7-bit whitening seed */
    sle_crc_type_t crc_type;   /* negotiated data-link CRC type */
    uint32_t crc_init;         /* negotiated 32-bit field; CRC24 uses low 24 bits */
    uint16_t max_payload_bytes; /* 0 means protocol limit 2047; else 1..2047 */
} sle_connect_config_t;

/* Validate link parameters before use. CRC32 is a valid negotiated type but
 * the current body encoder/decoder returns UNSUPPORTED_CRC for it. */
sle_decode_status_t sle_connect_config_validate(const sle_connect_config_t *config);

typedef struct {
    sle_frame_kind_t kind;
    uint8_t  seed;              /* whitening seed actually used */
    uint16_t crc12_init;        /* low 12 bits of the sync word used */

    /* broadcast (A1) fields */
    uint8_t  broadcast_type;    /* 3 bit */
    uint8_t  packet_type;       /* 3 bit */
    uint8_t  reserved;          /* 6 bit */

    /* connect (A2) fields */
    uint8_t  conn_pkt_type;     /* 2 bit */
    uint8_t  conn_empty;        /* 1 bit */
    uint8_t  conn_sn;           /* 1 bit */
    uint8_t  conn_nesn;         /* 1 bit */
    uint8_t  conn_flow;         /* 1 bit */
    uint8_t  conn_mgmt_rx;      /* 1 bit */
    uint8_t  conn_reserved;     /* 2 bit */

    uint16_t length;            /* payload length in bytes (8 bit for
                                  * broadcast, 11 bit for connect) */
    int      crc12_ok;
    int      crc24_ok;          /* only meaningful when has_crc24 */
    int      has_crc24;         /* connect empty (length==0) frames omit
                                  * the CRC24 body entirely */
    uint16_t total_bits_from_sync; /* sync+header(+body) bit count consumed */

    uint8_t  payload[SLE_MAX_CONNECT_PAYLOAD_BYTES];
    uint16_t payload_len;
} sle_frame_t;

/* -------------------------------------------------------------------- */
/* Broadcast (A1) encode/decode                                          */
/* -------------------------------------------------------------------- */

/* Encode payload into channel bits starting at the sync word.
 * out_bits must hold at least SLE_SYNC_BITS + SLE_HEADER_BITS +
 * payload_len*8 + SLE_CRC24_BITS bits. Returns the number of bits
 * written, or 0 if payload_len > SLE_MAX_PAYLOAD_BYTES. */
size_t sle_encode_broadcast(uint8_t *out_bits, const uint8_t *payload,
                             size_t payload_len, uint8_t white_seed,
                             uint8_t broadcast_type, uint8_t packet_type,
                             uint8_t reserved);

/* Decode a sync-aligned bit buffer (bits[0..31] must equal the sync word
 * used) as a broadcast frame. `avail` is how many bits are available in
 * `bits`. Returns SLE_DECODE_NEED_MORE if `avail` is smaller than the
 * frame implies (caller should re-invoke once more bits arrive), or the
 * final status otherwise. On OK/CRC failure, *out is fully populated. */
sle_decode_status_t sle_decode_broadcast(const uint8_t *bits, size_t avail,
                                          uint8_t white_seed,
                                          const uint8_t sync_word_bits[32],
                                          sle_frame_t *out);

/* -------------------------------------------------------------------- */
/* Connect (A2). The configured calls are the production interface.       */
/* Unknown-seed decode is for recorded empty A2 headers only; it returns  */
/* NEED_CONFIG for nonempty frames because their CRC is link-negotiated.  */
/* -------------------------------------------------------------------- */

sle_decode_status_t sle_decode_connect(const uint8_t *bits, size_t avail,
                                        const uint8_t sync_word_bits[32],
                                        sle_frame_t *out);

/* A2 encoder writes only when all fields, CRC settings, and output capacity
 * are valid. Return 0 on invalid configuration, unsupported CRC32, or
 * insufficient capacity. An empty PDU has length 0 and omits body CRC. */
size_t sle_encode_connect_config(uint8_t *out_bits, size_t out_capacity_bits,
                                 const uint8_t *payload, size_t payload_len,
                                 const sle_connect_config_t *config,
                                 uint8_t pkt_type, uint8_t empty, uint8_t sn,
                                 uint8_t nesn, uint8_t flow, uint8_t mgmt_rx,
                                 uint8_t reserved2);

sle_decode_status_t sle_decode_connect_config(const uint8_t *bits, size_t avail,
                                                const sle_connect_config_t *config,
                                                sle_frame_t *out);

/* Legacy encoder has no LID or CRC configuration and therefore cannot emit
 * a valid connection frame. It always returns zero. */
size_t sle_encode_connect(uint8_t *out_bits, const uint8_t *payload,
                           size_t payload_len, uint8_t white_seed,
                           uint8_t pkt_type, uint8_t empty, uint8_t sn,
                           uint8_t nesn, uint8_t flow, uint8_t mgmt_rx,
                           uint8_t reserved2);

#ifdef __cplusplus
}
#endif
#endif /* SLE_PHY_H */
