/* Streaming invariants on deterministic synthetic 1M GFSK. This tests
 * receiver state and fault handling, not RF sensitivity or interoperability. */
#include "sle_demod.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PI 3.14159265358979323846
#define SPS 4
#define NSAMPLES 5000
#define FIRST_START 256
#define SECOND_START 2500
#define MAX_HITS 128
static unsigned failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

typedef struct {
    uint64_t sample;
    int phase, crc12, crc24, kind;
    unsigned length;
    uint8_t payload[SLE_MAX_CONNECT_PAYLOAD_BYTES];
} record_t;
typedef struct { size_t n; record_t rows[MAX_HITS]; } hits_t;

static void collect(const sle_found_frame_t *f, void *user)
{
    hits_t *h = user;
    CHECK(h->n < MAX_HITS);
    if (h->n >= MAX_HITS) return;
    record_t *r = &h->rows[h->n++];
    memset(r, 0, sizeof(*r));
    r->sample = f->sample_index;
    r->phase = f->phase;
    r->crc12 = f->frame.crc12_ok;
    r->crc24 = f->frame.crc24_ok;
    r->kind = f->frame.kind;
    r->length = f->frame.payload_len;
    memcpy(r->payload, f->frame.payload, r->length);
}

static sle_demod_channel_t *new_channel(hits_t *hits)
{
    sle_demod_channel_t *ch = calloc(1, sizeof(*ch));
    if (!ch) exit(2);
    CHECK(sle_demod_channel_init(ch, 4e6, 300e3, 2424, collect, hits) == 0);
    CHECK(sle_demod_add_broadcast_target(ch, 77, 0) == 0);
    return ch;
}

static uint32_t rng(uint32_t *s)
{
    *s = *s * 1664525u + 1013904223u;
    return *s;
}

static double uniform(uint32_t *s)
{
    return ((double)rng(s) + 0.5) / 4294967296.0;
}

/* Gaussian NRZ shaping, BT=0.5, span=4 symbols, h=0.5. An offset of
 * 300kHz exercises the NCO; residual CFO/noise are explicit test inputs. */
static void modulate_n(int16_t *iq, size_t capacity, size_t start, const uint8_t *bits, size_t nbits,
                     double cfo, double snr_db, uint32_t seed)
{
    const int half = 2 * SPS;
    const double sigma = sqrt(log(2.0)) * SPS / PI;
    double taps[4 * SPS + 1], sum = 0;
    for (int k = -half; k <= half; k++) {
        taps[k + half] = exp(-0.5 * k * k / (sigma * sigma));
        sum += taps[k + half];
    }
    const size_t n = (nbits + 10) * SPS;
    CHECK(start + n < capacity);
    if (start + n >= capacity) return;
    double phase = 0.37;
    const double amp = 12000.0;
    const double noise = snr_db > 100 ? 0 : amp * pow(10.0, -snr_db / 20) / sqrt(2.0);
    for (size_t i = 0; i < n; i++) {
        double control = 0;
        for (int k = -half; k <= half; k++) {
            long p = (long)i - k;
            if (p < 0 || (size_t)p >= n) continue;
            size_t b = (size_t)p / SPS;
            unsigned bit = b < 10 ? (unsigned)(b % 2) : bits[b - 10];
            control += (bit ? 1.0 : -1.0) * taps[k + half] / sum;
        }
        phase += 2 * PI * (300e3 + cfo + 250e3 * control) / 4e6;
        double radius = sqrt(-2 * log(uniform(&seed)));
        double angle = 2 * PI * uniform(&seed);
        iq[2 * (start + i)] = (int16_t)lrint(amp * cos(phase) + noise * radius * cos(angle));
        iq[2 * (start + i) + 1] = (int16_t)lrint(amp * sin(phase) + noise * radius * sin(angle));
    }
}

#define modulate(iq, start, bits, nbits, cfo, snr, seed) \
    modulate_n(iq, NSAMPLES, start, bits, nbits, cfo, snr, seed)

static size_t broadcast_bits(uint8_t *bits)
{
    uint8_t payload[32];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(7 + 31 * i);
    size_t n = sle_encode_broadcast(bits, payload, sizeof(payload), 77, 3, 1, 0);
    CHECK(n == 344);
    return n;
}

static void check_equal(const hits_t *a, const hits_t *b)
{
    CHECK(a->n == b->n);
    if (a->n == b->n) CHECK(memcmp(a->rows, b->rows, a->n * sizeof(record_t)) == 0);
}

static void test_chunking(double cfo, double snr)
{
    int16_t iq[2 * NSAMPLES] = {0};
    uint8_t bits[1024];
    size_t n = broadcast_bits(bits);
    modulate(iq, FIRST_START, bits, n, cfo, snr, 0x51E123u);
    modulate(iq, SECOND_START, bits, n, cfo, snr, 0x51E456u);
    hits_t *reference = calloc(1, sizeof(*reference));
    sle_demod_channel_t *whole = new_channel(reference);
    const uint64_t origin = 1000003; /* nonzero, not symbol-aligned */
    CHECK(sle_demod_channel_process(whole, iq, NSAMPLES, origin) == SLE_STREAM_OK);
    CHECK(whole->sample_counter == origin + NSAMPLES);
    CHECK(whole->stats.frames_ok >= 2);
    CHECK(reference->n >= 2);
    sle_demod_channel_finish(whole);
    for (int mode = 0; mode < 4; mode++) {
        hits_t *fragmented = calloc(1, sizeof(*fragmented));
        sle_demod_channel_t *ch = new_channel(fragmented);
        uint32_t random = 0x5EED2026u;
        for (size_t pos = 0; pos < NSAMPLES;) {
            size_t chunk = mode == 0 ? 1 : mode == 1 ? 7 : mode == 2 ? 997 : 1 + rng(&random) % 137;
            if (chunk > NSAMPLES - pos) chunk = NSAMPLES - pos;
            CHECK(sle_demod_channel_process(ch, iq + 2 * pos, chunk, origin + pos) == SLE_STREAM_OK);
            pos += chunk;
        }
        sle_demod_channel_finish(ch);
        check_equal(reference, fragmented);
        CHECK(memcmp(&whole->stats, &ch->stats, sizeof(ch->stats)) == 0);
        free(ch); free(fragmented);
    }
    printf("chunking cfo=%.0f snr_db=%.0f raw_candidates=%zu frames_ok=%llu: PASS\n",
           cfo, snr, reference->n, (unsigned long long)whole->stats.frames_ok);
    free(whole); free(reference);
}

static void test_faults(void)
{
    int16_t iq[2 * NSAMPLES] = {0};
    uint8_t bits[1024];
    size_t n = broadcast_bits(bits);
    modulate(iq, FIRST_START, bits, n, 0, 200, 1);
    modulate(iq, SECOND_START, bits, n, 0, 200, 2);
    hits_t *hits = calloc(1, sizeof(*hits));
    sle_demod_channel_t *ch = new_channel(hits);
    const size_t cut = FIRST_START + (10 + 32 + 32 + 24) * SPS + 32;
    const size_t resume = SECOND_START - 128;
    CHECK(sle_demod_channel_process(ch, iq, cut, 0) == SLE_STREAM_OK);
    CHECK(hits->n == 0);
    CHECK(sle_demod_channel_process(ch, iq + 2 * resume, NSAMPLES - resume, resume) == SLE_STREAM_GAP);
    CHECK(ch->stats.discontinuities == 1);
    CHECK(ch->stats.missing_samples == resume - cut);
    CHECK(ch->stats.truncated_candidates > 0);
    CHECK(ch->stats.frames_ok > 0);
    for (size_t i = 0; i < hits->n; i++) CHECK(hits->rows[i].sample >= resume);
    printf("gap missing_samples=%llu truncated_phase_candidates=%llu later_frames=%zu: PASS\n",
           (unsigned long long)ch->stats.missing_samples,
           (unsigned long long)ch->stats.truncated_candidates, hits->n);
    free(ch); memset(hits, 0, sizeof(*hits)); ch = new_channel(hits);
    CHECK(sle_demod_channel_process(ch, iq, 100, 0) == SLE_STREAM_OK);
    CHECK(sle_demod_channel_process(ch, iq, 100, 0) == SLE_STREAM_STALE);
    CHECK(sle_demod_channel_process(ch, iq + 100, 25, 50) == SLE_STREAM_STALE);
    CHECK(ch->sample_counter == 100);
    CHECK(ch->stats.rejected_chunks == 2 && ch->stats.rejected_samples == 125);
    CHECK(sle_demod_channel_process(ch, iq + 200, NSAMPLES - 100, 100) == SLE_STREAM_OK);
    CHECK(ch->stats.samples_processed == NSAMPLES && ch->stats.frames_ok >= 2);
    hits_t *ref = calloc(1, sizeof(*ref));
    sle_demod_channel_t *whole = new_channel(ref);
    CHECK(sle_demod_channel_process(whole, iq, NSAMPLES, 0) == SLE_STREAM_OK);
    check_equal(hits, ref);
    free(whole); free(ref); free(ch);
    memset(hits, 0, sizeof(*hits)); ch = new_channel(hits);
    CHECK(sle_demod_channel_process(ch, iq, cut, 0) == SLE_STREAM_OK);
    CHECK(sle_demod_channel_finish(ch) > 0);
    CHECK(sle_demod_channel_finish(ch) == 0);
    CHECK(hits->n == 0);
    CHECK(sle_demod_channel_process(ch, NULL, 1, 0) == SLE_STREAM_BAD_ARGUMENT);
    CHECK(sle_demod_channel_process(ch, iq, 2, UINT64_MAX) == SLE_STREAM_BAD_ARGUMENT);
    CHECK(sle_demod_channel_process(ch, NULL, 0, 1234) == SLE_STREAM_OK);
    CHECK(!ch->have_sample_counter);
    CHECK(sle_demod_channel_init(ch, NAN, 0, 2424, NULL, NULL) != 0);
    CHECK(sle_demod_channel_init(ch, 4e6, INFINITY, 2424, NULL, NULL) != 0);
    printf("duplicate/backwards rejected; EOF truncation and invalid input: PASS\n");
    free(ch); free(hits);
}

static void test_crc_diagnostics(void)
{
    for (int body = 0; body < 2; body++) {
        int16_t iq[2 * NSAMPLES] = {0};
        uint8_t bits[1024];
        size_t n = broadcast_bits(bits);
        bits[body ? n - 1 : 32 + 3] ^= 1;
        modulate(iq, FIRST_START, bits, n, 0, 200, 3);
        hits_t *h = calloc(1, sizeof(*h));
        sle_demod_channel_t *ch = new_channel(h);
        CHECK(sle_demod_channel_process(ch, iq, NSAMPLES, 0) == SLE_STREAM_OK);
        CHECK(ch->stats.frames_ok == 0);
        if (body) {
            CHECK(ch->stats.crc24_failures > 0 && h->n > 0);
            for (size_t i = 0; i < h->n; i++) CHECK(h->rows[i].crc12 && !h->rows[i].crc24);
        } else {
            CHECK(ch->stats.crc12_failures > 0 && h->n == 0);
        }
        printf("damaged %s: crc12_fail=%llu crc24_fail=%llu PASS\n", body ? "body" : "header",
               (unsigned long long)ch->stats.crc12_failures, (unsigned long long)ch->stats.crc24_failures);
        free(ch); free(h);
    }
}

static void test_segment_boundary(void)
{
    int16_t iq[2 * NSAMPLES] = {0};
    uint8_t bits[1024];
    size_t n = broadcast_bits(bits);
    modulate(iq, FIRST_START, bits, n, 0, 200, 5);
    modulate(iq, SECOND_START, bits, n, 0, 200, 6);
    /* One segment begins at the preamble; the other is missing the first
     * half of the sync word. The latter must not invent a complete packet. */
    for (int partial = 0; partial < 2; partial++) {
        size_t origin = FIRST_START + (partial ? (10 + 16) * SPS : 0);
        hits_t *h = calloc(1, sizeof(*h));
        sle_demod_channel_t *ch = new_channel(h);
        CHECK(sle_demod_channel_process(ch, iq + 2 * origin, NSAMPLES - origin, origin) == SLE_STREAM_OK);
        CHECK(ch->stats.warmup_samples_discarded == SLE_DEMOD_FIR_TAPS);
        CHECK(h->n > 0);
        int early = 0;
        for (size_t i = 0; i < h->n; i++) if (h->rows[i].sample < SECOND_START) early++;
        CHECK(partial ? early == 0 : early > 0);
        free(ch); free(h);
    }
    printf("segment at preamble vs missing sync: explicit warmup and later recovery PASS\n");
}

static void test_configured_connect(void)
{
    const uint8_t payload[] = {0x51, 0x00, 0x63, 0xA5, 0xFF};
    sle_connect_config_t cfg = { .lid = 0xE56436, .white_seed = 92,
        .crc_type = SLE_CRC_TYPE_24, .crc_init = 0x123456, .max_payload_bytes = 255 };
    uint8_t bits[1024];
    size_t n = sle_encode_connect_config(bits, sizeof(bits), payload, sizeof(payload), &cfg, 0, 0, 0, 1, 0, 0, 0);
    CHECK(n > 0);
    int16_t iq[2 * NSAMPLES] = {0};
    modulate(iq, FIRST_START, bits, n, 0, 200, 4);
    for (int configured = 0; configured < 2; configured++) {
        hits_t *h = calloc(1, sizeof(*h));
        sle_demod_channel_t *ch = new_channel(h);
        int ret = configured ? sle_demod_add_connect_config_target(ch, &cfg, 0)
                             : sle_demod_add_connect_target(ch, cfg.lid, 0);
        CHECK(ret == 0);
        CHECK(sle_demod_channel_process(ch, iq, NSAMPLES, 0) == SLE_STREAM_OK);
        if (configured) {
            CHECK(ch->stats.frames_ok > 0 && h->n > 0);
            for (size_t i = 0; i < h->n; i++) {
                CHECK(h->rows[i].kind == SLE_FRAME_CONNECT);
                CHECK(h->rows[i].length == sizeof(payload));
                CHECK(memcmp(h->rows[i].payload, payload, sizeof(payload)) == 0);
            }
        } else {
            CHECK(ch->stats.configuration_failures > 0);
            CHECK(h->n == 0);
        }
        free(ch); free(h);
    }
    printf("nonempty connection requires explicit link config: PASS\n");

    /* Exercise the streaming bit buffer at the full 11-bit payload limit. */
    size_t capacity = 70000;
    int16_t *large_iq = calloc(2 * capacity, sizeof(*large_iq));
    uint8_t *large_bits = malloc(SLE_MAX_FRAME_BITS);
    uint8_t *large_payload = malloc(SLE_MAX_CONNECT_PAYLOAD_BYTES);
    if (!large_iq || !large_bits || !large_payload) exit(2);
    for (size_t i = 0; i < SLE_MAX_CONNECT_PAYLOAD_BYTES; i++) large_payload[i] = (uint8_t)(i * 29 + 11);
    cfg.max_payload_bytes = 0;
    n = sle_encode_connect_config(large_bits, SLE_MAX_FRAME_BITS, large_payload,
           SLE_MAX_CONNECT_PAYLOAD_BYTES, &cfg, 0, 0, 0, 1, 0, 0, 0);
    CHECK(n == SLE_MAX_FRAME_BITS);
    modulate_n(large_iq, capacity, FIRST_START, large_bits, n, 0, 200, 7);
    hits_t *h = calloc(1, sizeof(*h));
    sle_demod_channel_t *ch = new_channel(h);
    CHECK(sle_demod_add_connect_config_target(ch, &cfg, 0) == 0);
    for (size_t pos = 0; pos < capacity;) {
        size_t size = capacity - pos < 97 ? capacity - pos : 97;
        CHECK(sle_demod_channel_process(ch, large_iq + 2 * pos, size, pos) == SLE_STREAM_OK);
        pos += size;
    }
    CHECK(h->n > 0);
    for (size_t i = 0; i < h->n; i++) {
        CHECK(h->rows[i].length == SLE_MAX_CONNECT_PAYLOAD_BYTES);
        CHECK(memcmp(h->rows[i].payload, large_payload, SLE_MAX_CONNECT_PAYLOAD_BYTES) == 0);
    }
    printf("2047-byte A2 GFSK in 97-sample chunks: PASS\n");
    free(ch); free(h); free(large_iq); free(large_bits); free(large_payload);
}

int main(void)
{
    test_chunking(0, 200);
    test_chunking(20000, 22);
    test_chunking(-20000, 22);
    test_faults();
    test_crc_diagnostics();
    test_segment_boundary();
    test_configured_connect();
    printf("synthetic demod tests: %s (%u failures)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
