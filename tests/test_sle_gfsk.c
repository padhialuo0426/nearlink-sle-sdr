/* test_sle_gfsk.c - sle_gfsk round trip through sle_demod, and a dump mode
 * for the sample-by-sample comparison with scripts/sle_waveform_reference.py
 * (check_gfsk_ref.py).
 *
 * Usage: test_sle_gfsk            run the round-trip tests
 *        test_sle_gfsk --dump FS BITS   print "i q" per sample for BITS (0/1 string)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sle_demod.h"
#include "sle_gfsk.h"
#include "sle_phy.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", \
    __FILE__, __LINE__, #c); } } while (0)

static int found_ok, found_count;
static uint8_t found_payload[64];
static size_t found_len;
static uint64_t found_index;

static void on_frame(const sle_found_frame_t *f, void *user)
{
    (void)user;
    found_count++;
    if (f->frame.crc12_ok && f->frame.crc24_ok && !found_ok) {
        found_ok = 1;
        found_len = f->frame.payload_len;
        memcpy(found_payload, f->frame.payload, found_len < 64 ? found_len : 64);
        found_index = f->sample_index;
    }
}

static void roundtrip(int fs, double offset, int bypass, int dedup)
{
    static const uint8_t payload[] = { 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                       0x0b, 0x22, 0x00, 0x00 };   /* WS63 primary shape */
    uint8_t bits[SLE_MAX_FRAME_BITS], air[SLE_MAX_FRAME_BITS + 16];
    size_t nb = sle_encode_broadcast(bits, payload, sizeof payload, 77, 1, 0, 0);
    CHECK(nb > 0);
    size_t na = sle_gfsk_with_preamble(bits, nb, air, sizeof air);
    sle_gfsk_cfg_t c;
    sle_gfsk_default(&c, fs);
    size_t pad = (size_t)fs / 1000;                    /* 1 ms of silence around */
    size_t n = sle_gfsk_len(&c, na) + 2 * pad;
    int16_t *iq = calloc(n * 2, sizeof(int16_t));
    size_t w = sle_gfsk_mod(&c, air, na, offset, iq + 2 * pad, n - pad);
    CHECK(w == sle_gfsk_len(&c, na));
    static sle_demod_channel_t ch;
    found_ok = 0;
    found_count = 0;
    CHECK(sle_demod_channel_init(&ch, fs, offset, 2424, on_frame, NULL) == 0);
    CHECK(sle_demod_add_broadcast_target(&ch, 77, 0) == 0);
    sle_demod_set_fir_bypass(&ch, bypass);
    sle_demod_set_dedup(&ch, dedup);
    sle_demod_channel_process(&ch, iq, n, 0);
    sle_demod_channel_finish(&ch);
    CHECK(found_ok && found_len == sizeof payload && !memcmp(found_payload, payload, sizeof payload));
    /* sync starts after pad + lead + 10 preamble symbols */
    long expect = (long)(pad + (size_t)c.lead) + SLE_GFSK_PREAMBLE_BITS * (fs / 1000000);
    long err = (long)found_index - expect;
    CHECK(err >= -(fs / 1000000) && err <= fs / 1000000);
    if (dedup) CHECK(found_count == 1 && ch.stats.dedup_suppressed >= 1 && err == 0);
    else CHECK(found_count >= 2);   /* one report per phase that decoded it */
    printf("roundtrip fs=%d offset=%.0f bypass=%d dedup=%d: ok=%d reports=%d sync_index_error=%ld samples\n",
           fs, offset, bypass, dedup, found_ok, found_count, err);
    free(iq);
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "--dump")) {
        int fs = atoi(argv[2]);
        size_t nb = strlen(argv[3]);
        uint8_t *bits = malloc(nb);
        for (size_t i = 0; i < nb; i++) bits[i] = argv[3][i] == '1';
        sle_gfsk_cfg_t c;
        sle_gfsk_default(&c, fs);
        size_t n = sle_gfsk_len(&c, nb);
        int16_t *iq = malloc(n * 4);
        if (sle_gfsk_mod(&c, bits, nb, 0, iq, n) != n) return 1;
        printf("%d %d %.1f\n", c.lead, c.tail, c.amplitude);
        for (size_t i = 0; i < n; i++) printf("%d %d\n", iq[2 * i], iq[2 * i + 1]);
        return 0;
    }
    roundtrip(4000000, 0, 1, 0);
    roundtrip(4000000, 0, 0, 0);
    roundtrip(6000000, 1e6, 0, 0);
    roundtrip(4000000, 0, 1, 1);
    roundtrip(6000000, 1e6, 0, 1);
    printf("test_sle_gfsk: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
