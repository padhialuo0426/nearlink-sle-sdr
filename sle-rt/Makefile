# Two SDK108 runtime roles; all offline tests live in ../tests.
CC ?= cc
AR ?= ar
CFLAGS ?= -std=c11 -Wall -Wextra -O2
LDLIBS := -lm
PYTHON ?= python3
PAIR_PYTHON ?= $(PYTHON)
ARM_CC ?= arm-none-linux-gnueabihf-gcc
ARM_AR ?= $(patsubst %gcc,%ar,$(ARM_CC))
ARM_CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2 -mcpu=cortex-a9 -mfpu=neon -mfloat-abi=hard -static
ARM_BASE_CFLAGS = $(filter-out -DSLE_DEMOD_NEON_FIR=%,$(ARM_CFLAGS))
QEMU_ARM ?= qemu-arm-static

LIB_SRC := sle_phy.c sle_demod.c sle_access.c sle_clock.c sle_link.c sle_gfsk.c
RADIO_SRC := $(LIB_SRC) sle_radio_core.c sle_radio.c sle_hwstat.c sle_ssap.c sle_sdu.c
G_SRC := sle_g_runtime.c sle_pair.c sle_crypto.c sle_cmtc.c
G_RUNTIME_SRC := sle_phy.c sle_access.c sle_clock.c sle_link.c $(G_SRC)
T_SRC := sle_t_runtime.c sle_t_pair.c sle_ssap_server.c sle_t_wave.c
HEADERS := $(wildcard *.h)
TEST_HEADERS := $(wildcard ../tests/*.h)
G_RUNTIME_WRAP := -Wl,--wrap=sle_pair_run_work,--wrap=pthread_create
RADIO_WRAP := -Wl,--wrap=ioctl,--wrap=pthread_create,--wrap=pthread_join
G_APP_SYMBOLS := sle_iio_now_ns sle_iio_realtime sle_rt_radio_now sle_rt_radio_retune sle_rt_radio_submit sle_rt_ring_pop sle_rt_radio_setup sle_rt_radio_start sle_rt_radio_stop sle_rt_radio_restore
G_APP_WRAP := $(foreach sym,$(G_APP_SYMBOLS),-Wl,--wrap=$(sym))

# Unmodified upstream Mbed TLS with the project's minimal configuration.
MBEDTLS_DIR ?= ../deps/mbedtls-3.6.7
MBEDTLS_SRC := aes.c cipher.c cipher_wrap.c cmac.c ccm.c bignum.c bignum_core.c \
	constant_time.c ecp.c ecp_curves.c ecdh.c platform_util.c
MBEDTLS_CFLAGS = -I. -I$(MBEDTLS_DIR)/include -I$(MBEDTLS_DIR)/library \
	-DMBEDTLS_CONFIG_FILE='"sle_mbedtls_config.h"'

.DEFAULT_GOAL := all
RUNTIME_NAMES := sle_gnode sle_tnode
TEST_NAMES := test_sle_phy test_sle_demod test_sle_access test_sle_link test_sle_gfsk \
	test_sle_ssap test_sle_sdu test_sle_pair test_crypto_synthetic \
	test_sle_radio_core test_sle_radio test_sle_gnode test_sle_g_runtime \
	test_sle_t_protocol test_sle_t_wave test_sle_tnode
.PHONY: all runtime host arm test test-c test-oracles pair-xcheck selftest test-arm clean FORCE
all runtime host: $(addprefix build/,$(RUNTIME_NAMES))
arm: $(addprefix build-armv7/,$(RUNTIME_NAMES))
test-c: $(addprefix build/,$(TEST_NAMES))
	@set -e; for test in $(TEST_NAMES); do ./build/$$test; done
test-oracles pair-xcheck:
	$(PAIR_PYTHON) -B ../tests/gen_pair_vectors.py --check
test: test-c test-oracles
selftest: build/test_sle_radio_core
	./build/test_sle_radio_core
test-arm: $(addprefix build-armv7/,$(TEST_NAMES)) build-armv7/test_sle_demod_neon
	@mkdir -p build
	@set -e; for test in $(TEST_NAMES) test_sle_demod_neon; do $(QEMU_ARM) build-armv7/$$test; done
clean:
	rm -rf build build-armv7

# Avoid stale ARM outputs after compiler/flags changes.
build-armv7/.arm-build-flags: FORCE
	@mkdir -p $(@D)
	@printf '%s\n' '$(ARM_CC)' '$(ARM_BASE_CFLAGS)' '$(LDLIBS)' '$(MBEDTLS_CFLAGS)' > $@.tmp
	@cmp -s $@.tmp $@ || mv $@.tmp $@
	@rm -f $@.tmp

# One rule set for host and ARM; test bodies never enter runtime links.
define platform_rules
$(1)/mbedtls/%.o: $(MBEDTLS_DIR)/library/%.c sle_mbedtls_config.h $(4)
	@mkdir -p $$(@D)
	$(2) $(3) $(MBEDTLS_CFLAGS) -c $$< -o $$@
$(1)/libsle_mbedcrypto.a: $(addprefix $(1)/mbedtls/,$(MBEDTLS_SRC:.c=.o))
	rm -f $$@
	$(5) rcs $$@ $$^
endef
$(eval $(call platform_rules,build,$(CC),$(CFLAGS),,$(AR)))
$(eval $(call platform_rules,build-armv7,$(ARM_CC),$(ARM_BASE_CFLAGS),build-armv7/.arm-build-flags,$(ARM_AR)))

# name, sources, extra flags, crypto (yes/empty), extra dependencies
comma := ,
define executable
build/$(1): $(2) $(HEADERS) $(if $(4),build/libsle_mbedcrypto.a) $(5) Makefile
	@mkdir -p $$(@D)
	$(CC) $(CFLAGS) $(MBEDTLS_CFLAGS) -pthread $(3) -o $$@ $(2) $(if $(4),build/libsle_mbedcrypto.a) $(LDLIBS)
build-armv7/$(1): $(2) $(HEADERS) $(if $(4),build-armv7/libsle_mbedcrypto.a) $(5) build-armv7/.arm-build-flags Makefile
	@mkdir -p $$(@D)
	$(ARM_CC) $(ARM_BASE_CFLAGS) $(MBEDTLS_CFLAGS) -pthread $(3) -o $$@ $(2) $(if $(4),build-armv7/libsle_mbedcrypto.a) $(LDLIBS)
endef
$(eval $(call executable,sle_gnode,$(RADIO_SRC) $(G_SRC) sle_iio.c sle_gnode.c,,yes))
$(eval $(call executable,sle_tnode,$(RADIO_SRC) $(G_SRC) $(T_SRC) sle_iio.c sle_tnode.c,,yes))
$(foreach name,phy demod access link gfsk,$(eval $(call executable,test_sle_$(name),$(LIB_SRC) ../tests/test_sle_$(name).c)))
$(foreach name,ssap sdu,$(eval $(call executable,test_sle_$(name),sle_$(name).c ../tests/test_sle_$(name).c)))
$(eval $(call executable,test_sle_pair,sle_pair.c sle_crypto.c ../tests/test_sle_pair.c,,yes))
$(eval $(call executable,test_crypto_synthetic,sle_crypto.c ../tests/test_crypto_synthetic.c,,yes))
$(eval $(call executable,test_sle_radio_core,$(RADIO_SRC) sle_iio.c ../tests/test_sle_radio_core.c,,,$(TEST_HEADERS)))
$(eval $(call executable,test_sle_radio,$(RADIO_SRC) ../tests/test_sle_radio.c,$(RADIO_WRAP)))
$(eval $(call executable,test_sle_gnode,$(RADIO_SRC) $(G_SRC) sle_iio.c ../tests/test_sle_gnode.c,$(G_APP_WRAP),yes,sle_gnode.c $(TEST_HEADERS)))
$(eval $(call executable,test_sle_g_runtime,$(G_RUNTIME_SRC) ../tests/test_sle_g_runtime.c,$(G_RUNTIME_WRAP),yes))
$(eval $(call executable,test_sle_t_protocol,$(G_RUNTIME_SRC) $(T_SRC) sle_ssap.c ../tests/test_sle_t_protocol.c,,yes))
$(eval $(call executable,test_sle_t_wave,$(LIB_SRC) sle_radio_core.c sle_t_wave.c ../tests/test_sle_t_wave.c))
$(eval $(call executable,test_sle_tnode,$(RADIO_SRC) sle_t_wave.c ../tests/test_sle_tnode.c,-ffunction-sections -fdata-sections -Wl$(comma)--gc-sections,,sle_tnode.c sle_ssap_server.c sle_cmtc.c))

# Exercise the retained vectorized DSP implementation under ARM QEMU.
build-armv7/test_sle_demod_neon: $(LIB_SRC) $(HEADERS) ../tests/test_sle_demod.c build-armv7/.arm-build-flags Makefile
	@mkdir -p $(@D)
	$(ARM_CC) $(ARM_BASE_CFLAGS) -I. -DSLE_DEMOD_NEON_FIR=1 -o $@ $(LIB_SRC) ../tests/test_sle_demod.c $(LDLIBS)
