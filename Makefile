# =========================================================================
# PQ-TLS Server — Production Makefile
# =========================================================================
# Uses vendored liboqs from vendor/liboqs/ (architected by Vamshi Krishna).
# System OpenSSL (libssl-dev) is used via pkg-config / default paths.
# =========================================================================

PROJ     := $(shell pwd)
BUILDDIR := $(PROJ)/build

CC       := gcc
CFLAGS   := -std=c11 -Wall -Wextra -O2 -fPIC -fstack-protector-strong
CFLAGS   += -D_GNU_SOURCE

# Vendor paths (liboqs only — OpenSSL comes from system libssl-dev)
OQS_INC     := $(PROJ)/vendor/liboqs/include
OQS_LIB     := $(PROJ)/vendor/liboqs/lib

INCLUDES := -I$(PROJ)/src/common \
            -I$(PROJ)/src/core \
            -I$(PROJ)/src/http \
            -I$(PROJ)/src/proxy \
            -I$(PROJ)/src/dashboard \
            -I$(PROJ)/src/mgmt \
            -I$(PROJ)/src/metrics \
            -I$(PROJ)/src/security \
            -I$(PROJ)/src/benchmark \
            -I$(OQS_INC)

LDFLAGS  := -L$(OQS_LIB) -Wl,-rpath,$(OQS_LIB)
LIBS     := -lssl -lcrypto -loqs -lpthread -lm -ldl

# =========================================================================
# Source files
# =========================================================================

COMMON_SRCS := $(wildcard $(PROJ)/src/common/*.c)
CORE_SRCS   := $(PROJ)/src/core/server_config.c \
               $(PROJ)/src/core/connection_manager.c \
               $(PROJ)/src/core/epoll_reactor.c \
               $(PROJ)/src/core/graceful_drain.c \
               $(PROJ)/src/core/master_worker.c
HTTP_SRCS   := $(wildcard $(PROJ)/src/http/*.c)
PROXY_SRCS  := $(PROJ)/src/proxy/http_proxy.c
DASH_SRCS   := $(PROJ)/src/dashboard/dashboard.c
MGMT_SRCS   := $(PROJ)/src/mgmt/mgmt_server.c \
               $(PROJ)/src/mgmt/mgmt_auth.c \
               $(PROJ)/src/mgmt/mgmt_api.c \
               $(PROJ)/src/mgmt/config_writer.c \
               $(PROJ)/src/mgmt/json_helpers.c \
               $(PROJ)/src/mgmt/cert_manager.c \
               $(PROJ)/src/mgmt/log_streamer.c \
               $(PROJ)/src/mgmt/static_assets.c
METRIC_SRCS := $(PROJ)/src/metrics/prometheus.c
SEC_SRCS    := $(wildcard $(PROJ)/src/security/*.c)
BENCH_SRCS  := $(PROJ)/src/benchmark/bench.c \
               $(PROJ)/src/benchmark/bench_agility.c
MAIN_SRC    := $(wildcard $(PROJ)/src/server/*.c)

ALL_SRCS    := $(COMMON_SRCS) $(CORE_SRCS) $(HTTP_SRCS) $(PROXY_SRCS) \
               $(DASH_SRCS) $(MGMT_SRCS) $(METRIC_SRCS) $(SEC_SRCS) $(BENCH_SRCS) $(MAIN_SRC)
ALL_OBJS    := $(patsubst $(PROJ)/%.c,$(BUILDDIR)/%.o,$(ALL_SRCS))

# Test sources (exclude standalone test binaries that have their own main)
TEST_SRCS   := $(filter-out $(PROJ)/tests/test_crypto_registry.c,$(wildcard $(PROJ)/tests/*.c))
TEST_MOD_SRCS := $(PROJ)/src/http/http_parser.c \
                 $(PROJ)/src/http/conn_pool.c \
                 $(PROJ)/src/http/h2_frame.c \
                 $(PROJ)/src/http/hpack.c \
                 $(PROJ)/src/core/epoll_reactor.c \
                 $(PROJ)/src/security/rate_limiter.c \
                 $(PROJ)/src/security/acl.c
TEST_ALL_SRCS := $(TEST_SRCS) $(TEST_MOD_SRCS)
TEST_OBJS    := $(patsubst $(PROJ)/%.c,$(BUILDDIR)/%.o,$(TEST_ALL_SRCS))

# =========================================================================
# Targets
# =========================================================================

# Crypto-agility registry test sources
REGISTRY_TEST_SRCS := $(PROJ)/tests/test_crypto_registry.c
REGISTRY_TEST_MOD_SRCS := $(wildcard $(PROJ)/src/common/*.c) \
                          $(PROJ)/src/benchmark/bench_agility.c
REGISTRY_TEST_ALL := $(REGISTRY_TEST_SRCS) $(REGISTRY_TEST_MOD_SRCS)
REGISTRY_TEST_OBJS := $(patsubst $(PROJ)/%.c,$(BUILDDIR)/%.o,$(REGISTRY_TEST_ALL))

# Benchmark runner sources
BENCH_RUNNER_SRC := $(PROJ)/src/benchmark/bench_runner.c
BENCH_RUNNER_MOD := $(wildcard $(PROJ)/src/common/*.c) \
                    $(PROJ)/src/benchmark/bench_agility.c
BENCH_RUNNER_ALL := $(BENCH_RUNNER_SRC) $(BENCH_RUNNER_MOD)
BENCH_RUNNER_OBJS := $(patsubst $(PROJ)/%.c,$(BUILDDIR)/%.o,$(BENCH_RUNNER_ALL))

# HQC plugin (shared library)
HQC_PLUGIN_SRC := $(PROJ)/src/common/kem_hqc.c
HQC_PLUGIN_OBJ := $(BUILDDIR)/src/common/kem_hqc_plugin.o

.PHONY: all clean test server tests embed bench test-registry hqc-plugin

all: server tests

server: $(BUILDDIR)/bin/pq-tls-server

tests: $(BUILDDIR)/bin/pq-tls-tests

$(BUILDDIR)/bin/pq-tls-server: $(ALL_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)
	@echo "=== Built: pq-tls-server ==="

$(BUILDDIR)/bin/pq-tls-tests: $(TEST_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto -lpthread
	@echo "=== Built: pq-tls-tests ==="

$(BUILDDIR)/%.o: $(PROJ)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

test: tests
	@echo ""
	@echo "=== Running Test Suite ==="
	LD_LIBRARY_PATH=$(OQS_LIB) $(BUILDDIR)/bin/pq-tls-tests

clean:
	rm -rf $(BUILDDIR)

bench: $(BUILDDIR)/bin/bench_runner

$(BUILDDIR)/bin/bench_runner: $(BENCH_RUNNER_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS) -ldl
	@echo "=== Built: bench_runner ==="

test-registry: $(BUILDDIR)/bin/test_crypto_registry
	@echo ""
	@echo "=== Running Crypto-Agility Registry Tests ==="
	LD_LIBRARY_PATH=$(OQS_LIB) $(BUILDDIR)/bin/test_crypto_registry

$(BUILDDIR)/bin/test_crypto_registry: $(REGISTRY_TEST_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS) -ldl
	@echo "=== Built: test_crypto_registry ==="

hqc-plugin: $(BUILDDIR)/lib/pq_hqc_provider.so

$(BUILDDIR)/lib/pq_hqc_provider.so: $(HQC_PLUGIN_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -shared -o $@ $< $(LDFLAGS) -loqs
	@echo "=== Built: pq_hqc_provider.so (plugin) ==="

embed:
	bash $(PROJ)/tools/embed_assets.sh

help:
	@echo "Targets:"
	@echo "  all      Build server and tests"
	@echo "  server   Build pq-tls-server binary"
	@echo "  tests    Build test binary"
	@echo "  test     Build and run tests"
	@echo "  embed    Embed frontend assets into binary"
	@echo "  bench    Build benchmark runner"
	@echo "  test-registry  Build and run crypto-agility registry tests"
	@echo "  hqc-plugin     Build HQC plugin shared library"
	@echo "  clean    Remove build artifacts"
