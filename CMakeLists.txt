# =========================================================================
# PQ-TLS Server — Post-Quantum TLS Termination Reverse Proxy
# Production Architecture v2.0
# =========================================================================

cmake_minimum_required(VERSION 3.16)
project(pq-tls-server VERSION 2.2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# =========================================================================
# Compiler Flags
# =========================================================================

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=2 -Wformat-security")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# =========================================================================
# Dependencies
# =========================================================================

find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

# liboqs — prefer vendored build, then fall back to system paths
find_library(OQS_LIBRARY NAMES oqs
    PATHS ${CMAKE_SOURCE_DIR}/vendor/liboqs/lib
    NO_DEFAULT_PATH
)
if(NOT OQS_LIBRARY)
    find_library(OQS_LIBRARY NAMES oqs)
endif()

find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h
    PATHS ${CMAKE_SOURCE_DIR}/vendor/liboqs/include
    NO_DEFAULT_PATH
)
if(NOT OQS_INCLUDE_DIR)
    find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h)
endif()

if(OQS_LIBRARY AND OQS_INCLUDE_DIR)
    message(STATUS "liboqs: ${OQS_LIBRARY}")
    message(STATUS "liboqs include: ${OQS_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "liboqs not found. Install liboqs or set OQS_LIBRARY/OQS_INCLUDE_DIR.")
endif()

message(STATUS "OpenSSL: ${OPENSSL_VERSION}")

# =========================================================================
# Source Files
# =========================================================================

set(COMMON_SOURCES
    src/common/pq_errors.c
    src/common/pq_utils.c
    src/common/pq_utils_extra.c
    src/common/pq_kem.c
    src/common/pq_sig.c
    src/common/hpke.c
    src/common/hybrid_kex.c
    src/common/pq_config.c
    src/common/crypto_registry.c
    src/common/crypto_builtins.c
    src/common/kem_mlkem.c
    src/common/kem_classical.c
    src/common/kem_hqc.c
    src/common/sig_providers.c
    src/common/hybrid_combiner.c
)

set(CORE_SOURCES
    src/core/server_config.c
    src/core/connection_manager.c
    src/core/epoll_reactor.c
    src/core/graceful_drain.c
    src/core/master_worker.c
)

set(HTTP_SOURCES
    src/http/http_parser.c
    src/http/conn_pool.c
    src/http/h2_frame.c
    src/http/hpack.c
)

set(PROXY_SOURCES
    src/proxy/http_proxy.c
)

set(DASHBOARD_SOURCES
    src/dashboard/dashboard.c
)

set(MGMT_SOURCES
    src/mgmt/mgmt_server.c
    src/mgmt/mgmt_auth.c
    src/mgmt/mgmt_api.c
    src/mgmt/config_writer.c
    src/mgmt/json_helpers.c
    src/mgmt/cert_manager.c
    src/mgmt/log_streamer.c
    src/mgmt/static_assets.c
)

set(METRICS_SOURCES
    src/metrics/prometheus.c
)

set(SECURITY_SOURCES
    src/security/rate_limiter.c
    src/security/acl.c
)

set(BENCHMARK_SOURCES
    src/benchmark/bench.c
    src/benchmark/bench_agility.c
)

set(SERVER_SOURCES
    src/server/main.c
)

# =========================================================================
# Build — Main Server
# =========================================================================

# PQ crypto library
add_library(pq_common STATIC ${COMMON_SOURCES})
target_include_directories(pq_common PUBLIC
    ${CMAKE_SOURCE_DIR}/src/common
    ${OQS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(pq_common PUBLIC
    ${OQS_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
    m
    dl
)

# Main server binary
add_executable(pq-tls-server
    ${SERVER_SOURCES}
    ${CORE_SOURCES}
    ${HTTP_SOURCES}
    ${PROXY_SOURCES}
    ${DASHBOARD_SOURCES}
    ${MGMT_SOURCES}
    ${METRICS_SOURCES}
    ${SECURITY_SOURCES}
    ${BENCHMARK_SOURCES}
)

target_include_directories(pq-tls-server PRIVATE
    ${CMAKE_SOURCE_DIR}/src/common
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/http
    ${CMAKE_SOURCE_DIR}/src/proxy
    ${CMAKE_SOURCE_DIR}/src/dashboard
    ${CMAKE_SOURCE_DIR}/src/mgmt
    ${CMAKE_SOURCE_DIR}/src/metrics
    ${CMAKE_SOURCE_DIR}/src/security
    ${CMAKE_SOURCE_DIR}/src/benchmark
    ${OQS_INCLUDE_DIR}
)

# Optional: embed frontend assets before building
add_custom_target(embed_assets
    COMMAND bash ${CMAKE_SOURCE_DIR}/tools/embed_assets.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Embedding frontend static assets"
)

target_link_libraries(pq-tls-server PRIVATE
    pq_common
    Threads::Threads
)

set_target_properties(pq-tls-server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# RPATH for finding vendored liboqs at runtime
set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
set(CMAKE_BUILD_RPATH "${CMAKE_SOURCE_DIR}/vendor/liboqs/lib")

# =========================================================================
# Build — Test Suite
# =========================================================================

enable_testing()

add_executable(pq-tls-tests
    tests/test_main.c
    tests/test_http_parser.c
    tests/test_conn_pool.c
    tests/test_h2_frame.c
    tests/test_epoll_reactor.c
    tests/test_rate_limiter.c
    tests/test_acl.c
    # Dependencies for the modules under test
    src/http/http_parser.c
    src/http/conn_pool.c
    src/http/h2_frame.c
    src/http/hpack.c
    src/core/epoll_reactor.c
    src/security/rate_limiter.c
    src/security/acl.c
)

target_include_directories(pq-tls-tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/common
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src/http
    ${CMAKE_SOURCE_DIR}/src/proxy
    ${CMAKE_SOURCE_DIR}/src/dashboard
    ${CMAKE_SOURCE_DIR}/src/metrics
    ${CMAKE_SOURCE_DIR}/src/security
    ${CMAKE_SOURCE_DIR}/src/benchmark
    ${OPENSSL_INCLUDE_DIR}
    ${OQS_INCLUDE_DIR}
)

target_link_libraries(pq-tls-tests PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

set_target_properties(pq-tls-tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_test(NAME pq-tls-tests COMMAND pq-tls-tests)

# =========================================================================
# Install
# =========================================================================

install(TARGETS pq-tls-server
    RUNTIME DESTINATION bin
)

install(TARGETS pq_common
    ARCHIVE DESTINATION lib
)

install(DIRECTORY src/common/
    DESTINATION include/pq-tls
    FILES_MATCHING PATTERN "*.h"
)

install(FILES etc/pq-tls-server.conf
    DESTINATION /etc/pq-tls-server
    COMPONENT config
)

# =========================================================================
# Summary
# =========================================================================

message(STATUS "")
message(STATUS "=== PQ-TLS Server v${PROJECT_VERSION} — Production Architecture ===")
message(STATUS "  OpenSSL:    ${OPENSSL_VERSION}")
message(STATUS "  liboqs:     ${OQS_LIBRARY}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install:    ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Modules:    core http proxy dashboard mgmt metrics security benchmark")
message(STATUS "  New:        crypto-agility registry plugin-loader hybrid-combiner")
message(STATUS "              bench-agility bench-runner")
message(STATUS "  Tests:      52 test cases across 7 modules")
message(STATUS "")
