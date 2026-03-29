/**
 * @file connection_manager.c
 * @brief Multi-client PQ-TLS connection manager
 *
 * Architecture:
 *   - Worker threads accept and handle connections independently via SO_REUSEPORT.
 *   - Each worker: accept() -> ACL check -> rate limit -> TLS handshake ->
 *     PQ detection -> weighted upstream select -> bidirectional proxy -> cleanup.
 *   - SSL_CTX is protected by a read-write lock for safe SIGHUP hot-reload.
 *
 * @author Vamshi Krishna Doddikadi
 */

#include "connection_manager.h"
#include "../proxy/http_proxy.h"
#include "../dashboard/dashboard.h"
#include "../mgmt/mgmt_server.h"
#include "../security/rate_limiter.h"
#include "../security/acl.h"
#include "../common/crypto_registry.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <libgen.h>
#include <pthread.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* ======================================================================== */
/* Logging helpers                                                          */
/* ======================================================================== */

static const char *level_str[] = {"DEBUG", "INFO", "WARN", "ERROR"};

#define LOG(mgr, lvl, fmt, ...) do {                                       \
    if ((lvl) >= (mgr)->config->log_level) {                               \
        pthread_mutex_lock(&(mgr)->log_mutex);                             \
        time_t _now = time(NULL);                                          \
        struct tm _tm; localtime_r(&_now, &_tm);                           \
        char _ts[32];                                                      \
        strftime(_ts, sizeof(_ts), "%Y-%m-%d %H:%M:%S", &_tm);            \
        if ((mgr)->json_logging) {                                         \
            fprintf((mgr)->log_fp,                                          \
                "{\"ts\":\"%s\",\"level\":\"%s\",\"msg\":\"" fmt "\"}\n",   \
                _ts, level_str[(lvl) < 4 ? (lvl) : 3], ##__VA_ARGS__);    \
        } else {                                                           \
            fprintf((mgr)->log_fp, "[%s] [%s] " fmt "\n",                  \
                    _ts, level_str[(lvl) < 4 ? (lvl) : 3], ##__VA_ARGS__);\
        }                                                                  \
        fflush((mgr)->log_fp);                                             \
        pthread_mutex_unlock(&(mgr)->log_mutex);                           \
    }                                                                      \
} while(0)

#define LOG_DEBUG(mgr, fmt, ...) LOG(mgr, 0, fmt, ##__VA_ARGS__)
#define LOG_INFO(mgr, fmt, ...)  LOG(mgr, 1, fmt, ##__VA_ARGS__)
#define LOG_WARN(mgr, fmt, ...)  LOG(mgr, 2, fmt, ##__VA_ARGS__)
#define LOG_ERROR(mgr, fmt, ...) LOG(mgr, 3, fmt, ##__VA_ARGS__)

/* ======================================================================== */
/* OQS provider auto-detection                                              */
/* ======================================================================== */

static void setup_oqs_provider_path(void) {
    const char *existing = getenv("OPENSSL_MODULES");
    if (existing) {
        char check[PATH_MAX];
        snprintf(check, sizeof(check), "%s/oqsprovider.so", existing);
        if (access(check, R_OK) == 0) return;
    }

    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len < 0) return;
    exe_path[len] = '\0';

    char copy1[PATH_MAX], copy2[PATH_MAX], copy3[PATH_MAX];
    strncpy(copy1, exe_path, PATH_MAX - 1);  copy1[PATH_MAX-1] = '\0';
    char *bin_dir = dirname(copy1);
    strncpy(copy2, bin_dir,  PATH_MAX - 1);  copy2[PATH_MAX-1] = '\0';
    char *build_dir = dirname(copy2);
    strncpy(copy3, build_dir, PATH_MAX - 1); copy3[PATH_MAX-1] = '\0';
    char *root = dirname(copy3);

    const char *suffixes[] = {
        "/vendor/oqs-provider/build/lib",
        "/vendor/lib64/ossl-modules",
        "/vendor/openssl/lib64/ossl-modules",
        "/vendor/openssl/lib/ossl-modules",
        "/lib/ossl-modules",
        "/usr/lib/x86_64-linux-gnu/ossl-modules",
        "/usr/lib64/ossl-modules",
        NULL
    };

    char path[PATH_MAX], provider[PATH_MAX + 20];
    for (int i = 0; suffixes[i]; i++) {
        snprintf(path, sizeof(path), "%s%s", root, suffixes[i]);
        snprintf(provider, sizeof(provider), "%s/oqsprovider.so", path);
        if (access(provider, R_OK) == 0) {
            setenv("OPENSSL_MODULES", path, 1);
            return;
        }
    }

    const char *sys_paths[] = {
        "/usr/lib/x86_64-linux-gnu/ossl-modules",
        "/usr/lib64/ossl-modules",
        "/usr/local/lib64/ossl-modules",
        "/usr/local/lib/ossl-modules",
        NULL
    };
    for (int i = 0; sys_paths[i]; i++) {
        snprintf(provider, sizeof(provider), "%s/oqsprovider.so", sys_paths[i]);
        if (access(provider, R_OK) == 0) {
            setenv("OPENSSL_MODULES", sys_paths[i], 1);
            return;
        }
    }
}

/* ======================================================================== */
/* SSL context setup                                                        */
/* ======================================================================== */

static SSL_CTX* create_ssl_ctx(pq_conn_manager_t *mgr) {
    const pq_server_config_t *cfg = mgr->config;

    setup_oqs_provider_path();

    mgr->default_provider = OSSL_PROVIDER_load(NULL, "default");
    mgr->oqs_provider     = OSSL_PROVIDER_load(NULL, "oqsprovider");

    if (!mgr->default_provider) {
        fprintf(stderr, "Failed to load OpenSSL default provider\n");
        if (mgr->oqs_provider) OSSL_PROVIDER_unload(mgr->oqs_provider);
        mgr->oqs_provider = NULL;
        return NULL;
    }
    if (!mgr->oqs_provider) {
        fprintf(stderr, "Warning: OQS provider not loaded — post-quantum groups unavailable\n");
        fprintf(stderr, "  OPENSSL_MODULES=%s\n", getenv("OPENSSL_MODULES") ?: "(not set)");
        fprintf(stderr, "  Continuing with classical TLS only.\n");
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        if (mgr->oqs_provider) OSSL_PROVIDER_unload(mgr->oqs_provider);
        if (mgr->default_provider) OSSL_PROVIDER_unload(mgr->default_provider);
        mgr->oqs_provider = NULL;
        mgr->default_provider = NULL;
        return NULL;
    }

    int min_ver = (cfg->tls_min_version == 0x0303) ? TLS1_2_VERSION : TLS1_3_VERSION;
    SSL_CTX_set_min_proto_version(ctx, min_ver);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Security Hardening: Disable legacy protocols, renegotiation, and compression.
       Only disable TLS 1.2 when min_version is TLS 1.3 — otherwise the config
       option to allow TLS 1.2 would be silently broken. */
    {
        long opts = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
                  | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION;
        if (min_ver > TLS1_2_VERSION)
            opts |= SSL_OP_NO_TLSv1_2;
        if (cfg->tls_groups[0] &&
            (strstr(cfg->tls_groups, "MLKEM") || strstr(cfg->tls_groups, "Kyber")))
            opts |= SSL_OP_NO_TICKET;
        SSL_CTX_set_options(ctx, opts);
    }

    /* Crypto-agility: use registry-generated groups if available,
     * otherwise fall back to config-specified groups string */
    {
        char registry_groups[PQ_MAX_GROUPS];
        const char *groups_to_use = cfg->tls_groups;

        if (mgr->crypto_registry) {
            int glen = pq_registry_generate_groups_string(
                mgr->crypto_registry, registry_groups, sizeof(registry_groups));
            if (glen > 0) {
                groups_to_use = registry_groups;
                LOG_INFO(mgr, "Crypto-agility: using registry groups: %s", registry_groups);
            }
        }

        if (groups_to_use[0] && SSL_CTX_set1_groups_list(ctx, groups_to_use) != 1) {
            fprintf(stderr, "Warning: failed to set groups '%s', falling back to defaults\n",
                    groups_to_use);
        }
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cfg->cert_file) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, cfg->key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        if (mgr->oqs_provider) OSSL_PROVIDER_unload(mgr->oqs_provider);
        if (mgr->default_provider) OSSL_PROVIDER_unload(mgr->default_provider);
        mgr->oqs_provider = NULL;
        mgr->default_provider = NULL;
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Private key does not match certificate\n");
        SSL_CTX_free(ctx);
        if (mgr->oqs_provider) OSSL_PROVIDER_unload(mgr->oqs_provider);
        if (mgr->default_provider) OSSL_PROVIDER_unload(mgr->default_provider);
        mgr->oqs_provider = NULL;
        mgr->default_provider = NULL;
        return NULL;
    }

    if (cfg->require_client_auth) {
        if (SSL_CTX_load_verify_locations(ctx, cfg->ca_file, NULL) != 1) {
            fprintf(stderr, "Failed to load CA file: %s\n", cfg->ca_file);
            SSL_CTX_free(ctx);
            if (mgr->oqs_provider) OSSL_PROVIDER_unload(mgr->oqs_provider);
            if (mgr->default_provider) OSSL_PROVIDER_unload(mgr->default_provider);
            mgr->oqs_provider = NULL;
            mgr->default_provider = NULL;
            return NULL;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(ctx, 4);
    }

    /* TLS Optimization: Memory efficiency for idle connections and buffer management */
    /* Enable release of internal buffers when not needed, reducing per-connection
       memory from ~34KB to ~1KB when idle. */
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    /* Enable moving write buffer support for scatter-gather I/O */
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    /* Optimize fragment size for PQ certificates which are typically larger */
    SSL_CTX_set_max_send_fragment(ctx, 16384);

    /* TLS session resumption — server-side session cache */
    if (cfg->session_cache_size > 0) {
        SSL_CTX_set_session_cache_mode(ctx,
            SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP);
        SSL_CTX_sess_set_cache_size(ctx, (unsigned long)cfg->session_cache_size);
        SSL_CTX_set_timeout(ctx, 3600);
    }

    return ctx;
}

/**
 * Create a fresh SSL_CTX for hot-reload (does NOT touch providers).
 */
static SSL_CTX* create_ssl_ctx_reload(const pq_server_config_t *cfg) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return NULL; }

    int min_ver = (cfg->tls_min_version == 0x0303) ? TLS1_2_VERSION : TLS1_3_VERSION;
    SSL_CTX_set_min_proto_version(ctx, min_ver);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Security Hardening — same logic as create_ssl_ctx() */
    {
        long opts = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1
                  | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION;
        if (min_ver > TLS1_2_VERSION)
            opts |= SSL_OP_NO_TLSv1_2;
        if (cfg->tls_groups[0] &&
            (strstr(cfg->tls_groups, "MLKEM") || strstr(cfg->tls_groups, "Kyber")))
            opts |= SSL_OP_NO_TICKET;
        SSL_CTX_set_options(ctx, opts);
    }

    if (cfg->tls_groups[0])
        SSL_CTX_set1_groups_list(ctx, cfg->tls_groups);

    if (SSL_CTX_use_certificate_chain_file(ctx, cfg->cert_file) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, cfg->key_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (cfg->require_client_auth) {
        if (SSL_CTX_load_verify_locations(ctx, cfg->ca_file, NULL) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(ctx, 4);
    }

    /* TLS Optimization: Memory efficiency and buffer management */
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_max_send_fragment(ctx, 16384);

    if (cfg->session_cache_size > 0) {
        SSL_CTX_set_session_cache_mode(ctx,
            SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP);
        SSL_CTX_sess_set_cache_size(ctx, (unsigned long)cfg->session_cache_size);
        SSL_CTX_set_timeout(ctx, 3600);
    }

    return ctx;
}

/* ======================================================================== */
/* Listening socket                                                         */
/* ======================================================================== */

static int create_listen_socket(const pq_server_config_t *cfg) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(cfg->listen_port);
    inet_pton(AF_INET, cfg->bind_address, &addr.sin_addr);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    if (listen(fd, 512) < 0) {
        perror("listen"); close(fd); return -1;
    }
    return fd;
}

/* ======================================================================== */
/* Weighted round-robin load balancing with health checks                   */
/* ======================================================================== */

/**
 * Weighted round-robin upstream selection.
 * Skips backends marked unhealthy by the health-check thread.
 */
static int pick_upstream(pq_conn_manager_t *mgr) {
    static atomic_int rr_counter = 0;
    int n = mgr->config->upstream_count;
    if (n <= 0) return -1; /* No upstreams — caller must handle */

    int total_weight = 0;
    for (int i = 0; i < n; i++) {
        if (atomic_load(&mgr->upstream_healthy[i]))
            total_weight += mgr->config->upstreams[i].weight;
    }
    if (total_weight == 0) {
        /* All unhealthy — fall back to simple round-robin */
        return atomic_fetch_add(&rr_counter, 1) % n;
    }

    int target = atomic_fetch_add(&rr_counter, 1) % total_weight;
    int cumulative = 0;
    for (int i = 0; i < n; i++) {
        if (!atomic_load(&mgr->upstream_healthy[i])) continue;
        cumulative += mgr->config->upstreams[i].weight;
        if (target < cumulative) return i;
    }
    return 0;
}

/**
 * Health check thread — periodically probes backends with TCP connect.
 */
static void* health_check_thread(void *arg) {
    pq_conn_manager_t *mgr = (pq_conn_manager_t*)arg;
    const int interval_sec = 10;

    while (atomic_load(&mgr->running)) {
        for (int i = 0; i < mgr->config->upstream_count; i++) {
            const pq_upstream_t *up = &mgr->config->upstreams[i];

            /* Unix socket backends — always considered healthy */
            if (strncmp(up->host, "unix:", 5) == 0) {
                atomic_store(&mgr->upstream_healthy[i], 1);
                continue;
            }

            int fd = pq_proxy_connect_upstream(up->host, up->port, 2000);
            if (fd >= 0) {
                close(fd);
                if (!atomic_load(&mgr->upstream_healthy[i])) {
                    LOG_INFO(mgr, "Backend %s:%u is now UP", up->host, up->port);
                }
                atomic_store(&mgr->upstream_healthy[i], 1);
            } else {
                if (atomic_load(&mgr->upstream_healthy[i])) {
                    LOG_WARN(mgr, "Backend %s:%u is DOWN", up->host, up->port);
                }
                atomic_store(&mgr->upstream_healthy[i], 0);
            }
        }

        /* Periodic rate limiter cleanup */
        pq_rate_limiter_cleanup();

        for (int s = 0; s < interval_sec && atomic_load(&mgr->running); s++)
            sleep(1);
    }
    return NULL;
}

/* ======================================================================== */
/* Unix socket connect helper                                               */
/* ======================================================================== */

static int connect_unix_socket(const char *path, int timeout_ms) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) { close(fd); return -1; }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret == 0) {
        fcntl(fd, F_SETFL, flags); /* restore blocking */
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) { close(fd); return -1; }

    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err != 0) { close(fd); return -1; }

    fcntl(fd, F_SETFL, flags); /* restore blocking */
    return fd;
}

/* ======================================================================== */
/* Per-connection handler (runs in worker thread)                           */
/* ======================================================================== */

static void handle_connection(pq_conn_manager_t *mgr, int client_fd,
                              struct sockaddr_in *client_addr) {
    pq_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.client_fd  = client_fd;
    conn.backend_fd = -1;
    conn.state      = CONN_STATE_TLS_HANDSHAKE;
    clock_gettime(CLOCK_MONOTONIC, &conn.connected_at);

    if (!inet_ntop(AF_INET, &client_addr->sin_addr, conn.client_addr,
                   sizeof(conn.client_addr))) {
        snprintf(conn.client_addr, sizeof(conn.client_addr), "unknown");
    }
    conn.client_port = ntohs(client_addr->sin_port);

    /* --- ACL check --- */
    if (!pq_acl_check(conn.client_addr)) {
        LOG_DEBUG(mgr, "ACL denied connection from %s:%u",
                  conn.client_addr, conn.client_port);
        goto cleanup;
    }

    /* --- Rate limiting --- */
    if (!pq_rate_limiter_allow(conn.client_addr)) {
        atomic_fetch_add(&mgr->rate_limited_connections, 1);
        LOG_WARN(mgr, "Rate limited %s:%u", conn.client_addr, conn.client_port);
        const char *rate_resp = "HTTP/1.1 429 Too Many Requests\r\n"
                                "Content-Length: 24\r\n"
                                "Connection: close\r\n\r\n"
                                "429 Too Many Requests\r\n";
        (void)write(client_fd, rate_resp, strlen(rate_resp));
        goto cleanup;
    }

    atomic_fetch_add(&mgr->active_connections, 1);
    atomic_fetch_add(&mgr->total_connections, 1);

    LOG_DEBUG(mgr, "New connection from %s:%u (fd %d)",
              conn.client_addr, conn.client_port, client_fd);

    /* --- TLS handshake (acquire read lock for SSL_CTX access) --- */
    pthread_rwlock_rdlock(&mgr->ssl_ctx_lock);
    SSL *ssl = SSL_new(mgr->ssl_ctx);
    pthread_rwlock_unlock(&mgr->ssl_ctx_lock);

    if (!ssl) {
        LOG_ERROR(mgr, "SSL_new failed for %s:%u", conn.client_addr, conn.client_port);
        goto cleanup_active;
    }
    conn.ssl = ssl;
    SSL_set_fd(ssl, client_fd);

    struct timespec hs_start, hs_end;
    clock_gettime(CLOCK_MONOTONIC, &hs_start);

    if (SSL_accept(ssl) != 1) {
        unsigned long err = ERR_peek_last_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        LOG_WARN(mgr, "TLS handshake failed from %s:%u: %s",
                 conn.client_addr, conn.client_port, err_buf);
        atomic_fetch_add(&mgr->total_handshake_failures, 1);
        goto cleanup_active;
    }

    clock_gettime(CLOCK_MONOTONIC, &hs_end);
    double hs_ms = (double)(hs_end.tv_sec - hs_start.tv_sec) * 1000.0 +
                   (double)(hs_end.tv_nsec - hs_start.tv_nsec) / 1e6;

    conn.state = CONN_STATE_ACTIVE;

    /* Log negotiated parameters and track PQ vs classical */
    const char *proto   = SSL_get_version(ssl);
    const char *cipher  = SSL_get_cipher(ssl);
    int group_nid = SSL_get_negotiated_group(ssl);
    const char *group_name = (group_nid != 0)
        ? SSL_group_to_name(ssl, group_nid) : "unknown";

    int is_pq = 0;
    if (group_name) {
        if (strstr(group_name, "MLKEM") || strstr(group_name, "mlkem") ||
            strstr(group_name, "Kyber") || strstr(group_name, "kyber")) {
            is_pq = 1;
        }
    }
    if (is_pq) {
        atomic_fetch_add(&mgr->pq_negotiations, 1);
    } else {
        atomic_fetch_add(&mgr->classical_negotiations, 1);
    }

    LOG_INFO(mgr, "Handshake OK %s:%u  proto=%s cipher=%s group=%s pq=%s  %.1fms",
             conn.client_addr, conn.client_port,
             proto, cipher, group_name ? group_name : "N/A",
             is_pq ? "yes" : "no", hs_ms);

    /* --- Connect to upstream --- */
    int ui = pick_upstream(mgr);
    if (ui < 0 || ui >= mgr->config->upstream_count) {
        LOG_ERROR(mgr, "No valid upstream backend for %s:%u",
                  conn.client_addr, conn.client_port);
        const char *bad_gw = "HTTP/1.1 502 Bad Gateway\r\n"
                             "Content-Length: 22\r\n"
                             "Connection: close\r\n\r\n"
                             "502 No Backend Available";
        SSL_write(ssl, bad_gw, (int)strlen(bad_gw));
        goto cleanup_active;
    }

    conn.upstream_idx = ui;
    const pq_upstream_t *up = &mgr->config->upstreams[ui];

    /* Support unix socket backends (host starts with "unix:") */
    if (strncmp(up->host, "unix:", 5) == 0) {
        conn.backend_fd = connect_unix_socket(
            up->host + 5, mgr->config->upstream_connect_timeout_ms);
    } else {
        conn.backend_fd = pq_proxy_connect_upstream(
            up->host, up->port, mgr->config->upstream_connect_timeout_ms);
    }

    if (conn.backend_fd < 0) {
        LOG_ERROR(mgr, "Upstream connect failed %s:%u -> %s:%u",
                  conn.client_addr, conn.client_port, up->host, up->port);
        const char *bad_gw = "HTTP/1.1 502 Bad Gateway\r\n"
                             "Content-Length: 15\r\n"
                             "Connection: close\r\n\r\n"
                             "502 Bad Gateway";
        SSL_write(ssl, bad_gw, (int)strlen(bad_gw));
        goto cleanup_active;
    }

    LOG_DEBUG(mgr, "Upstream connected %s:%u -> %s:%u",
              conn.client_addr, conn.client_port, up->host, up->port);

    /* --- Bidirectional proxy loop --- */
    pq_proxy_info_t pq_info = {
        .group_name  = group_name ? group_name : "unknown",
        .cipher_name = cipher ? cipher : "unknown",
        .is_pq       = is_pq
    };
    pq_proxy_result_t result = pq_proxy_relay(
        ssl, conn.backend_fd, mgr->config->upstream_timeout_ms, &pq_info);

    conn.bytes_in  = result.bytes_from_client;
    conn.bytes_out = result.bytes_from_backend;
    atomic_fetch_add(&mgr->total_bytes_in,  (long)conn.bytes_in);
    atomic_fetch_add(&mgr->total_bytes_out, (long)conn.bytes_out);

    if (mgr->config->access_log) {
        LOG_INFO(mgr, "CLOSE %s:%u  upstream=%s:%u  in=%zu out=%zu",
                 conn.client_addr, conn.client_port,
                 up->host, up->port, conn.bytes_in, conn.bytes_out);
    }

cleanup_active:
    conn.state = CONN_STATE_CLOSED;
    if (conn.ssl) {
        SSL_shutdown(conn.ssl);
        SSL_free(conn.ssl);
    }
    if (conn.client_fd >= 0)  close(conn.client_fd);
    if (conn.backend_fd >= 0) close(conn.backend_fd);
    atomic_fetch_sub(&mgr->active_connections, 1);
    return;

cleanup:
    conn.state = CONN_STATE_CLOSED;
    if (conn.client_fd >= 0) close(conn.client_fd);
}

/* ======================================================================== */
/* Worker thread function                                                   */
/* ======================================================================== */

typedef struct {
    pq_conn_manager_t *mgr;
    int                thread_id;
} worker_arg_t;

static void* worker_thread(void *arg) {
    worker_arg_t *wa = (worker_arg_t*)arg;
    pq_conn_manager_t *mgr = wa->mgr;
    int tid = wa->thread_id;
    free(wa);

    LOG_DEBUG(mgr, "Worker %d started", tid);

    while (atomic_load(&mgr->running)) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(mgr->listen_fd,
                               (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            if (!atomic_load(&mgr->running)) break;
            LOG_ERROR(mgr, "Worker %d: accept failed: %s", tid, strerror(errno));
            continue;
        }

        int opt = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

        handle_connection(mgr, client_fd, &client_addr);
    }

    LOG_DEBUG(mgr, "Worker %d stopped", tid);
    return NULL;
}

/* ======================================================================== */
/* Public API                                                               */
/* ======================================================================== */

pq_conn_manager_t* pq_conn_manager_create(const pq_server_config_t *cfg) {
    pq_conn_manager_t *mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    mgr->config = cfg;
    mgr->json_logging = cfg->json_logging;
    mgr->start_time = time(NULL);
    pthread_mutex_init(&mgr->log_mutex, NULL);
    pthread_rwlock_init(&mgr->ssl_ctx_lock, NULL);

    /* Open log file */
    if (cfg->log_file[0]) {
        mgr->log_fp = fopen(cfg->log_file, "a");
        if (!mgr->log_fp) {
            fprintf(stderr, "Cannot open log file '%s': %m\n", cfg->log_file);
            goto fail_early;
        }
    } else {
        mgr->log_fp = stderr;
    }

    /* Initialize crypto-agility registry */
    mgr->crypto_registry = pq_registry_create();
    if (mgr->crypto_registry) {
        pq_registry_register_builtins(mgr->crypto_registry);
        LOG_INFO(mgr, "Crypto-agility: registered %zu KEMs, %zu SIGs",
                 pq_registry_kem_count(mgr->crypto_registry),
                 pq_registry_sig_count(mgr->crypto_registry));
    }

    /* Create SSL context */
    mgr->ssl_ctx = create_ssl_ctx(mgr);
    if (!mgr->ssl_ctx) {
        goto fail_log;
    }

    /* Create listening socket */
    mgr->listen_fd = create_listen_socket(cfg);
    if (mgr->listen_fd < 0) {
        goto fail_ssl;
    }

    /* Worker count */
    mgr->worker_count = cfg->worker_threads;
    if (mgr->worker_count <= 0) {
        mgr->worker_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (mgr->worker_count < 1) mgr->worker_count = 4;
    }

    /* Initialize rate limiter */
    if (cfg->rate_limit_per_ip > 0) {
        pq_rate_limiter_init(cfg->rate_limit_per_ip, cfg->rate_limit_burst);
        LOG_INFO(mgr, "Rate limiting: %d/s per IP, burst=%d",
                 cfg->rate_limit_per_ip, cfg->rate_limit_burst);
    }

    /* Initialize ACL */
    if (cfg->acl_mode != PQ_ACL_MODE_DISABLED) {
        pq_acl_init(cfg->acl_mode);
        for (int i = 0; i < cfg->acl_count; i++) {
            pq_acl_add(cfg->acl_entries[i]);
        }
        LOG_INFO(mgr, "ACL: mode=%s, %d entries",
                 cfg->acl_mode == PQ_ACL_MODE_ALLOWLIST ? "allowlist" : "blocklist",
                 cfg->acl_count);
    }

    /* Mark all upstreams healthy initially */
    for (int i = 0; i < cfg->upstream_count && i < PQ_MAX_UPSTREAMS; i++) {
        atomic_store(&mgr->upstream_healthy[i], 1);
    }

    LOG_INFO(mgr, "PQ-TLS Server initialized  workers=%d", mgr->worker_count);
    return mgr;

    /* Structured cleanup on failure */
fail_ssl:
    SSL_CTX_free(mgr->ssl_ctx);
fail_log:
    if (mgr->log_fp && mgr->log_fp != stderr) fclose(mgr->log_fp);
fail_early:
    pthread_rwlock_destroy(&mgr->ssl_ctx_lock);
    pthread_mutex_destroy(&mgr->log_mutex);
    free(mgr);
    return NULL;
}

int pq_conn_manager_run(pq_conn_manager_t *mgr) {
    atomic_store(&mgr->running, 1);

    /* Start management dashboard (replaces old read-only dashboard) */
    if (mgr->config->health_port > 0) {
        /* Cast away const — mgmt server needs mutable config for write-back */
        pq_server_config_t *mutable_cfg = (pq_server_config_t *)mgr->config;
        if (pq_mgmt_start(mgr, mutable_cfg, mgr->config->health_port,
                           mgr->config->config_file_path) == 0) {
            LOG_INFO(mgr, "Management dashboard on http://0.0.0.0:%d",
                     mgr->config->health_port);
        } else {
            /* Fall back to read-only dashboard */
            if (pq_dashboard_start(mgr, mgr->config->health_port) == 0) {
                LOG_INFO(mgr, "Dashboard (read-only) on http://0.0.0.0:%d",
                         mgr->config->health_port);
            }
        }
    }

    /* Start upstream health check thread */
    pthread_t hc_tid;
    if (mgr->config->upstream_count > 0) {
        if (pthread_create(&hc_tid, NULL, health_check_thread, mgr) == 0) {
            pthread_detach(hc_tid);
        } else {
            LOG_WARN(mgr, "Failed to start health check thread");
        }
    }

    /* Spawn workers */
    mgr->workers = calloc((size_t)mgr->worker_count, sizeof(pthread_t));
    if (!mgr->workers) {
        LOG_ERROR(mgr, "Failed to allocate worker thread array");
        return -1;
    }

    for (int i = 0; i < mgr->worker_count; i++) {
        worker_arg_t *wa = malloc(sizeof(*wa));
        if (!wa) {
            LOG_ERROR(mgr, "Failed to allocate worker arg for thread %d", i);
            continue;
        }
        wa->mgr = mgr;
        wa->thread_id = i;
        if (pthread_create(&mgr->workers[i], NULL, worker_thread, wa) != 0) {
            LOG_ERROR(mgr, "Failed to create worker thread %d: %s", i, strerror(errno));
            free(wa);
        }
    }

    LOG_INFO(mgr, "Listening on %s:%u  (%d workers)",
             mgr->config->bind_address, mgr->config->listen_port,
             mgr->worker_count);

    /* Wait for workers */
    for (int i = 0; i < mgr->worker_count; i++) {
        if (mgr->workers[i])
            pthread_join(mgr->workers[i], NULL);
    }

    return 0;
}

void pq_conn_manager_stop(pq_conn_manager_t *mgr) {
    if (!mgr) return;
    atomic_store(&mgr->running, 0);

    pq_mgmt_stop();
    pq_dashboard_stop();

    if (mgr->listen_fd >= 0) {
        shutdown(mgr->listen_fd, SHUT_RDWR);
    }
}

void pq_conn_manager_destroy(pq_conn_manager_t *mgr) {
    if (!mgr) return;

    pq_conn_manager_stop(mgr);

    pq_rate_limiter_destroy();
    pq_acl_destroy();

    if (mgr->listen_fd >= 0) close(mgr->listen_fd);

    pthread_rwlock_wrlock(&mgr->ssl_ctx_lock);
    if (mgr->ssl_ctx) SSL_CTX_free(mgr->ssl_ctx);
    mgr->ssl_ctx = NULL;
    pthread_rwlock_unlock(&mgr->ssl_ctx_lock);

    if (mgr->oqs_provider) OSSL_PROVIDER_unload(mgr->oqs_provider);
    if (mgr->default_provider) OSSL_PROVIDER_unload(mgr->default_provider);
    if (mgr->crypto_registry) pq_registry_destroy(mgr->crypto_registry);
    if (mgr->log_fp && mgr->log_fp != stderr) fclose(mgr->log_fp);
    free(mgr->workers);
    pthread_rwlock_destroy(&mgr->ssl_ctx_lock);
    pthread_mutex_destroy(&mgr->log_mutex);
    free(mgr);
}

int pq_conn_manager_metrics_json(const pq_conn_manager_t *mgr,
                                  char *buf, size_t len) {
    /* Note: individual atomic reads are consistent per-field but the
     * snapshot as a whole is not perfectly atomic. Acceptable for monitoring. */
    long uptime = (long)(time(NULL) - mgr->start_time);
    if (uptime < 0) uptime = 0;

    return snprintf(buf, len,
        "{"
        "\"status\":\"ok\","
        "\"total_connections\":%ld,"
        "\"active_connections\":%d,"
        "\"handshake_failures\":%ld,"
        "\"bytes_in\":%ld,"
        "\"bytes_out\":%ld,"
        "\"pq_negotiations\":%ld,"
        "\"classical_negotiations\":%ld,"
        "\"rate_limited\":%ld,"
        "\"workers\":%d,"
        "\"uptime_seconds\":%ld"
        "}",
        atomic_load(&mgr->total_connections),
        atomic_load(&mgr->active_connections),
        atomic_load(&mgr->total_handshake_failures),
        atomic_load(&mgr->total_bytes_in),
        atomic_load(&mgr->total_bytes_out),
        atomic_load(&mgr->pq_negotiations),
        atomic_load(&mgr->classical_negotiations),
        atomic_load(&mgr->rate_limited_connections),
        mgr->worker_count,
        uptime);
}

/**
 * Hot-reload TLS certificates without dropping connections.
 * Called from the reload watcher thread (NOT from a signal handler).
 *
 * Uses rwlock: existing SSL* objects have an internal refcount on their
 * parent SSL_CTX, so freeing the old CTX is safe — OpenSSL will defer
 * actual cleanup until the last SSL_free() on connections using it.
 */
int pq_conn_manager_reload(pq_conn_manager_t *mgr) {
    if (!mgr) return -1;

    LOG_INFO(mgr, "Reloading TLS certificates...");

    SSL_CTX *new_ctx = create_ssl_ctx_reload(mgr->config);
    if (!new_ctx) {
        LOG_ERROR(mgr, "Certificate reload FAILED — keeping old certificates");
        return -1;
    }

    /* Acquire write lock — blocks until all workers finish their SSL_new() */
    pthread_rwlock_wrlock(&mgr->ssl_ctx_lock);
    SSL_CTX *old_ctx = mgr->ssl_ctx;
    mgr->ssl_ctx = new_ctx;
    pthread_rwlock_unlock(&mgr->ssl_ctx_lock);

    /*
     * Safe to free: SSL_new() calls SSL_CTX_up_ref(), so existing SSL*
     * objects hold their own reference. The old CTX is only truly freed
     * when the last SSL* using it calls SSL_free().
     */
    SSL_CTX_free(old_ctx);

    LOG_INFO(mgr, "TLS certificates reloaded successfully");
    return 0;
}
