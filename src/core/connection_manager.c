/**
 * @file connection_manager.c
 * @brief Multi-client PQ-TLS connection manager
 *
 * Architecture:
 *   - Acceptor threads accept() on the shared listen socket and hand every
 *     connection to its own thread, bounded by max_connections, so slow or
 *     idle keep-alive clients can never starve the server.
 *   - Connection thread: ACL check -> rate limit -> TLS handshake (bounded by
 *     handshake_timeout) -> PQ policy check -> weighted upstream selection ->
 *     relay (http_proxy.c) -> cleanup.
 *   - SSL_CTX is swapped under a read-write lock for SIGHUP / API hot-reload;
 *     the live configuration is guarded by config_lock.
 *   - Shutdown stops accepting, lets in-flight connections finish for up to
 *     drain_timeout, then force-closes whatever is left.
 *
 * @author Vamshi Krishna Doddikadi
 */

#include "connection_manager.h"
#include "tls_policy.h"
#include "../proxy/http_proxy.h"
#include "../dashboard/dashboard.h"
#include "../mgmt/mgmt_server.h"
#include "../security/rate_limiter.h"
#include "../security/acl.h"
#include "../common/crypto_registry.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <libgen.h>
#include <pthread.h>
#include <poll.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* Stack for connection threads: TLS handshakes with ML-DSA certificates
 * (liboqs keeps large polynomial vectors on the stack) need well over the
 * 64-128 KiB that would otherwise suffice. */
#define PQ_CONN_STACK_SIZE  (512 * 1024)

/* ======================================================================== */
/* Logging                                                                  */
/* ======================================================================== */

static const char *level_str[] = {"DEBUG", "INFO", "WARN", "ERROR"};

static void json_escape(char *dst, size_t dst_len, const char *src) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 7 < dst_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c < 0x20) {
            j += (size_t)snprintf(dst + j, dst_len - j, "\\u%04x", c);
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

__attribute__((format(printf, 3, 4)))
static void mgr_log(pq_conn_manager_t *mgr, int lvl, const char *fmt, ...) {
    if (lvl < mgr->config->log_level) return;

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
    const char *level = level_str[lvl < 4 ? lvl : 3];

    pthread_mutex_lock(&mgr->log_mutex);
    if (mgr->json_logging) {
        char esc[2048];
        json_escape(esc, sizeof(esc), msg);
        fprintf(mgr->log_fp, "{\"ts\":\"%s\",\"level\":\"%s\",\"msg\":\"%s\"}\n",
                ts, level, esc);
    } else {
        fprintf(mgr->log_fp, "[%s] [%s] %s\n", ts, level, msg);
    }
    fflush(mgr->log_fp);
    pthread_mutex_unlock(&mgr->log_mutex);
}

#define LOG_DEBUG(mgr, ...) mgr_log(mgr, 0, __VA_ARGS__)
#define LOG_INFO(mgr, ...)  mgr_log(mgr, 1, __VA_ARGS__)
#define LOG_WARN(mgr, ...)  mgr_log(mgr, 2, __VA_ARGS__)
#define LOG_ERROR(mgr, ...) mgr_log(mgr, 3, __VA_ARGS__)

/* At most one message per second per call site (for overload conditions). */
#define LOG_THROTTLED(mgr, lvl, ...) do {                                   \
        static atomic_long _last_log;                                       \
        long _now = (long)time(NULL);                                       \
        long _prev = atomic_load(&_last_log);                               \
        if (_now != _prev &&                                                \
            atomic_compare_exchange_strong(&_last_log, &_prev, _now))       \
            mgr_log(mgr, lvl, __VA_ARGS__);                                 \
    } while (0)

/* ======================================================================== */
/* Live configuration lock                                                  */
/* ======================================================================== */

void pq_conn_manager_config_rdlock(pq_conn_manager_t *mgr) { pthread_rwlock_rdlock(&mgr->config_lock); }
void pq_conn_manager_config_wrlock(pq_conn_manager_t *mgr) { pthread_rwlock_wrlock(&mgr->config_lock); }
void pq_conn_manager_config_unlock(pq_conn_manager_t *mgr) { pthread_rwlock_unlock(&mgr->config_lock); }

/* ======================================================================== */
/* Providers                                                                */
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
    snprintf(copy1, sizeof(copy1), "%s", exe_path);
    char *bin_dir = dirname(copy1);
    snprintf(copy2, sizeof(copy2), "%s", bin_dir);
    char *build_dir = dirname(copy2);
    snprintf(copy3, sizeof(copy3), "%s", build_dir);
    char *root = dirname(copy3);

    const char *suffixes[] = {
        "/vendor/oqs-provider/build/lib",
        "/vendor/lib64/ossl-modules",
        "/vendor/openssl/lib64/ossl-modules",
        "/vendor/openssl/lib/ossl-modules",
        "/lib/ossl-modules",
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
        "/usr/lib/aarch64-linux-gnu/ossl-modules",
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

/* Groups the operator asked for: the configured list, or — if that is
 * empty — the list generated by the crypto-agility registry. */
static void requested_groups(pq_conn_manager_t *mgr, char *out, size_t len) {
    snprintf(out, len, "%s", mgr->config->tls_groups);
    if (!out[0] && mgr->crypto_registry) {
        if (pq_registry_generate_groups_string(mgr->crypto_registry, out, len) <= 0)
            out[0] = '\0';
    }
}

/**
 * Load the default provider and — only when needed — oqs-provider.
 * OpenSSL >= 3.5 implements ML-KEM hybrids natively; oqs-provider is then
 * loaded only if a configured group is not available natively.
 */
static int load_providers(pq_conn_manager_t *mgr) {
    mgr->default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!mgr->default_provider) {
        fprintf(stderr, "Failed to load OpenSSL default provider\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    int need_oqs = 1;
    if (OpenSSL_version_num() >= 0x30500000L) {
        char req[PQ_MAX_GROUPS], resolved[PQ_MAX_GROUPS], dropped[PQ_MAX_GROUPS];
        requested_groups(mgr, req, sizeof(req));
        pq_tls_resolve_groups(req, 0, resolved, sizeof(resolved), dropped, sizeof(dropped));
        need_oqs = dropped[0] != '\0';
        if (!need_oqs)
            LOG_INFO(mgr, "Using OpenSSL %s native post-quantum key exchange",
                     OpenSSL_version(OPENSSL_VERSION_STRING));
    }

    if (need_oqs) {
        setup_oqs_provider_path();
        mgr->oqs_provider = OSSL_PROVIDER_load(NULL, "oqsprovider");
        ERR_clear_error();
        if (mgr->oqs_provider) {
            LOG_INFO(mgr, "Loaded oqs-provider from %s",
                     getenv("OPENSSL_MODULES") ? getenv("OPENSSL_MODULES") : "default module path");
        } else {
            LOG_WARN(mgr, "oqs-provider not available (OPENSSL_MODULES=%s)",
                     getenv("OPENSSL_MODULES") ? getenv("OPENSSL_MODULES") : "not set");
        }
    }
    return 0;
}

static void unload_providers(pq_conn_manager_t *mgr) {
    if (mgr->oqs_provider) OSSL_PROVIDER_unload(mgr->oqs_provider);
    if (mgr->default_provider) OSSL_PROVIDER_unload(mgr->default_provider);
    mgr->oqs_provider = NULL;
    mgr->default_provider = NULL;
}

/* ======================================================================== */
/* SSL context                                                              */
/* ======================================================================== */

static void log_openssl_error(pq_conn_manager_t *mgr, const char *what) {
    unsigned long e = ERR_peek_last_error();
    char buf[256] = "unknown error";
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    LOG_ERROR(mgr, "%s: %s", what, buf);
    ERR_clear_error();
}

/**
 * Build a fully configured SSL_CTX from the current configuration.
 * Used both at startup and for hot reload, so a reload can never weaken the
 * policy (groups, --require-pq, protocol floor) that startup enforced.
 * Caller must hold config_lock (read).
 */
static SSL_CTX *build_ssl_ctx(pq_conn_manager_t *mgr, char *effective, size_t eff_len) {
    const pq_server_config_t *cfg = mgr->config;

    /* ---- key-exchange groups ---- */
    char req[PQ_MAX_GROUPS], groups[PQ_MAX_GROUPS], dropped[PQ_MAX_GROUPS];
    requested_groups(mgr, req, sizeof(req));
    int n = pq_tls_resolve_groups(req, cfg->require_pq, groups, sizeof(groups),
                                  dropped, sizeof(dropped));
    if (n < 0) {
        LOG_ERROR(mgr, "Failed to evaluate TLS groups '%s'", req);
        return NULL;
    }
    if (dropped[0]) {
        LOG_WARN(mgr, "Skipping TLS groups %s: %s", dropped,
                 cfg->require_pq ? "not supported by the loaded providers, "
                                   "or classical-only under --require-pq"
                                 : "not supported by the loaded providers");
    }
    if (n == 0) {
        if (cfg->require_pq) {
            LOG_ERROR(mgr, "--require-pq: no post-quantum key exchange is available "
                      "(requested '%s'). Install oqs-provider (OPENSSL_MODULES) or "
                      "use OpenSSL >= 3.5.", req);
        } else {
            LOG_ERROR(mgr, "No usable TLS key exchange group in '%s'", req);
        }
        return NULL;
    }
    int have_pq = pq_tls_groups_have_pq(groups);
    if (!have_pq) {
        LOG_WARN(mgr, "POST-QUANTUM KEY EXCHANGE IS NOT AVAILABLE: offering only "
                 "classical groups (%s). Install oqs-provider or use OpenSSL >= 3.5.",
                 groups);
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        log_openssl_error(mgr, "SSL_CTX_new");
        return NULL;
    }

    /* ---- protocol versions & ciphers ---- */
    int min_ver = (cfg->tls_min_version == 0x0303) ? TLS1_2_VERSION : TLS1_3_VERSION;
    if (cfg->require_pq && min_ver < TLS1_3_VERSION) {
        LOG_WARN(mgr, "--require-pq: raising minimum TLS version to 1.3 "
                 "(TLS 1.2 cannot negotiate post-quantum key exchange)");
        min_ver = TLS1_3_VERSION;
    }
    if (SSL_CTX_set_min_proto_version(ctx, min_ver) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
        log_openssl_error(mgr, "Setting TLS protocol versions");
        goto fail;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION |
                             SSL_OP_CIPHER_SERVER_PREFERENCE);
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:"
                                      "TLS_CHACHA20_POLY1305_SHA256:"
                                      "TLS_AES_128_GCM_SHA256") != 1) {
        log_openssl_error(mgr, "Setting TLS 1.3 cipher suites");
        goto fail;
    }
    /* TLS 1.2 (if enabled): forward-secret AEAD suites only. */
    if (min_ver == TLS1_2_VERSION &&
        SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!SHA1") != 1) {
        log_openssl_error(mgr, "Setting TLS 1.2 cipher list");
        goto fail;
    }

    if (SSL_CTX_set1_groups_list(ctx, groups) != 1) {
        log_openssl_error(mgr, "Setting TLS groups");
        goto fail;
    }

    /* ---- certificate & key ---- */
    if (SSL_CTX_use_certificate_chain_file(ctx, cfg->cert_file) != 1) {
        log_openssl_error(mgr, "Loading certificate chain");
        goto fail;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, cfg->key_file, SSL_FILETYPE_PEM) != 1) {
        log_openssl_error(mgr, "Loading private key");
        goto fail;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        log_openssl_error(mgr, "Private key does not match certificate");
        goto fail;
    }

    /* ---- client authentication (mTLS) ---- */
    if (cfg->require_client_auth) {
        if (SSL_CTX_load_verify_locations(ctx, cfg->ca_file, NULL) != 1) {
            log_openssl_error(mgr, "Loading client CA file");
            goto fail;
        }
        STACK_OF(X509_NAME) *names = SSL_load_client_CA_file(cfg->ca_file);
        if (names) SSL_CTX_set_client_CA_list(ctx, names);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(ctx, 4);
    }

    /* ---- session resumption ----
     * TLS 1.3 resumption uses psk_dhe_ke (OpenSSL never enables psk_ke
     * unless SSL_OP_ALLOW_NO_DHE_KEX is set), so every resumed session still
     * performs a fresh (PQ) key exchange. */
    static const unsigned char sid_ctx[] = "pq-tls-server";
    SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx) - 1);
    if (cfg->session_cache_size > 0) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_sess_set_cache_size(ctx, (long)cfg->session_cache_size);
        SSL_CTX_set_timeout(ctx, 3600);
    } else {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
        SSL_CTX_set_num_tickets(ctx, 0);
    }

    /* ---- misc ---- */
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (cfg->proxy_mode == PQ_PROXY_MODE_HTTP)
        SSL_CTX_set_alpn_select_cb(ctx, pq_tls_alpn_select_http1, NULL);

    snprintf(effective, eff_len, "%s", groups);
    atomic_store(&mgr->pq_available, have_pq);
    ERR_clear_error();
    return ctx;

fail:
    SSL_CTX_free(ctx);
    return NULL;
}

/* ======================================================================== */
/* Listening socket                                                         */
/* ======================================================================== */

static int create_listen_socket(pq_conn_manager_t *mgr) {
    const pq_server_config_t *cfg = mgr->config;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;

    char port[8];
    snprintf(port, sizeof(port), "%u", cfg->listen_port);
    int gai = getaddrinfo(cfg->bind_address, port, &hints, &res);
    if (gai != 0 || !res) {
        fprintf(stderr, "Invalid listen address '%s': %s\n", cfg->bind_address,
                gai_strerror(gai));
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC, res->ai_protocol);
    if (fd < 0) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (res->ai_family == AF_INET6) {
        int v6only = 0;                     /* "::" also accepts IPv4 */
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "bind %s:%u: %s\n", cfg->bind_address, cfg->listen_port,
                strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    if (listen(fd, SOMAXCONN) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

/* Render a peer address; IPv4-mapped IPv6 is shown as plain IPv4 so ACLs and
 * rate limits treat both listen modes identically. */
static void format_peer(const struct sockaddr_storage *ss, char *ip, size_t ip_len,
                        uint16_t *port) {
    *port = 0;
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        if (!inet_ntop(AF_INET, &s4->sin_addr, ip, (socklen_t)ip_len)) goto unknown;
        *port = ntohs(s4->sin_port);
        return;
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        *port = ntohs(s6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr)) {
            if (!inet_ntop(AF_INET, &s6->sin6_addr.s6_addr[12], ip, (socklen_t)ip_len))
                goto unknown;
        } else if (!inet_ntop(AF_INET6, &s6->sin6_addr, ip, (socklen_t)ip_len)) {
            goto unknown;
        }
        return;
    }
unknown:
    snprintf(ip, ip_len, "unknown");
}

/* ======================================================================== */
/* Connection slots (lets shutdown unblock threads stuck in I/O)            */
/* ======================================================================== */

static int slot_acquire(pq_conn_manager_t *mgr) {
    int limit = mgr->config->max_connections;
    pthread_mutex_lock(&mgr->slot_lock);
    int in_use = mgr->slot_count - mgr->free_top;
    int slot = -1;
    if (mgr->free_top > 0 && in_use < limit) {
        slot = mgr->free_slots[--mgr->free_top];
        mgr->slots[slot].client_fd = -1;
        mgr->slots[slot].backend_fd = -1;
    }
    pthread_mutex_unlock(&mgr->slot_lock);
    return slot;
}

static void slot_release(pq_conn_manager_t *mgr, int slot) {
    pthread_mutex_lock(&mgr->slot_lock);
    mgr->slots[slot].client_fd = -1;
    mgr->slots[slot].backend_fd = -1;
    mgr->free_slots[mgr->free_top++] = slot;
    pthread_mutex_unlock(&mgr->slot_lock);
}

static void slot_set(pq_conn_manager_t *mgr, int slot, int client_fd, int backend_fd) {
    pthread_mutex_lock(&mgr->slot_lock);
    mgr->slots[slot].client_fd = client_fd;
    mgr->slots[slot].backend_fd = backend_fd;
    pthread_mutex_unlock(&mgr->slot_lock);
}

/* Unregister and close an fd; unregistering first guarantees the force-close
 * path never shuts down a recycled descriptor. */
static void slot_close_fds(pq_conn_manager_t *mgr, int slot, int *client_fd, int *backend_fd) {
    slot_set(mgr, slot, -1, -1);
    if (*backend_fd >= 0) { close(*backend_fd); *backend_fd = -1; }
    if (*client_fd >= 0)  { close(*client_fd);  *client_fd = -1; }
}

static void force_close_all(pq_conn_manager_t *mgr) {
    pthread_mutex_lock(&mgr->slot_lock);
    for (int i = 0; i < mgr->slot_count; i++) {
        if (mgr->slots[i].client_fd >= 0)  shutdown(mgr->slots[i].client_fd, SHUT_RDWR);
        if (mgr->slots[i].backend_fd >= 0) shutdown(mgr->slots[i].backend_fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&mgr->slot_lock);
}

/* ======================================================================== */
/* Weighted round-robin load balancing with health checks                   */
/* ======================================================================== */

static int clamp_weight(int w) { return w < 1 ? 1 : (w > 100 ? 100 : w); }

/**
 * Weighted round-robin upstream selection over healthy backends; falls back
 * to plain round-robin when every backend is marked down.
 * Caller must hold config_lock (read).
 */
static int pick_upstream_locked(pq_conn_manager_t *mgr) {
    static atomic_uint rr_counter;
    int n = mgr->config->upstream_count;
    if (n <= 0) return -1;
    if (n > PQ_MAX_UPSTREAMS) n = PQ_MAX_UPSTREAMS;

    unsigned int total = 0;
    for (int i = 0; i < n; i++) {
        if (atomic_load(&mgr->upstream_healthy[i]))
            total += (unsigned int)clamp_weight(mgr->config->upstreams[i].weight);
    }
    unsigned int ticket = atomic_fetch_add(&rr_counter, 1u);
    if (total == 0) return (int)(ticket % (unsigned int)n);

    unsigned int target = ticket % total, cumulative = 0;
    for (int i = 0; i < n; i++) {
        if (!atomic_load(&mgr->upstream_healthy[i])) continue;
        cumulative += (unsigned int)clamp_weight(mgr->config->upstreams[i].weight);
        if (target < cumulative) return i;
    }
    return 0;
}

static int connect_unix_socket(const char *path, int timeout_ms) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) { close(fd); return -1; }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return -1; }

    int ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret != 0) {
        if (errno != EINPROGRESS && errno != EAGAIN) { close(fd); return -1; }
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, timeout_ms) <= 0) { close(fd); return -1; }
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 || err != 0) {
            close(fd);
            return -1;
        }
    }
    fcntl(fd, F_SETFL, flags); /* restore blocking */
    return fd;
}

static int connect_backend(const pq_upstream_t *up, int timeout_ms) {
    if (strncmp(up->host, "unix:", 5) == 0)
        return connect_unix_socket(up->host + 5, timeout_ms);
    return pq_proxy_connect_upstream(up->host, up->port, timeout_ms);
}

/**
 * Health check thread — periodically probes backends with a connect().
 * Probes run on a snapshot, without holding the config lock.
 */
static void* health_check_thread(void *arg) {
    pq_conn_manager_t *mgr = (pq_conn_manager_t*)arg;
    const int interval_sec = 10;

    while (atomic_load(&mgr->running)) {
        pq_upstream_t snap[PQ_MAX_UPSTREAMS];
        int n, connect_timeout;

        pq_conn_manager_config_rdlock(mgr);
        n = mgr->config->upstream_count;
        if (n > PQ_MAX_UPSTREAMS) n = PQ_MAX_UPSTREAMS;
        memcpy(snap, mgr->config->upstreams, sizeof(pq_upstream_t) * (size_t)n);
        connect_timeout = mgr->config->upstream_connect_timeout_ms;
        pq_conn_manager_config_unlock(mgr);

        for (int i = 0; i < n && atomic_load(&mgr->running); i++) {
            int fd = connect_backend(&snap[i], connect_timeout < 2000 ? connect_timeout : 2000);
            int healthy = fd >= 0;
            if (fd >= 0) close(fd);

            /* Only record the result if the list did not change meanwhile. */
            pq_conn_manager_config_rdlock(mgr);
            int same = i < mgr->config->upstream_count &&
                       strcmp(mgr->config->upstreams[i].host, snap[i].host) == 0 &&
                       mgr->config->upstreams[i].port == snap[i].port;
            if (same) {
                int was = atomic_exchange(&mgr->upstream_healthy[i], healthy);
                if (was != healthy)
                    mgr_log(mgr, healthy ? 1 : 2, "Backend %s:%u is %s",
                            snap[i].host, snap[i].port, healthy ? "UP" : "DOWN");
            }
            pq_conn_manager_config_unlock(mgr);
        }

        /* Periodic rate limiter cleanup */
        pq_rate_limiter_cleanup();

        for (int s = 0; s < interval_sec && atomic_load(&mgr->running); s++)
            sleep(1);
    }
    return NULL;
}

/* ======================================================================== */
/* Per-connection handler (runs in its own thread)                          */
/* ======================================================================== */

static void set_io_timeout(int fd, int timeout_ms) {
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void handle_connection(pq_conn_manager_t *mgr, int client_fd,
                              const struct sockaddr_storage *peer, int slot) {
    pq_connection_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.client_fd  = client_fd;
    conn.backend_fd = -1;
    conn.state      = CONN_STATE_TLS_HANDSHAKE;
    clock_gettime(CLOCK_MONOTONIC, &conn.connected_at);
    format_peer(peer, conn.client_addr, sizeof(conn.client_addr), &conn.client_port);
    slot_set(mgr, slot, client_fd, -1);

    /* Snapshot the settings this connection uses. */
    pq_conn_manager_config_rdlock(mgr);
    const int hs_timeout      = mgr->config->handshake_timeout_ms;
    const int idle_timeout    = mgr->config->upstream_timeout_ms;
    const int connect_timeout = mgr->config->upstream_connect_timeout_ms;
    const int require_pq      = mgr->config->require_pq;
    const int http_mode       = mgr->config->proxy_mode == PQ_PROXY_MODE_HTTP;
    const int access_log      = mgr->config->access_log;
    pq_conn_manager_config_unlock(mgr);

    int counted_active = 0;
    SSL *ssl = NULL;

    /* --- ACL check --- */
    if (!pq_acl_check(conn.client_addr)) {
        LOG_DEBUG(mgr, "ACL denied connection from %s:%u", conn.client_addr, conn.client_port);
        goto cleanup;
    }

    /* --- Rate limiting (before any expensive TLS work) --- */
    if (!pq_rate_limiter_allow(conn.client_addr)) {
        atomic_fetch_add(&mgr->rate_limited_connections, 1);
        LOG_WARN(mgr, "Rate limited %s:%u", conn.client_addr, conn.client_port);
        goto cleanup;
    }

    atomic_fetch_add(&mgr->active_connections, 1);
    atomic_fetch_add(&mgr->total_connections, 1);
    counted_active = 1;

    int opt = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
    setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    /* A peer that stalls mid-handshake is cut off after hs_timeout. */
    set_io_timeout(client_fd, hs_timeout);

    /* --- TLS handshake --- */
    pthread_rwlock_rdlock(&mgr->ssl_ctx_lock);
    ssl = SSL_new(mgr->ssl_ctx);
    pthread_rwlock_unlock(&mgr->ssl_ctx_lock);
    if (!ssl || SSL_set_fd(ssl, client_fd) != 1) {
        LOG_ERROR(mgr, "SSL_new failed for %s:%u", conn.client_addr, conn.client_port);
        goto cleanup;
    }
    conn.ssl = ssl;

    struct timespec hs_start, hs_end;
    clock_gettime(CLOCK_MONOTONIC, &hs_start);
    if (SSL_accept(ssl) != 1) {
        unsigned long err = ERR_peek_last_error();
        char err_buf[256] = "connection closed or timed out";
        if (err) ERR_error_string_n(err, err_buf, sizeof(err_buf));
        ERR_clear_error();
        LOG_INFO(mgr, "TLS handshake failed from %s:%u: %s",
                 conn.client_addr, conn.client_port, err_buf);
        atomic_fetch_add(&mgr->total_handshake_failures, 1);
        goto cleanup;
    }
    clock_gettime(CLOCK_MONOTONIC, &hs_end);
    double hs_ms = (double)(hs_end.tv_sec - hs_start.tv_sec) * 1000.0 +
                   (double)(hs_end.tv_nsec - hs_start.tv_nsec) / 1e6;
    conn.state = CONN_STATE_ACTIVE;

    const char *proto  = SSL_get_version(ssl);
    const char *cipher = SSL_get_cipher(ssl);
    const char *group  = pq_tls_negotiated_group(ssl);
    int is_pq = pq_tls_group_is_pq(group);

    /* --- PQ policy: defense in depth on top of the PQ-only group list --- */
    if (require_pq && !is_pq) {
        atomic_fetch_add(&mgr->rejected_non_pq, 1);
        LOG_WARN(mgr, "Rejected %s:%u: classical key exchange '%s' under --require-pq",
                 conn.client_addr, conn.client_port, group);
        goto cleanup;
    }
    atomic_fetch_add(is_pq ? &mgr->pq_negotiations : &mgr->classical_negotiations, 1);

    LOG_INFO(mgr, "Handshake OK %s:%u  proto=%s cipher=%s group=%s pq=%s  %.1fms",
             conn.client_addr, conn.client_port, proto, cipher ? cipher : "?",
             group, is_pq ? "yes" : "no", hs_ms);

    /* From here on, SO_RCVTIMEO/SO_SNDTIMEO bound individual blocking TLS
     * reads/writes; the relay enforces the idle timeout. */
    set_io_timeout(client_fd, idle_timeout);

    /* --- Select and connect to an upstream --- */
    pq_upstream_t up;
    pq_conn_manager_config_rdlock(mgr);
    int ui = pick_upstream_locked(mgr);
    if (ui >= 0) up = mgr->config->upstreams[ui];
    pq_conn_manager_config_unlock(mgr);

    if (ui < 0) {
        LOG_ERROR(mgr, "No upstream backend configured for %s:%u",
                  conn.client_addr, conn.client_port);
        if (http_mode) pq_proxy_send_status(ssl, 503, 1000);
        goto cleanup;
    }
    conn.upstream_idx = ui;
    conn.backend_fd = connect_backend(&up, connect_timeout);
    if (conn.backend_fd < 0) {
        LOG_ERROR(mgr, "Upstream connect failed %s:%u -> %s:%u",
                  conn.client_addr, conn.client_port, up.host, up.port);
        atomic_store(&mgr->upstream_healthy[ui], 0);
        if (http_mode) pq_proxy_send_status(ssl, 502, 1000);
        goto cleanup;
    }
    slot_set(mgr, slot, client_fd, conn.backend_fd);
    LOG_DEBUG(mgr, "Upstream connected %s:%u -> %s:%u",
              conn.client_addr, conn.client_port, up.host, up.port);

    /* --- Relay --- */
    pq_proxy_info_t info = {
        .group_name        = group,
        .cipher_name       = cipher ? cipher : "unknown",
        .client_addr       = conn.client_addr,
        .is_pq             = is_pq,
        .rewrite_http      = http_mode,
        .header_timeout_ms = hs_timeout,
        .running           = &mgr->running,
        .force_stop        = &mgr->force_close,
    };
    pq_proxy_result_t result = pq_proxy_relay(ssl, conn.backend_fd, idle_timeout, &info);

    conn.bytes_in  = result.bytes_from_client;
    conn.bytes_out = result.bytes_from_backend;
    atomic_fetch_add(&mgr->total_bytes_in,  (long)conn.bytes_in);
    atomic_fetch_add(&mgr->total_bytes_out, (long)conn.bytes_out);
    if (result.http_status) {
        atomic_fetch_add(&mgr->bad_requests, 1);
        LOG_WARN(mgr, "Rejected request from %s:%u with HTTP %d",
                 conn.client_addr, conn.client_port, result.http_status);
    }

    if (access_log) {
        LOG_INFO(mgr, "CLOSE %s:%u  upstream=%s:%u  requests=%lu in=%zu out=%zu",
                 conn.client_addr, conn.client_port, up.host, up.port,
                 result.requests, conn.bytes_in, conn.bytes_out);
    }

cleanup:
    conn.state = CONN_STATE_CLOSED;
    if (ssl) {
        if (SSL_is_init_finished(ssl)) {
            set_io_timeout(client_fd, 1000);        /* don't linger on close_notify */
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
        ERR_clear_error();
    }
    slot_close_fds(mgr, slot, &conn.client_fd, &conn.backend_fd);
    if (counted_active) atomic_fetch_sub(&mgr->active_connections, 1);
}

typedef struct {
    pq_conn_manager_t      *mgr;
    int                     fd;
    int                     slot;
    struct sockaddr_storage peer;
} conn_task_t;

static void *connection_thread(void *arg) {
    conn_task_t *t = arg;
    pq_conn_manager_t *mgr = t->mgr;
    handle_connection(mgr, t->fd, &t->peer, t->slot);
    slot_release(mgr, t->slot);
    free(t);
    /* Last touch of mgr: the manager may be destroyed once this reaches 0. */
    atomic_fetch_sub(&mgr->conn_threads, 1);
    return NULL;
}

/* ======================================================================== */
/* Acceptor threads                                                         */
/* ======================================================================== */

typedef struct {
    pq_conn_manager_t *mgr;
    int                thread_id;
} worker_arg_t;

static void* acceptor_thread(void *arg) {
    worker_arg_t *wa = (worker_arg_t*)arg;
    pq_conn_manager_t *mgr = wa->mgr;
    int tid = wa->thread_id;
    free(wa);

    LOG_DEBUG(mgr, "Acceptor %d started", tid);

    while (atomic_load(&mgr->running)) {
        struct sockaddr_storage peer;
        socklen_t addr_len = sizeof(peer);
        int fd = accept4(mgr->listen_fd, (struct sockaddr*)&peer, &addr_len, SOCK_CLOEXEC);
        if (fd < 0) {
            if (!atomic_load(&mgr->running)) break;
            if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED) continue;
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) {
                /* Out of descriptors/memory: back off instead of spinning. */
                LOG_THROTTLED(mgr, 3, "accept: %s — backing off (raise ulimit -n "
                              "or lower max_connections)", strerror(errno));
                usleep(100000);
                continue;
            }
            LOG_ERROR(mgr, "Acceptor %d: accept failed: %s", tid, strerror(errno));
            usleep(10000);
            continue;
        }

        int slot = slot_acquire(mgr);
        if (slot < 0) {
            atomic_fetch_add(&mgr->rejected_overload, 1);
            LOG_THROTTLED(mgr, 2, "Connection limit reached (max_connections=%d); "
                          "rejecting new connections", mgr->config->max_connections);
            close(fd);
            continue;
        }

        conn_task_t *t = malloc(sizeof(*t));
        if (!t) {
            slot_release(mgr, slot);
            close(fd);
            continue;
        }
        t->mgr = mgr;
        t->fd = fd;
        t->slot = slot;
        t->peer = peer;

        atomic_fetch_add(&mgr->conn_threads, 1);
        pthread_t th;
        int rc = pthread_create(&th, &mgr->conn_attr, connection_thread, t);
        if (rc != 0) {
            atomic_fetch_sub(&mgr->conn_threads, 1);
            slot_release(mgr, slot);
            close(fd);
            free(t);
            LOG_THROTTLED(mgr, 3, "Cannot create connection thread: %s", strerror(rc));
            usleep(10000);
        }
    }

    LOG_DEBUG(mgr, "Acceptor %d stopped", tid);
    return NULL;
}

/* ======================================================================== */
/* Public API                                                               */
/* ======================================================================== */

pq_conn_manager_t* pq_conn_manager_create(const pq_server_config_t *cfg) {
    pq_conn_manager_t *mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;

    mgr->config = cfg;
    mgr->listen_fd = -1;
    mgr->json_logging = cfg->json_logging;
    mgr->start_time = time(NULL);
    pthread_mutex_init(&mgr->log_mutex, NULL);
    pthread_mutex_init(&mgr->slot_lock, NULL);
    pthread_rwlock_init(&mgr->ssl_ctx_lock, NULL);
    pthread_rwlock_init(&mgr->config_lock, NULL);
    pthread_attr_init(&mgr->conn_attr);
    pthread_attr_setdetachstate(&mgr->conn_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&mgr->conn_attr, PQ_CONN_STACK_SIZE);

    if (cfg->log_file[0]) {
        mgr->log_fp = fopen(cfg->log_file, "a");
        if (!mgr->log_fp) {
            fprintf(stderr, "Cannot open log file '%s': %s\n", cfg->log_file, strerror(errno));
            goto fail;
        }
    } else {
        mgr->log_fp = stderr;
    }

    /* Connection slots */
    mgr->slot_count = cfg->max_connections > 0 ? cfg->max_connections : 1;
    mgr->slots = calloc((size_t)mgr->slot_count, sizeof(pq_conn_slot_t));
    mgr->free_slots = calloc((size_t)mgr->slot_count, sizeof(int));
    if (!mgr->slots || !mgr->free_slots) goto fail;
    for (int i = 0; i < mgr->slot_count; i++) {
        mgr->slots[i].client_fd = mgr->slots[i].backend_fd = -1;
        mgr->free_slots[i] = mgr->slot_count - 1 - i;
    }
    mgr->free_top = mgr->slot_count;

    /* Crypto-agility registry */
    mgr->crypto_registry = pq_registry_create();
    if (mgr->crypto_registry) {
        pq_registry_register_builtins(mgr->crypto_registry);
        LOG_INFO(mgr, "Crypto-agility: registered %zu KEMs, %zu SIGs",
                 pq_registry_kem_count(mgr->crypto_registry),
                 pq_registry_sig_count(mgr->crypto_registry));
    }

    if (load_providers(mgr) != 0) goto fail;

    mgr->ssl_ctx = build_ssl_ctx(mgr, mgr->effective_groups, sizeof(mgr->effective_groups));
    if (!mgr->ssl_ctx) goto fail;
    LOG_INFO(mgr, "TLS key exchange groups: %s%s", mgr->effective_groups,
             cfg->require_pq ? "  (post-quantum required)" : "");

    mgr->listen_fd = create_listen_socket(mgr);
    if (mgr->listen_fd < 0) goto fail;

    /* Acceptor threads: a few suffice, connections get their own threads. */
    mgr->worker_count = cfg->worker_threads;
    if (mgr->worker_count <= 0) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        mgr->worker_count = ncpu < 1 ? 1 : (ncpu > 4 ? 4 : (int)ncpu);
    }

    if (cfg->rate_limit_per_ip > 0) {
        int burst = cfg->rate_limit_burst > 0 ? cfg->rate_limit_burst : cfg->rate_limit_per_ip * 2;
        pq_rate_limiter_init(cfg->rate_limit_per_ip, burst);
        LOG_INFO(mgr, "Rate limiting: %d/s per IP, burst=%d", cfg->rate_limit_per_ip, burst);
    }

    if (cfg->acl_mode != PQ_ACL_MODE_DISABLED) {
        /* An ACL that silently drops a bad entry could leave a blocklist open
         * or an allowlist wider than intended: refuse to start instead. */
        if (pq_acl_replace(cfg->acl_mode, (const char (*)[64])cfg->acl_entries,
                           cfg->acl_count) != 0) {
            fprintf(stderr, "Invalid [acl] entry: expected IPv4/IPv6 address or CIDR\n");
            goto fail;
        }
        LOG_INFO(mgr, "ACL: mode=%s, %d entries",
                 cfg->acl_mode == PQ_ACL_MODE_ALLOWLIST ? "allowlist" : "blocklist",
                 cfg->acl_count);
    }

    for (int i = 0; i < cfg->upstream_count && i < PQ_MAX_UPSTREAMS; i++)
        atomic_store(&mgr->upstream_healthy[i], 1);

    LOG_INFO(mgr, "PQ-TLS Server initialized  acceptors=%d max_connections=%d",
             mgr->worker_count, mgr->slot_count);
    return mgr;

fail:
    if (mgr->listen_fd >= 0) close(mgr->listen_fd);
    if (mgr->ssl_ctx) SSL_CTX_free(mgr->ssl_ctx);
    unload_providers(mgr);
    if (mgr->crypto_registry) pq_registry_destroy(mgr->crypto_registry);
    if (mgr->log_fp && mgr->log_fp != stderr) fclose(mgr->log_fp);
    free(mgr->slots);
    free(mgr->free_slots);
    pthread_attr_destroy(&mgr->conn_attr);
    pthread_rwlock_destroy(&mgr->config_lock);
    pthread_rwlock_destroy(&mgr->ssl_ctx_lock);
    pthread_mutex_destroy(&mgr->slot_lock);
    pthread_mutex_destroy(&mgr->log_mutex);
    free(mgr);
    return NULL;
}

/* Wait until all connection threads are gone or timeout_ms passes. */
static int wait_for_connections(pq_conn_manager_t *mgr, long timeout_ms) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (atomic_load(&mgr->conn_threads) > 0) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long el = (now.tv_sec - start.tv_sec) * 1000L + (now.tv_nsec - start.tv_nsec) / 1000000L;
        if (el >= timeout_ms) return -1;
        usleep(20000);
    }
    return 0;
}

int pq_conn_manager_run(pq_conn_manager_t *mgr) {
    atomic_store(&mgr->running, 1);

    if (mgr->config->health_port > 0) {
        /* The management server writes back into the (shared) config. */
        pq_server_config_t *mutable_cfg = (pq_server_config_t *)mgr->config;
        if (pq_mgmt_start(mgr, mutable_cfg, mgr->config->health_port,
                          mgr->config->config_file_path) == 0) {
            LOG_INFO(mgr, "Management dashboard on http://%s:%d",
                     mgr->config->mgmt_localhost_only ? "127.0.0.1" : "0.0.0.0",
                     mgr->config->health_port);
        } else if (pq_dashboard_start(mgr, mgr->config->health_port) == 0) {
            LOG_INFO(mgr, "Dashboard (read-only) on http://0.0.0.0:%d",
                     mgr->config->health_port);
        }
    }

    if (mgr->config->upstream_count > 0) {
        if (pthread_create(&mgr->health_tid, NULL, health_check_thread, mgr) == 0)
            mgr->health_started = 1;
        else
            LOG_WARN(mgr, "Failed to start health check thread");
    }

    mgr->workers = calloc((size_t)mgr->worker_count, sizeof(pthread_t));
    int *started = calloc((size_t)mgr->worker_count, sizeof(int));
    if (!mgr->workers || !started) {
        LOG_ERROR(mgr, "Failed to allocate acceptor thread array");
        free(started);
        pq_conn_manager_stop(mgr);
        if (mgr->health_started) { pthread_join(mgr->health_tid, NULL); mgr->health_started = 0; }
        return -1;
    }

    for (int i = 0; i < mgr->worker_count; i++) {
        worker_arg_t *wa = malloc(sizeof(*wa));
        if (!wa) continue;
        wa->mgr = mgr;
        wa->thread_id = i;
        int rc = pthread_create(&mgr->workers[i], NULL, acceptor_thread, wa);
        if (rc != 0) {
            LOG_ERROR(mgr, "Failed to create acceptor thread %d: %s", i, strerror(rc));
            free(wa);
        } else {
            started[i] = 1;
        }
    }

    LOG_INFO(mgr, "Listening on %s:%u  (%d acceptors, max %d connections)",
             mgr->config->bind_address, mgr->config->listen_port,
             mgr->worker_count, mgr->slot_count);

    for (int i = 0; i < mgr->worker_count; i++) {
        if (started[i]) pthread_join(mgr->workers[i], NULL);
    }
    free(started);

    /* ---- graceful drain ---- */
    int inflight = atomic_load(&mgr->conn_threads);
    if (inflight > 0) {
        LOG_INFO(mgr, "Draining %d connection(s) (up to %d ms)...",
                 inflight, mgr->config->drain_timeout_ms);
        if (wait_for_connections(mgr, mgr->config->drain_timeout_ms) != 0) {
            LOG_WARN(mgr, "Drain timeout: closing %d remaining connection(s)",
                     atomic_load(&mgr->conn_threads));
            atomic_store(&mgr->force_close, 1);
            force_close_all(mgr);
            if (wait_for_connections(mgr, 5000) != 0)
                LOG_ERROR(mgr, "%d connection thread(s) did not exit",
                          atomic_load(&mgr->conn_threads));
        }
    }

    if (mgr->health_started) {
        pthread_join(mgr->health_tid, NULL);
        mgr->health_started = 0;
    }
    return 0;
}

void pq_conn_manager_stop(pq_conn_manager_t *mgr) {
    if (!mgr) return;
    atomic_store(&mgr->running, 0);
    /* Idempotent; joins the management thread unless called from it. */
    pq_mgmt_stop();
    pq_dashboard_stop();
    /* Wakes acceptors blocked in accept() (they get EINVAL). */
    if (mgr->listen_fd >= 0) shutdown(mgr->listen_fd, SHUT_RDWR);
}

void pq_conn_manager_destroy(pq_conn_manager_t *mgr) {
    if (!mgr) return;

    pq_conn_manager_stop(mgr);

    /* Connection threads reference mgr; never free it underneath them. */
    if (atomic_load(&mgr->conn_threads) > 0) {
        atomic_store(&mgr->force_close, 1);
        force_close_all(mgr);
        if (wait_for_connections(mgr, 5000) != 0) {
            fprintf(stderr, "pq_conn_manager_destroy: connection threads still running; "
                    "leaking manager to avoid use-after-free\n");
            return;
        }
    }
    if (mgr->health_started) pthread_join(mgr->health_tid, NULL);

    pq_rate_limiter_destroy();
    pq_acl_destroy();

    if (mgr->listen_fd >= 0) close(mgr->listen_fd);

    pthread_rwlock_wrlock(&mgr->ssl_ctx_lock);
    if (mgr->ssl_ctx) SSL_CTX_free(mgr->ssl_ctx);
    mgr->ssl_ctx = NULL;
    pthread_rwlock_unlock(&mgr->ssl_ctx_lock);

    unload_providers(mgr);
    if (mgr->crypto_registry) pq_registry_destroy(mgr->crypto_registry);
    if (mgr->log_fp && mgr->log_fp != stderr) fclose(mgr->log_fp);
    free(mgr->workers);
    free(mgr->slots);
    free(mgr->free_slots);
    pthread_attr_destroy(&mgr->conn_attr);
    pthread_rwlock_destroy(&mgr->config_lock);
    pthread_rwlock_destroy(&mgr->ssl_ctx_lock);
    pthread_mutex_destroy(&mgr->slot_lock);
    pthread_mutex_destroy(&mgr->log_mutex);
    free(mgr);
}

void pq_conn_manager_tls_groups(pq_conn_manager_t *mgr, char *buf, size_t len) {
    pthread_rwlock_rdlock(&mgr->ssl_ctx_lock);
    snprintf(buf, len, "%s", mgr->effective_groups);
    pthread_rwlock_unlock(&mgr->ssl_ctx_lock);
}

int pq_conn_manager_metrics_json(pq_conn_manager_t *mgr, char *buf, size_t len) {
    /* Individual atomic reads are consistent per field; the snapshot as a
     * whole is not. Acceptable for monitoring. */
    long uptime = (long)(time(NULL) - mgr->start_time);
    if (uptime < 0) uptime = 0;

    char groups[PQ_MAX_GROUPS];
    pq_conn_manager_tls_groups(mgr, groups, sizeof(groups));

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
        "\"pq_rejected\":%ld,"
        "\"pq_available\":%s,"
        "\"pq_required\":%s,"
        "\"tls_groups\":\"%s\","
        "\"rate_limited\":%ld,"
        "\"overload_rejected\":%ld,"
        "\"bad_requests\":%ld,"
        "\"workers\":%d,"
        "\"max_connections\":%d,"
        "\"uptime_seconds\":%ld"
        "}",
        atomic_load(&mgr->total_connections),
        atomic_load(&mgr->active_connections),
        atomic_load(&mgr->total_handshake_failures),
        atomic_load(&mgr->total_bytes_in),
        atomic_load(&mgr->total_bytes_out),
        atomic_load(&mgr->pq_negotiations),
        atomic_load(&mgr->classical_negotiations),
        atomic_load(&mgr->rejected_non_pq),
        atomic_load(&mgr->pq_available) ? "true" : "false",
        mgr->config->require_pq ? "true" : "false",
        groups,
        atomic_load(&mgr->rate_limited_connections),
        atomic_load(&mgr->rejected_overload),
        atomic_load(&mgr->bad_requests),
        mgr->worker_count,
        mgr->slot_count,
        uptime);
}

/**
 * Hot-reload the TLS configuration without dropping connections.
 *
 * Existing SSL* objects hold their own reference to the SSL_CTX they were
 * created from (SSL_new() up-refs it), so freeing the old context here only
 * drops our reference.
 */
int pq_conn_manager_reload(pq_conn_manager_t *mgr) {
    if (!mgr) return -1;

    LOG_INFO(mgr, "Reloading TLS configuration...");

    char groups[PQ_MAX_GROUPS];
    pq_conn_manager_config_rdlock(mgr);
    SSL_CTX *new_ctx = build_ssl_ctx(mgr, groups, sizeof(groups));
    pq_conn_manager_config_unlock(mgr);
    if (!new_ctx) {
        LOG_ERROR(mgr, "TLS reload FAILED — keeping the previous configuration");
        return -1;
    }

    pthread_rwlock_wrlock(&mgr->ssl_ctx_lock);
    SSL_CTX *old_ctx = mgr->ssl_ctx;
    mgr->ssl_ctx = new_ctx;
    snprintf(mgr->effective_groups, sizeof(mgr->effective_groups), "%s", groups);
    pthread_rwlock_unlock(&mgr->ssl_ctx_lock);

    SSL_CTX_free(old_ctx);

    LOG_INFO(mgr, "TLS configuration reloaded (groups: %s)", groups);
    return 0;
}
