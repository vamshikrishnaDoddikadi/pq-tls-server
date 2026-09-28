/**
 * @file mgmt_server.c
 * @brief Management HTTP server — request router, static file serving, SSE
 */

#include "mgmt_server.h"
#include "mgmt_api.h"
#include "mgmt_auth.h"
#include "json_helpers.h"
#include "log_streamer.h"
#include "static_assets.h"
#include "../metrics/prometheus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdatomic.h>
#include <time.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static pthread_t mgmt_thread;
static atomic_int mgmt_running = 0;
static atomic_int mgmt_thread_live = 0;   /* created and not yet joined */
static pq_conn_manager_t *g_mgr = NULL;
static pq_server_config_t *g_config = NULL;
static int g_port = 0;
static char g_config_path[2048] = {0};

/* Maximum request body size (1MB) - prevents memory exhaustion */
#define MAX_REQUEST_BODY_SIZE 1048576

/* ======================================================================== */
/* HTTP Response Helpers                                                    */
/* ======================================================================== */

/* The dashboard builds some markup with inline event handlers, hence
 * 'unsafe-inline' for scripts; everything else is locked to this origin
 * (plus Google Fonts), and framing / plugins / foreign form targets are
 * refused. */
#define MGMT_CSP "default-src 'self'; script-src 'self' 'unsafe-inline'; " \
                 "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " \
                 "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; " \
                 "connect-src 'self'; object-src 'none'; base-uri 'none'; " \
                 "form-action 'self'; frame-ancestors 'none'"

static void send_response(int fd, const char *status, const char *content_type,
                          const char *body, size_t body_len) {
    char header[1536];
    int is_html = strncmp(content_type, "text/html", 9) == 0;
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "%s%s%s"
        "Connection: close\r\n\r\n",
        status, content_type, body_len,
        is_html ? "Content-Security-Policy: " : "",
        is_html ? MGMT_CSP : "",
        is_html ? "\r\n" : "");
    send(fd, header, (size_t)hlen, MSG_NOSIGNAL);
    if (body && body_len > 0)
        send(fd, body, body_len, MSG_NOSIGNAL);
}

/* ======================================================================== */
/* Static asset serving                                                      */
/* ======================================================================== */

static const char* get_content_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    if (strcmp(ext, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(ext, ".css") == 0)  return "text/css; charset=utf-8";
    if (strcmp(ext, ".js") == 0)   return "application/javascript; charset=utf-8";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".png") == 0)  return "image/png";
    if (strcmp(ext, ".svg") == 0)  return "image/svg+xml";
    if (strcmp(ext, ".ico") == 0)  return "image/x-icon";
    return "application/octet-stream";
}

static int serve_static(int fd, const char *path) {
    /* Map URL path to embedded asset */
    const char *asset_path = path;

    /* Root serves index.html */
    if (strcmp(path, "/") == 0) {
        asset_path = "/index.html";
    }

    /* Skip leading slash for asset lookup */
    const char *lookup = asset_path;
    if (lookup[0] == '/') lookup++;

    const embedded_asset_t *asset = find_embedded_asset(lookup);
    if (!asset) return 0; /* Not found */

    send_response(fd, "200 OK", get_content_type(asset_path),
                  (const char *)asset->data, asset->size);
    return 1;
}

/* ======================================================================== */
/* SSE metrics stream (backward-compatible with /api/stream)                 */
/* ======================================================================== */

/* Long-lived streams run on their own threads so they never block the
 * (single-threaded) request loop. Their number is bounded, and
 * pq_mgmt_stop() waits for them, because they reference the manager. */
#define MGMT_MAX_STREAMS 16
static atomic_int g_streams = 0;

typedef struct {
    int    fd;
    void (*fn)(int fd, void *arg);
    void  *arg;
} stream_task_t;

static void *stream_thread(void *p) {
    stream_task_t t = *(stream_task_t *)p;
    free(p);
    t.fn(t.fd, t.arg);                 /* fn closes fd */
    atomic_fetch_sub(&g_streams, 1);
    return NULL;
}

int pq_mgmt_spawn_stream(int fd, void (*fn)(int fd, void *arg), void *arg) {
    if (atomic_fetch_add(&g_streams, 1) >= MGMT_MAX_STREAMS) {
        atomic_fetch_sub(&g_streams, 1);
        return -1;
    }
    stream_task_t *t = malloc(sizeof(*t));
    pthread_t th;
    pthread_attr_t attr;
    int ok = 0;
    if (t && pthread_attr_init(&attr) == 0) {
        t->fd = fd;
        t->fn = fn;
        t->arg = arg;
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        ok = pthread_create(&th, &attr, stream_thread, t) == 0;
        pthread_attr_destroy(&attr);
    }
    if (!ok) {
        free(t);
        atomic_fetch_sub(&g_streams, 1);
        return -1;
    }
    return 0;
}

static void sse_stream_fn(int fd, void *arg) {
    pq_conn_manager_t *mgr = arg;

    const char *headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: keep-alive\r\n\r\n";
    send(fd, headers, strlen(headers), MSG_NOSIGNAL);

    while (atomic_load(&mgmt_running)) {
        char buf[2048];
        pq_conn_manager_metrics_json(mgr, buf, sizeof(buf));

        char event[2200];
        int n = snprintf(event, sizeof(event), "data: %s\n\n", buf);
        if (n < 0 || n >= (int)sizeof(event)) break;
        ssize_t sent = send(fd, event, (size_t)n, MSG_NOSIGNAL);
        if (sent <= 0) break;

        usleep(1000000);
    }

    close(fd);
}

/* ======================================================================== */
/* Request parser + router                                                   */
/* ======================================================================== */

static void extract_auth_token(const char *req, const char *path,
                               char *token_out, size_t token_size) {
    (void)path;
    token_out[0] = '\0';

    /* Check Authorization: Bearer <token> header */
    const char *auth = strstr(req, "Authorization: Bearer ");
    if (auth) {
        auth += 22;
        size_t i = 0;
        while (*auth && *auth != '\r' && *auth != '\n' && i < token_size - 1) {
            token_out[i++] = *auth++;
        }
        token_out[i] = '\0';
        return;
    }

    /* Check Cookie: mgmt_token=<token> */
    const char *cookie = strstr(req, "Cookie:");
    if (!cookie) cookie = strstr(req, "cookie:");
    if (cookie) {
        const char *tok = strstr(cookie, "mgmt_token=");
        if (tok) {
            tok += 11;
            size_t i = 0;
            while (*tok && *tok != ';' && *tok != '\r' && *tok != '\n' && i < token_size - 1) {
                token_out[i++] = *tok++;
            }
            token_out[i] = '\0';
            if (token_out[0]) return;
        }
    }

    /* SECURITY: Removed query string token support - tokens in URLs leak in logs/browser history.
     * Clients must use Authorization: Bearer header or Cookie: mgmt_token=<token> instead. */
}

static void extract_body(const char *req, ssize_t total_len,
                          const char **body_out, size_t *body_len_out) {
    const char *body = strstr(req, "\r\n\r\n");
    if (body) {
        body += 4;
        *body_out = body;
        *body_len_out = (size_t)(total_len - (body - req));
    } else {
        *body_out = "";
        *body_len_out = 0;
    }
}

static void handle_request(int fd, pq_conn_manager_t *mgr, pq_server_config_t *config, const char *client_ip) {
    char req[65536];
    ssize_t total = 0;

    /* Read until we have full headers + body (or buffer is full) */
    while (total < (ssize_t)sizeof(req) - 1) {
        ssize_t n = recv(fd, req + total, sizeof(req) - 1 - (size_t)total, 0);
        if (n <= 0) {
            if (total == 0) { close(fd); return; }
            break;
        }
        total += n;
        req[total] = '\0';

        /* Check if we have the complete headers */
        const char *hdr_end = strstr(req, "\r\n\r\n");
        if (!hdr_end) continue;

        /* For requests with a body, check Content-Length */
        const char *cl = strstr(req, "Content-Length:");
        if (!cl) cl = strstr(req, "content-length:");
        if (cl) {
            /* SECURITY: Use strtol for safe integer parsing instead of atoi */
            char *endptr = NULL;
            long content_len = strtol(cl + 15, &endptr, 10);
            /* Validate: must have consumed digits, no invalid chars, positive value */
            if (endptr == NULL || endptr == cl + 15 || *endptr == '\0' ||
                *endptr == ' ' || content_len < 0 || content_len > MAX_REQUEST_BODY_SIZE) {
                const char *err_msg = "{\"error\":\"Invalid Content-Length\"}";
                send_response(fd, "400 Bad Request", "application/json", err_msg, strlen(err_msg));
                close(fd);
                return;
            }
            size_t body_start = (size_t)(hdr_end + 4 - req);
            size_t body_have = (size_t)total - body_start;
            /* SECURITY: Reject if Content-Length exceeds our buffer capacity */
            if ((size_t)content_len > sizeof(req) - body_start - 1) {
                const char *err_msg = "{\"error\":\"Request body too large\"}";
                send_response(fd, "413 Payload Too Large", "application/json", err_msg, strlen(err_msg));
                close(fd);
                return;
            }
            if ((size_t)body_have >= (size_t)content_len) break;
            continue;
        }
        break;  /* No Content-Length → assume complete */
    }

    if (total <= 0) { close(fd); return; }
    ssize_t n = total;

    /* Parse request line */
    char method[16] = {0}, path[2048] = {0};
    if (sscanf(req, "%15s %2047s", method, path) < 2) {
        close(fd);
        return;
    }

    /* Strip query string from path for routing (keep full for param extraction) */
    char clean_path[2048];
    snprintf(clean_path, sizeof(clean_path), "%s", path);
    clean_path[sizeof(clean_path) - 1] = '\0';
    char *query = strchr(clean_path, '?');
    if (query) *query = '\0';

    /* Extract auth token */
    char token[128] = {0};
    extract_auth_token(req, path, token, sizeof(token));

    /* Extract body */
    const char *body = "";
    size_t body_len = 0;
    extract_body(req, n, &body, &body_len);

    /* ---- Backward-compatible monitoring endpoints (no auth) ---- */
    if (strcmp(clean_path, "/api/stats") == 0 && strcmp(method, "GET") == 0) {
        char buf[2048];
        pq_conn_manager_metrics_json(mgr, buf, sizeof(buf));
        send_response(fd, "200 OK", "application/json", buf, strlen(buf));
        close(fd);
        return;
    }

    if (strcmp(clean_path, "/api/stream") == 0 && strcmp(method, "GET") == 0) {
        if (pq_mgmt_spawn_stream(fd, sse_stream_fn, mgr) == 0)
            return; /* fd ownership transferred */
        const char *busy = "{\"error\":\"Too many open streams\"}";
        send_response(fd, "503 Service Unavailable", "application/json", busy, strlen(busy));
        close(fd);
        return;
    }

    if (strcmp(clean_path, "/metrics") == 0 && strcmp(method, "GET") == 0) {
        char buf[8192];
        pq_prometheus_format(mgr, buf, sizeof(buf));
        send_response(fd, "200 OK", "text/plain; version=0.0.4; charset=utf-8",
                      buf, strlen(buf));
        close(fd);
        return;
    }

    if (strcmp(clean_path, "/health") == 0 && strcmp(method, "GET") == 0) {
        const char *ok = "{\"status\":\"ok\"}";
        send_response(fd, "200 OK", "application/json", ok, strlen(ok));
        close(fd);
        return;
    }

    /* ---- API routes ---- */
    if (strncmp(clean_path, "/api/", 5) == 0) {
        mgmt_api_ctx_t api_ctx = {
            .mgr = mgr,
            .config = config,
            .config_path = g_config_path,
            .client_fd = fd,
            .method = method,
            .path = path,       /* Full path with query string for param extraction */
            .body = body,
            .body_len = body_len,
            .auth_token = token[0] ? token : NULL,
        };
        snprintf(api_ctx.client_ip, sizeof(api_ctx.client_ip), "%s", client_ip);

        if (mgmt_api_dispatch(&api_ctx)) {
            /* Log stream endpoints manage their own fd lifecycle */
            if (strcmp(clean_path, "/api/logs/stream") != 0) {
                close(fd);
            }
            return;
        }
    }

    /* ---- Static files / SPA ---- */
    if (strcmp(method, "GET") == 0) {
        if (serve_static(fd, clean_path)) {
            close(fd);
            return;
        }

        /* SPA fallback: serve index.html for unrecognized paths */
        if (serve_static(fd, "/")) {
            close(fd);
            return;
        }
    }

    /* 404 */
    const char *msg = "{\"error\":\"Not Found\"}";
    send_response(fd, "404 Not Found", "application/json", msg, strlen(msg));
    close(fd);
}

/* ======================================================================== */
/* Management server thread                                                  */
/* ======================================================================== */

static void* mgmt_thread_fn(void *arg) {
    (void)arg;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    /* SECURITY: Respect mgmt_localhost_only config - bind to 127.0.0.1 if enabled */
    if (g_config && g_config->mgmt_localhost_only) {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    addr.sin_port = htons((uint16_t)g_port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, 32) < 0) {
        close(fd);
        return NULL;
    }

    /* Initialize subsystems */
    mgmt_auth_init();
    log_streamer_init(g_config->log_file[0] ? g_config->log_file : NULL);

    if (mgmt_auth_needs_setup(g_config)) {
        const char *tok = mgmt_auth_setup_token_init();
        fprintf(stderr,
                "\n  First-run setup: open the management dashboard on port %d and enter\n"
                "  this one-time setup token to create the admin account:\n\n"
                "      %s\n\n", g_port, tok);
    }

    while (atomic_load(&mgmt_running)) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        if (ret <= 0) continue;

        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int cfd = accept4(fd, (struct sockaddr*)&peer, &peer_len, SOCK_CLOEXEC);
        if (cfd < 0) continue;

        /* Requests are handled one at a time: a client that stalls must
         * not be able to block /health, /metrics and the API for everyone. */
        struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        char client_ip[64] = "unknown";
        inet_ntop(AF_INET, &peer.sin_addr, client_ip, sizeof(client_ip));

        handle_request(cfd, g_mgr, g_config, client_ip);
    }

    /* Cleanup */
    mgmt_auth_cleanup();
    log_streamer_cleanup();
    close(fd);
    return NULL;
}

/* ======================================================================== */
/* Public API                                                                */
/* ======================================================================== */

int pq_mgmt_start(pq_conn_manager_t *mgr, pq_server_config_t *config,
                   int port, const char *config_path) {
    if (port <= 0) return 0;

    g_mgr = mgr;
    g_config = config;
    g_port = port;
    if (config_path) {
        snprintf(g_config_path, sizeof(g_config_path), "%s", config_path);
    }

    atomic_store(&mgmt_running, 1);

    if (pthread_create(&mgmt_thread, NULL, mgmt_thread_fn, NULL) != 0) {
        atomic_store(&mgmt_running, 0);
        return -1;
    }
    atomic_store(&mgmt_thread_live, 1);
    return 0;
}

void pq_mgmt_stop(void) {
    atomic_store(&mgmt_running, 0);
    if (!atomic_load(&mgmt_thread_live)) return;
    /* Called from a request handler (e.g. the restart endpoint): the thread
     * exits on its own; the owner joins it later from another thread. */
    if (pthread_equal(pthread_self(), mgmt_thread)) return;
    if (atomic_exchange(&mgmt_thread_live, 0))
        pthread_join(mgmt_thread, NULL);
    /* Streams notice the stop within ~1 s (sends are bounded by
     * SO_SNDTIMEO); wait so none outlives the manager it references. */
    for (int i = 0; i < 150 && atomic_load(&g_streams) > 0; i++)
        usleep(50000);
}
