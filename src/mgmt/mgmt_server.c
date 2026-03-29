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
#include <errno.h>
#include <stdatomic.h>
#include <time.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static pthread_t mgmt_thread;
static atomic_int mgmt_running = 0;
static pq_conn_manager_t *g_mgr = NULL;
static pq_server_config_t *g_config = NULL;
static int g_port = 0;
static char g_config_path[2048] = {0};

/* ======================================================================== */
/* HTTP Response Helpers                                                    */
/* ======================================================================== */

static void send_response(int fd, const char *status, const char *content_type,
                          const char *body, size_t body_len) {
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n",
        status, content_type, body_len);
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

typedef struct {
    int fd;
    pq_conn_manager_t *mgr;
} sse_ctx_t;

static void* sse_thread_fn(void *arg) {
    sse_ctx_t *ctx = (sse_ctx_t *)arg;
    int fd = ctx->fd;
    pq_conn_manager_t *mgr = ctx->mgr;
    free(ctx);

    const char *headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Access-Control-Allow-Origin: *\r\n"
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
    return NULL;
}

/* ======================================================================== */
/* Request parser + router                                                   */
/* ======================================================================== */

static void extract_auth_token(const char *req, const char *path,
                               char *token_out, size_t token_size) {
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

    /* Check query string ?token=<token> (for EventSource SSE connections) */
    if (path) {
        const char *q = strchr(path, '?');
        if (q) {
            const char *tp = strstr(q, "token=");
            if (tp) {
                tp += 6;
                size_t i = 0;
                while (*tp && *tp != '&' && *tp != ' ' && i < token_size - 1) {
                    token_out[i++] = *tp++;
                }
                token_out[i] = '\0';
            }
        }
    }
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

static void handle_request(int fd, pq_conn_manager_t *mgr, pq_server_config_t *config) {
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
            int content_len = atoi(cl + 15);
            size_t body_start = (size_t)(hdr_end + 4 - req);
            size_t body_have = (size_t)total - body_start;
            if ((int)body_have >= content_len) break;
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
    strncpy(clean_path, path, sizeof(clean_path) - 1);
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
        sse_ctx_t *ctx = malloc(sizeof(sse_ctx_t));
        if (ctx) {
            ctx->fd = fd;
            ctx->mgr = mgr;
            pthread_t t;
            if (pthread_create(&t, NULL, sse_thread_fn, ctx) == 0) {
                pthread_detach(t);
                return; /* fd ownership transferred */
            }
            free(ctx);
        }
        close(fd);
        return;
    }

    if (strcmp(clean_path, "/metrics") == 0 && strcmp(method, "GET") == 0) {
        char buf[4096];
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
            .auth_token = token[0] ? token : NULL
        };

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
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons((uint16_t)g_port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(fd, 32) < 0) {
        close(fd);
        return NULL;
    }

    /* Initialize subsystems */
    mgmt_auth_init();
    log_streamer_init(g_config->log_file[0] ? g_config->log_file : NULL);

    while (atomic_load(&mgmt_running)) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        if (ret <= 0) continue;

        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) continue;

        handle_request(cfd, g_mgr, g_config);
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
        strncpy(g_config_path, config_path, sizeof(g_config_path) - 1);
    }

    atomic_store(&mgmt_running, 1);

    if (pthread_create(&mgmt_thread, NULL, mgmt_thread_fn, NULL) != 0) {
        return -1;
    }
    return 0;
}

void pq_mgmt_stop(void) {
    if (!atomic_load(&mgmt_running)) return;
    atomic_store(&mgmt_running, 0);
    pthread_join(mgmt_thread, NULL);
}
