/**
 * @file mgmt_api.c
 * @brief REST API endpoint handlers — config CRUD, cert ops, management ops
 */

#include "mgmt_api.h"
#include "mgmt_auth.h"
#include "json_helpers.h"
#include "config_writer.h"
#include "cert_manager.h"
#include "log_streamer.h"
#include "../security/rate_limiter.h"
#include "../security/acl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <stdatomic.h>
#include <openssl/crypto.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* Validate a name for use in file paths — reject traversal characters */
static int validate_path_name(const char *name) {
    if (!name || !name[0]) return 0;
    if (strstr(name, "..")) return 0;
    for (const char *p = name; *p; p++) {
        if (*p == '/' || *p == '\\' || *p == '\0') return 0;
        /* Only allow safe filename characters */
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.'))
            return 0;
    }
    return 1;
}

/* ======================================================================== */
/* Response helpers                                                          */
/* ======================================================================== */

static void send_http(int fd, const char *status, const char *content_type,
                      const char *body, size_t body_len) {
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        "Connection: close\r\n\r\n",
        status, content_type, body_len);
    send(fd, header, (size_t)hlen, MSG_NOSIGNAL);
    if (body && body_len > 0)
        send(fd, body, body_len, MSG_NOSIGNAL);
}

static void send_json(int fd, const char *status, const char *json) {
    send_http(fd, status, "application/json", json, strlen(json));
}

static void send_json_with_cookie(int fd, const char *json, const char *token) {
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Set-Cookie: mgmt_token=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n",
        strlen(json), token, MGMT_SESSION_TTL_SEC);
    send(fd, header, (size_t)hlen, MSG_NOSIGNAL);
    send(fd, json, strlen(json), MSG_NOSIGNAL);
}

static void send_error(int fd, const char *status, const char *message) {
    char buf[512];
    json_builder_t jb;
    jb_init(&jb, buf, sizeof(buf));
    jb_object_start(&jb);
    jb_key_str(&jb, "error", message);
    jb_object_end(&jb);
    jb_finish(&jb);
    send_json(fd, status, buf);
}

static int require_auth(mgmt_api_ctx_t *ctx) {
    if (!ctx->auth_token || !mgmt_auth_validate_session(ctx->auth_token)) {
        send_error(ctx->client_fd, "401 Unauthorized", "Authentication required");
        return 0;
    }
    return 1;
}

/* ======================================================================== */
/* Auth endpoints                                                            */
/* ======================================================================== */

void mgmt_api_auth_login(mgmt_api_ctx_t *ctx) {
    char username[64] = {0}, password[256] = {0};

    if (json_extract_string(ctx->body, "username", username, sizeof(username)) != 0 ||
        json_extract_string(ctx->body, "password", password, sizeof(password)) != 0) {
        send_error(ctx->client_fd, "400 Bad Request", "Missing username or password");
        return;
    }

    /* Always verify password to prevent timing side-channel on username */
    int pw_valid = mgmt_auth_verify_password(password, ctx->config->mgmt_admin_pass_hash);
    /* Constant-time username compare */
    size_t ulen = strlen(username);
    size_t stored_ulen = strlen(ctx->config->mgmt_admin_user);
    int user_valid = (ulen == stored_ulen) &&
                     (CRYPTO_memcmp(username, ctx->config->mgmt_admin_user, ulen) == 0);
    if (!user_valid || !pw_valid) {
        send_error(ctx->client_fd, "401 Unauthorized", "Invalid credentials");
        return;
    }

    char token[MGMT_TOKEN_HEX_LEN + 1];
    if (mgmt_auth_create_session(username, token) != 0) {
        send_error(ctx->client_fd, "500 Internal Server Error", "Session creation failed");
        return;
    }

    char resp[256];
    snprintf(resp, sizeof(resp), "{\"token\":\"%s\"}", token);
    send_json_with_cookie(ctx->client_fd, resp, token);
}

void mgmt_api_auth_logout(mgmt_api_ctx_t *ctx) {
    if (ctx->auth_token) {
        mgmt_auth_destroy_session(ctx->auth_token);
    }
    /* Clear cookie */
    char header[512];
    const char *body = "{\"status\":\"ok\"}";
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Set-Cookie: mgmt_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0\r\n"
        "Connection: close\r\n\r\n",
        strlen(body));
    send(ctx->client_fd, header, (size_t)hlen, MSG_NOSIGNAL);
    send(ctx->client_fd, body, strlen(body), MSG_NOSIGNAL);
}

void mgmt_api_auth_status(mgmt_api_ctx_t *ctx) {
    if (ctx->auth_token && mgmt_auth_validate_session(ctx->auth_token)) {
        send_json(ctx->client_fd, "200 OK", "{\"authenticated\":true}");
    } else {
        int needs_setup = mgmt_auth_needs_setup(ctx->config);
        char buf[128];
        snprintf(buf, sizeof(buf),
                 "{\"authenticated\":false,\"needs_setup\":%s}",
                 needs_setup ? "true" : "false");
        send_json(ctx->client_fd, "200 OK", buf);
    }
}

void mgmt_api_auth_setup(mgmt_api_ctx_t *ctx) {
    if (!mgmt_auth_needs_setup(ctx->config)) {
        send_error(ctx->client_fd, "403 Forbidden", "Setup already completed");
        return;
    }

    char username[64] = {0}, password[256] = {0};
    if (json_extract_string(ctx->body, "username", username, sizeof(username)) != 0 ||
        json_extract_string(ctx->body, "password", password, sizeof(password)) != 0) {
        send_error(ctx->client_fd, "400 Bad Request", "Missing username or password");
        return;
    }

    if (strlen(username) < 3) {
        send_error(ctx->client_fd, "400 Bad Request", "Username must be at least 3 characters");
        return;
    }
    if (strlen(password) < 8) {
        send_error(ctx->client_fd, "400 Bad Request", "Password must be at least 8 characters");
        return;
    }

    char hash[128];
    if (mgmt_auth_hash_password(password, hash, sizeof(hash)) != 0) {
        send_error(ctx->client_fd, "500 Internal Server Error", "Password hashing failed");
        return;
    }

    /* Update config */
    strncpy(ctx->config->mgmt_admin_user, username, sizeof(ctx->config->mgmt_admin_user) - 1);
    strncpy(ctx->config->mgmt_admin_pass_hash, hash, sizeof(ctx->config->mgmt_admin_pass_hash) - 1);
    ctx->config->mgmt_enabled = 1;

    /* Save config */
    if (ctx->config_path && ctx->config_path[0]) {
        pq_server_config_save(ctx->config, ctx->config_path);
    }

    /* Create session */
    char token[MGMT_TOKEN_HEX_LEN + 1];
    if (mgmt_auth_create_session(username, token) != 0) {
        send_error(ctx->client_fd, "500 Internal Server Error", "Session creation failed");
        return;
    }

    char resp[256];
    snprintf(resp, sizeof(resp), "{\"status\":\"ok\",\"token\":\"%s\"}", token);
    send_json_with_cookie(ctx->client_fd, resp, token);
}

/* ======================================================================== */
/* Config GET — full config as JSON                                          */
/* ======================================================================== */

void mgmt_api_config_get(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    const pq_server_config_t *cfg = ctx->config;
    char buf[16384];
    json_builder_t jb;
    jb_init(&jb, buf, sizeof(buf));

    jb_object_start(&jb);

    /* listen */
    jb_key(&jb, "listen");
    jb_object_start(&jb);
    jb_key_str(&jb, "address", cfg->bind_address);
    jb_key_int(&jb, "port", cfg->listen_port);
    jb_object_end(&jb);

    /* tls */
    jb_key(&jb, "tls");
    jb_object_start(&jb);
    jb_key_str(&jb, "cert", cfg->cert_file);
    jb_key_str(&jb, "key", cfg->key_file);
    jb_key_str(&jb, "ca", cfg->ca_file);
    jb_key_bool(&jb, "client_auth", cfg->require_client_auth);
    jb_key_str(&jb, "groups", cfg->tls_groups);
    jb_key_str(&jb, "min_version", cfg->tls_min_version == 0x0303 ? "1.2" : "1.3");
    jb_key_int(&jb, "session_cache_size", cfg->session_cache_size);
    jb_object_end(&jb);

    /* upstreams */
    jb_key(&jb, "upstreams");
    jb_object_start(&jb);
    jb_key(&jb, "backends");
    jb_array_start(&jb);
    for (int i = 0; i < cfg->upstream_count; i++) {
        const pq_upstream_t *u = &cfg->upstreams[i];
        jb_object_start(&jb);
        jb_key_str(&jb, "host", u->host);
        jb_key_int(&jb, "port", u->port);
        jb_key_int(&jb, "weight", u->weight);
        jb_key_bool(&jb, "use_tls", u->use_tls);
        jb_key_bool(&jb, "healthy", atomic_load(&ctx->mgr->upstream_healthy[i]));
        jb_object_end(&jb);
    }
    jb_array_end(&jb);
    jb_key_int(&jb, "timeout_ms", cfg->upstream_timeout_ms);
    jb_key_int(&jb, "connect_timeout_ms", cfg->upstream_connect_timeout_ms);
    jb_object_end(&jb);

    /* server */
    jb_key(&jb, "server");
    jb_object_start(&jb);
    jb_key_int(&jb, "workers", cfg->worker_threads);
    jb_key_int(&jb, "max_connections", cfg->max_connections);
    jb_key_bool(&jb, "daemonize", cfg->daemonize);
    jb_key_str(&jb, "pid_file", cfg->pid_file);
    jb_object_end(&jb);

    /* logging */
    jb_key(&jb, "logging");
    jb_object_start(&jb);
    jb_key_str(&jb, "file", cfg->log_file);
    {
        const char *levels[] = {"debug", "info", "warn", "error"};
        int lvl = cfg->log_level;
        if (lvl < 0) lvl = 0; if (lvl > 3) lvl = 3;
        jb_key_str(&jb, "level", levels[lvl]);
    }
    jb_key_bool(&jb, "access_log", cfg->access_log);
    jb_key_bool(&jb, "json", cfg->json_logging);
    jb_object_end(&jb);

    /* rate_limit */
    jb_key(&jb, "rate_limit");
    jb_object_start(&jb);
    jb_key_int(&jb, "per_ip", cfg->rate_limit_per_ip);
    jb_key_int(&jb, "burst", cfg->rate_limit_burst);
    jb_object_end(&jb);

    /* acl */
    jb_key(&jb, "acl");
    jb_object_start(&jb);
    {
        const char *mode = "disabled";
        if (cfg->acl_mode == PQ_ACL_MODE_ALLOWLIST) mode = "allowlist";
        else if (cfg->acl_mode == PQ_ACL_MODE_BLOCKLIST) mode = "blocklist";
        jb_key_str(&jb, "mode", mode);
    }
    jb_key(&jb, "entries");
    jb_array_start(&jb);
    for (int i = 0; i < cfg->acl_count; i++) {
        jb_val_str(&jb, cfg->acl_entries[i]);
    }
    jb_array_end(&jb);
    jb_object_end(&jb);

    /* health */
    jb_key(&jb, "health");
    jb_object_start(&jb);
    jb_key_int(&jb, "port", cfg->health_port);
    jb_object_end(&jb);

    /* restart_pending */
    jb_key_bool(&jb, "restart_pending", atomic_load(&ctx->mgr->restart_pending));

    jb_object_end(&jb);
    if (jb_finish(&jb) == 0) {
        send_error(ctx->client_fd, "500 Internal Server Error", "Config too large");
        return;
    }

    send_json(ctx->client_fd, "200 OK", buf);
}

/* ======================================================================== */
/* Config PUT handlers                                                       */
/* ======================================================================== */

static void save_and_respond(mgmt_api_ctx_t *ctx, int restart_required) {
    if (ctx->config_path && ctx->config_path[0]) {
        pq_server_config_save(ctx->config, ctx->config_path);
    }

    if (restart_required) {
        atomic_store(&ctx->mgr->restart_pending, 1);
    }

    char buf[128];
    snprintf(buf, sizeof(buf),
             "{\"status\":\"%s\",\"restart_required\":%s}",
             restart_required ? "saved" : "applied",
             restart_required ? "true" : "false");
    send_json(ctx->client_fd, "200 OK", buf);
}

void mgmt_api_config_put_listen(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    char address[64];
    long port;

    if (json_extract_string(ctx->body, "address", address, sizeof(address)) == 0)
        strncpy(ctx->config->bind_address, address, sizeof(ctx->config->bind_address) - 1);
    if (json_extract_int(ctx->body, "port", &port) == 0 && port > 0 && port <= 65535)
        ctx->config->listen_port = (uint16_t)port;

    save_and_respond(ctx, 1); /* Always requires restart */
}

void mgmt_api_config_put_tls(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    char groups[512], min_ver[8], cert[1024], key[1024], ca[1024];
    long cache;
    int client_auth;

    if (json_extract_string(ctx->body, "groups", groups, sizeof(groups)) == 0)
        strncpy(ctx->config->tls_groups, groups, sizeof(ctx->config->tls_groups) - 1);
    if (json_extract_string(ctx->body, "min_version", min_ver, sizeof(min_ver)) == 0) {
        if (strcmp(min_ver, "1.2") == 0) ctx->config->tls_min_version = 0x0303;
        else if (strcmp(min_ver, "1.3") == 0) ctx->config->tls_min_version = 0x0304;
    }
    if (json_extract_string(ctx->body, "cert", cert, sizeof(cert)) == 0)
        strncpy(ctx->config->cert_file, cert, sizeof(ctx->config->cert_file) - 1);
    if (json_extract_string(ctx->body, "key", key, sizeof(key)) == 0)
        strncpy(ctx->config->key_file, key, sizeof(ctx->config->key_file) - 1);
    if (json_extract_string(ctx->body, "ca", ca, sizeof(ca)) == 0)
        strncpy(ctx->config->ca_file, ca, sizeof(ctx->config->ca_file) - 1);
    if (json_extract_int(ctx->body, "session_cache_size", &cache) == 0)
        ctx->config->session_cache_size = (int)cache;
    if (json_extract_bool(ctx->body, "client_auth", &client_auth) == 0)
        ctx->config->require_client_auth = client_auth;

    save_and_respond(ctx, 1); /* TLS config requires restart */
}

void mgmt_api_config_tls_reload(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    if (pq_conn_manager_reload(ctx->mgr) == 0) {
        send_json(ctx->client_fd, "200 OK", "{\"status\":\"ok\"}");
    } else {
        send_error(ctx->client_fd, "500 Internal Server Error", "Certificate reload failed");
    }
}

void mgmt_api_config_put_upstreams(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    long timeout, connect_timeout;

    if (json_extract_int(ctx->body, "timeout_ms", &timeout) == 0)
        ctx->config->upstream_timeout_ms = (int)timeout;
    if (json_extract_int(ctx->body, "connect_timeout_ms", &connect_timeout) == 0)
        ctx->config->upstream_connect_timeout_ms = (int)connect_timeout;

    /* Parse backends array */
    /* Simple approach: count how many "host" keys we find */
    json_parser_t jp;
    jp_init(&jp, ctx->body, ctx->body_len);

    if (jp_next(&jp) == JSON_TOK_OBJECT_START) {
        while (1) {
            json_tok_type_t t = jp_next(&jp);
            if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_END) break;
            if (t != JSON_TOK_STRING) continue;

            char kbuf[64];
            jp_string_value(&jp, kbuf, sizeof(kbuf));
            jp_next(&jp); /* colon */

            if (strcmp(kbuf, "backends") == 0) {
                t = jp_next(&jp);
                if (t != JSON_TOK_ARRAY_START) break;

                ctx->config->upstream_count = 0;
                while (1) {
                    t = jp_next(&jp);
                    if (t == JSON_TOK_ARRAY_END) break;
                    if (t != JSON_TOK_OBJECT_START) continue;

                    if (ctx->config->upstream_count >= PQ_MAX_UPSTREAMS) break;

                    pq_upstream_t *u = &ctx->config->upstreams[ctx->config->upstream_count];
                    memset(u, 0, sizeof(*u));
                    u->weight = 1;

                    while (1) {
                        t = jp_next(&jp);
                        if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_END) break;
                        if (t != JSON_TOK_STRING) continue;

                        char field[64];
                        jp_string_value(&jp, field, sizeof(field));
                        jp_next(&jp); /* colon */
                        t = jp_next(&jp);

                        if (strcmp(field, "host") == 0 && t == JSON_TOK_STRING)
                            jp_string_value(&jp, u->host, sizeof(u->host));
                        else if (strcmp(field, "port") == 0 && t == JSON_TOK_NUMBER)
                            u->port = (uint16_t)jp_int_value(&jp);
                        else if (strcmp(field, "weight") == 0 && t == JSON_TOK_NUMBER)
                            u->weight = (int)jp_int_value(&jp);
                        else if (strcmp(field, "use_tls") == 0 && t == JSON_TOK_BOOL)
                            u->use_tls = jp_bool_value(&jp);
                    }

                    if (u->host[0]) ctx->config->upstream_count++;
                }
                break;
            } else {
                /* Skip value — handle nested objects/arrays */
                json_tok_type_t vt = jp_next(&jp);
                if (vt == JSON_TOK_OBJECT_START || vt == JSON_TOK_ARRAY_START) {
                    int depth = 1;
                    while (depth > 0) {
                        vt = jp_next(&jp);
                        if (vt == JSON_TOK_OBJECT_START || vt == JSON_TOK_ARRAY_START) depth++;
                        else if (vt == JSON_TOK_OBJECT_END || vt == JSON_TOK_ARRAY_END) depth--;
                        else if (vt == JSON_TOK_END || vt == JSON_TOK_ERROR) break;
                    }
                }
            }
        }
    }

    save_and_respond(ctx, 1); /* Upstreams require restart */
}

void mgmt_api_config_put_server(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    long workers, max_conns;
    if (json_extract_int(ctx->body, "workers", &workers) == 0)
        ctx->config->worker_threads = (int)workers;
    if (json_extract_int(ctx->body, "max_connections", &max_conns) == 0)
        ctx->config->max_connections = (int)max_conns;

    save_and_respond(ctx, 1);
}

void mgmt_api_config_put_logging(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    char level[16], file[1024];
    int access_log, json_log;
    int restart_needed = 0;

    if (json_extract_string(ctx->body, "level", level, sizeof(level)) == 0) {
        int new_level = -1;
        if (strcmp(level, "debug") == 0) new_level = 0;
        else if (strcmp(level, "info") == 0) new_level = 1;
        else if (strcmp(level, "warn") == 0) new_level = 2;
        else if (strcmp(level, "error") == 0) new_level = 3;

        if (new_level >= 0) {
            ctx->config->log_level = new_level;
            /* Log level can be applied at runtime */
        }
    }

    if (json_extract_string(ctx->body, "file", file, sizeof(file)) == 0) {
        if (strcmp(file, ctx->config->log_file) != 0) {
            strncpy(ctx->config->log_file, file, sizeof(ctx->config->log_file) - 1);
            restart_needed = 1;
        }
    }

    if (json_extract_bool(ctx->body, "access_log", &access_log) == 0)
        ctx->config->access_log = access_log;
    if (json_extract_bool(ctx->body, "json", &json_log) == 0) {
        if (json_log != ctx->config->json_logging) {
            ctx->config->json_logging = json_log;
            restart_needed = 1;
        }
    }

    save_and_respond(ctx, restart_needed);
}

void mgmt_api_config_put_rate_limit(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    long per_ip, burst;
    if (json_extract_int(ctx->body, "per_ip", &per_ip) == 0)
        ctx->config->rate_limit_per_ip = (int)per_ip;
    if (json_extract_int(ctx->body, "burst", &burst) == 0)
        ctx->config->rate_limit_burst = (int)burst;

    /* Apply at runtime */
    pq_rate_limiter_destroy();
    if (ctx->config->rate_limit_per_ip > 0) {
        int b = ctx->config->rate_limit_burst;
        if (b <= 0) b = ctx->config->rate_limit_per_ip * 2;
        pq_rate_limiter_init(ctx->config->rate_limit_per_ip, b);
    }

    save_and_respond(ctx, 0); /* Runtime reloadable */
}

void mgmt_api_config_put_acl(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    char mode_str[32];
    pq_acl_mode_t new_mode = ctx->config->acl_mode;

    if (json_extract_string(ctx->body, "mode", mode_str, sizeof(mode_str)) == 0) {
        if (strcmp(mode_str, "allowlist") == 0) new_mode = PQ_ACL_MODE_ALLOWLIST;
        else if (strcmp(mode_str, "blocklist") == 0) new_mode = PQ_ACL_MODE_BLOCKLIST;
        else new_mode = PQ_ACL_MODE_DISABLED;
    }

    ctx->config->acl_mode = new_mode;
    ctx->config->acl_count = 0;

    /* Parse entries array */
    json_parser_t jp;
    jp_init(&jp, ctx->body, ctx->body_len);

    if (jp_next(&jp) == JSON_TOK_OBJECT_START) {
        while (1) {
            json_tok_type_t t = jp_next(&jp);
            if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_END) break;
            if (t != JSON_TOK_STRING) continue;

            char kbuf[64];
            jp_string_value(&jp, kbuf, sizeof(kbuf));
            jp_next(&jp); /* colon */

            if (strcmp(kbuf, "entries") == 0) {
                t = jp_next(&jp);
                if (t != JSON_TOK_ARRAY_START) break;

                while (1) {
                    t = jp_next(&jp);
                    if (t == JSON_TOK_ARRAY_END) break;
                    if (t == JSON_TOK_STRING && ctx->config->acl_count < PQ_MAX_ACL) {
                        jp_string_value(&jp, ctx->config->acl_entries[ctx->config->acl_count], 64);
                        ctx->config->acl_count++;
                    }
                }
                break;
            } else {
                /* Skip value — handle nested objects/arrays */
                json_tok_type_t vt = jp_next(&jp);
                if (vt == JSON_TOK_OBJECT_START || vt == JSON_TOK_ARRAY_START) {
                    int depth = 1;
                    while (depth > 0) {
                        vt = jp_next(&jp);
                        if (vt == JSON_TOK_OBJECT_START || vt == JSON_TOK_ARRAY_START) depth++;
                        else if (vt == JSON_TOK_OBJECT_END || vt == JSON_TOK_ARRAY_END) depth--;
                        else if (vt == JSON_TOK_END || vt == JSON_TOK_ERROR) break;
                    }
                }
            }
        }
    }

    /* Apply at runtime */
    pq_acl_destroy();
    if (new_mode != PQ_ACL_MODE_DISABLED) {
        pq_acl_init(new_mode);
        for (int i = 0; i < ctx->config->acl_count; i++) {
            pq_acl_add(ctx->config->acl_entries[i]);
        }
    }

    save_and_respond(ctx, 0); /* Runtime reloadable */
}

/* ======================================================================== */
/* Certificate endpoints                                                     */
/* ======================================================================== */

void mgmt_api_certs_list(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    const char *store = ctx->config->cert_store_path;
    if (!store[0]) store = "certs";

    cert_info_t certs[CERT_MAX_STORE];
    int count = cert_list_store(store, certs, CERT_MAX_STORE);

    /* Also include the active server cert */
    cert_info_t active;
    int has_active = (cert_parse_pem_file(ctx->config->cert_file, &active) == 0);

    char buf[16384];
    json_builder_t jb;
    jb_init(&jb, buf, sizeof(buf));
    jb_object_start(&jb);

    if (has_active) {
        jb_key(&jb, "active");
        jb_object_start(&jb);
        jb_key_str(&jb, "file", ctx->config->cert_file);
        jb_key_str(&jb, "subject", active.subject);
        jb_key_str(&jb, "issuer", active.issuer);
        jb_key_str(&jb, "not_after", active.not_after);
        jb_key_str(&jb, "key_type", active.key_type);
        jb_key_str(&jb, "sig_algo", active.sig_algo);
        jb_key_str(&jb, "fingerprint", active.fingerprint);
        jb_key_int(&jb, "days_remaining", active.days_remaining);
        jb_key_bool(&jb, "self_signed", active.is_self_signed);
        jb_object_end(&jb);
    }

    jb_key(&jb, "store");
    jb_array_start(&jb);
    for (int i = 0; i < count; i++) {
        jb_object_start(&jb);
        jb_key_str(&jb, "filename", certs[i].filename);
        jb_key_str(&jb, "subject", certs[i].subject);
        jb_key_str(&jb, "issuer", certs[i].issuer);
        jb_key_str(&jb, "not_after", certs[i].not_after);
        jb_key_str(&jb, "key_type", certs[i].key_type);
        jb_key_str(&jb, "fingerprint", certs[i].fingerprint);
        jb_key_int(&jb, "days_remaining", certs[i].days_remaining);
        jb_key_bool(&jb, "self_signed", certs[i].is_self_signed);
        jb_object_end(&jb);
    }
    jb_array_end(&jb);

    jb_object_end(&jb);
    jb_finish(&jb);

    send_json(ctx->client_fd, "200 OK", buf);
}

void mgmt_api_certs_generate(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    char cn[128] = {0}, org[128] = {0}, country[8] = {0};
    char key_type[16] = "rsa", sans[512] = {0};
    long days = 365;

    json_extract_string(ctx->body, "cn", cn, sizeof(cn));
    json_extract_string(ctx->body, "org", org, sizeof(org));
    json_extract_string(ctx->body, "country", country, sizeof(country));
    json_extract_string(ctx->body, "key_type", key_type, sizeof(key_type));
    json_extract_int(ctx->body, "days", &days);
    json_extract_string(ctx->body, "sans", sans, sizeof(sans));

    if (!cn[0]) {
        send_error(ctx->client_fd, "400 Bad Request", "Common Name (cn) is required");
        return;
    }
    if (!validate_path_name(cn)) {
        send_error(ctx->client_fd, "400 Bad Request", "Invalid common name for filename");
        return;
    }

    const char *store = ctx->config->cert_store_path;
    if (!store[0]) store = "certs";

    char cert_path[2048], key_path[2048];
    snprintf(cert_path, sizeof(cert_path), "%s/%s.pem", store, cn);
    snprintf(key_path, sizeof(key_path), "%s/%s-key.pem", store, cn);

    if (cert_generate_self_signed(cn, org[0] ? org : NULL,
                                   country[0] ? country : NULL,
                                   key_type, (int)days,
                                   sans[0] ? sans : NULL,
                                   cert_path, key_path) != 0) {
        send_error(ctx->client_fd, "500 Internal Server Error", "Certificate generation failed");
        return;
    }

    char buf[512];
    json_builder_t jb;
    jb_init(&jb, buf, sizeof(buf));
    jb_object_start(&jb);
    jb_key_str(&jb, "status", "ok");
    jb_key_str(&jb, "cert_file", cert_path);
    jb_key_str(&jb, "key_file", key_path);
    jb_object_end(&jb);
    jb_finish(&jb);
    send_json(ctx->client_fd, "200 OK", buf);
}

void mgmt_api_certs_upload(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    /* For simplicity, accept JSON with base64/PEM content */
    char name[128] = {0};
    json_extract_string(ctx->body, "name", name, sizeof(name));
    if (!name[0]) {
        send_error(ctx->client_fd, "400 Bad Request", "Certificate name is required");
        return;
    }
    if (!validate_path_name(name)) {
        send_error(ctx->client_fd, "400 Bad Request", "Invalid certificate name");
        return;
    }

    /* Find cert_pem and key_pem in body */
    char cert_pem[8192] = {0}, key_pem[8192] = {0};
    json_extract_string(ctx->body, "cert_pem", cert_pem, sizeof(cert_pem));
    json_extract_string(ctx->body, "key_pem", key_pem, sizeof(key_pem));

    if (!cert_pem[0]) {
        send_error(ctx->client_fd, "400 Bad Request", "cert_pem is required");
        return;
    }

    const char *store = ctx->config->cert_store_path;
    if (!store[0]) store = "certs";

    if (cert_save_upload(store, name, cert_pem, strlen(cert_pem),
                         key_pem[0] ? key_pem : NULL,
                         key_pem[0] ? strlen(key_pem) : 0) != 0) {
        send_error(ctx->client_fd, "500 Internal Server Error", "Upload failed");
        return;
    }

    send_json(ctx->client_fd, "200 OK", "{\"status\":\"ok\"}");
}

void mgmt_api_certs_apply(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    /* Extract cert name from path: /api/certs/{name}/apply */
    const char *p = ctx->path + strlen("/api/certs/");
    char name[256];
    const char *slash = strchr(p, '/');
    if (slash) {
        size_t len = (size_t)(slash - p);
        if (len >= sizeof(name)) len = sizeof(name) - 1;
        memcpy(name, p, len);
        name[len] = '\0';
    } else {
        send_error(ctx->client_fd, "400 Bad Request", "Invalid path");
        return;
    }
    if (!validate_path_name(name)) {
        send_error(ctx->client_fd, "400 Bad Request", "Invalid certificate name");
        return;
    }

    const char *store = ctx->config->cert_store_path;
    if (!store[0]) store = "certs";

    char cert_src[2048], key_src[2048];
    snprintf(cert_src, sizeof(cert_src), "%s/%s.pem", store, name);
    snprintf(key_src, sizeof(key_src), "%s/%s-key.pem", store, name);

    if (cert_apply(cert_src, key_src,
                   ctx->config->cert_file, ctx->config->key_file) != 0) {
        send_error(ctx->client_fd, "500 Internal Server Error", "Certificate apply failed");
        return;
    }

    /* Trigger TLS reload */
    pq_conn_manager_reload(ctx->mgr);

    send_json(ctx->client_fd, "200 OK", "{\"status\":\"ok\",\"reloaded\":true}");
}

void mgmt_api_certs_details(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    /* Extract cert name from path: /api/certs/{name}/details */
    const char *p = ctx->path + strlen("/api/certs/");
    char name[256];
    const char *slash = strchr(p, '/');
    if (slash) {
        size_t len = (size_t)(slash - p);
        if (len >= sizeof(name)) len = sizeof(name) - 1;
        memcpy(name, p, len);
        name[len] = '\0';
    } else {
        send_error(ctx->client_fd, "400 Bad Request", "Invalid path");
        return;
    }
    if (!validate_path_name(name)) {
        send_error(ctx->client_fd, "400 Bad Request", "Invalid certificate name");
        return;
    }

    const char *store = ctx->config->cert_store_path;
    if (!store[0]) store = "certs";

    char cert_path[2048];
    snprintf(cert_path, sizeof(cert_path), "%s/%s.pem", store, name);

    cert_info_t info;
    if (cert_parse_pem_file(cert_path, &info) != 0) {
        send_error(ctx->client_fd, "404 Not Found", "Certificate not found");
        return;
    }

    char buf[2048];
    json_builder_t jb;
    jb_init(&jb, buf, sizeof(buf));
    jb_object_start(&jb);
    jb_key_str(&jb, "filename", info.filename);
    jb_key_str(&jb, "subject", info.subject);
    jb_key_str(&jb, "issuer", info.issuer);
    jb_key_str(&jb, "not_before", info.not_before);
    jb_key_str(&jb, "not_after", info.not_after);
    jb_key_str(&jb, "key_type", info.key_type);
    jb_key_str(&jb, "sig_algo", info.sig_algo);
    jb_key_str(&jb, "fingerprint", info.fingerprint);
    jb_key_int(&jb, "days_remaining", info.days_remaining);
    jb_key_bool(&jb, "self_signed", info.is_self_signed);
    jb_object_end(&jb);
    jb_finish(&jb);

    send_json(ctx->client_fd, "200 OK", buf);
}

/* ======================================================================== */
/* Management endpoints                                                      */
/* ======================================================================== */

void mgmt_api_mgmt_status(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    char buf[2048];
    json_builder_t jb;
    jb_init(&jb, buf, sizeof(buf));
    jb_object_start(&jb);

    jb_key_str(&jb, "version", "2.0.0");
    jb_key_int(&jb, "pid", (long)getpid());
    jb_key_bool(&jb, "restart_pending", atomic_load(&ctx->mgr->restart_pending));
    jb_key_int(&jb, "active_connections", atomic_load(&ctx->mgr->active_connections));
    jb_key_int(&jb, "total_connections", atomic_load(&ctx->mgr->total_connections));
    jb_key_int(&jb, "workers", ctx->mgr->worker_count);

    /* OQS provider status */
    jb_key_bool(&jb, "oqs_available", ctx->mgr->oqs_provider != NULL);

    /* Uptime — use server start time */
    jb_key_int(&jb, "uptime_seconds", (long)(time(NULL) - ctx->mgr->start_time));

    jb_object_end(&jb);
    jb_finish(&jb);

    send_json(ctx->client_fd, "200 OK", buf);
}

void mgmt_api_mgmt_restart(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    int confirm = 0;
    json_extract_bool(ctx->body, "confirm", &confirm);
    if (!confirm) {
        send_error(ctx->client_fd, "400 Bad Request", "Confirmation required");
        return;
    }

    send_json(ctx->client_fd, "200 OK", "{\"status\":\"ok\",\"restarting\":true}");

    /* Signal restart */
    atomic_store(&ctx->mgr->restart_pending, 2); /* 2 = restart now */
    pq_conn_manager_stop(ctx->mgr);
}

/* ======================================================================== */
/* Log endpoints                                                             */
/* ======================================================================== */

void mgmt_api_logs_stream(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;
    log_streamer_stream_sse(ctx->client_fd);
}

void mgmt_api_logs_recent(mgmt_api_ctx_t *ctx) {
    if (!require_auth(ctx)) return;

    int count = 100;
    /* Parse ?lines=N from path */
    const char *q = strchr(ctx->path, '?');
    if (q) {
        const char *lines_param = strstr(q, "lines=");
        if (lines_param) count = atoi(lines_param + 6);
    }
    if (count <= 0) count = 100;
    if (count > LOG_RING_SIZE) count = LOG_RING_SIZE;

    char buf[65536];
    int n = log_streamer_recent(buf, sizeof(buf), count);
    (void)n;
    send_http(ctx->client_fd, "200 OK", "application/json", buf, strlen(buf));
}

/* ======================================================================== */
/* Crypto-agility endpoints                                                  */
/* ======================================================================== */

void mgmt_api_algorithms(mgmt_api_ctx_t *ctx) {
    /* /api/algorithms — public endpoint showing available algorithms */
    pq_registry_t *reg = ctx->mgr ? ctx->mgr->crypto_registry : NULL;
    if (!reg) {
        send_http(ctx->client_fd, "503 Service Unavailable",
                  "application/json",
                  "{\"error\":\"crypto registry not initialized\"}", 0);
        return;
    }

    char buf[8192];
    int len = pq_registry_to_json(reg, buf, sizeof(buf));
    if (len <= 0) {
        send_http(ctx->client_fd, "500 Internal Server Error",
                  "application/json",
                  "{\"error\":\"failed to serialize registry\"}", 0);
        return;
    }
    send_http(ctx->client_fd, "200 OK", "application/json", buf, (size_t)len);
}

/* ======================================================================== */
/* Request dispatcher                                                        */
/* ======================================================================== */

int mgmt_api_dispatch(mgmt_api_ctx_t *ctx) {
    const char *m = ctx->method;
    const char *p = ctx->path;

    /* CORS preflight */
    if (strcmp(m, "OPTIONS") == 0) {
        send_http(ctx->client_fd, "204 No Content",
                  "text/plain", NULL, 0);
        return 1;
    }

    /* Auth endpoints (no auth required) */
    if (strcmp(p, "/api/auth/login") == 0 && strcmp(m, "POST") == 0) {
        mgmt_api_auth_login(ctx); return 1;
    }
    if (strcmp(p, "/api/auth/logout") == 0 && strcmp(m, "POST") == 0) {
        mgmt_api_auth_logout(ctx); return 1;
    }
    if (strcmp(p, "/api/auth/status") == 0 && strcmp(m, "GET") == 0) {
        mgmt_api_auth_status(ctx); return 1;
    }
    if (strcmp(p, "/api/auth/setup") == 0 && strcmp(m, "POST") == 0) {
        mgmt_api_auth_setup(ctx); return 1;
    }

    /* Config endpoints */
    if (strcmp(p, "/api/config") == 0 && strcmp(m, "GET") == 0) {
        mgmt_api_config_get(ctx); return 1;
    }
    if (strcmp(p, "/api/config/listen") == 0 && strcmp(m, "PUT") == 0) {
        mgmt_api_config_put_listen(ctx); return 1;
    }
    if (strcmp(p, "/api/config/tls") == 0 && strcmp(m, "PUT") == 0) {
        mgmt_api_config_put_tls(ctx); return 1;
    }
    if (strcmp(p, "/api/config/tls/reload") == 0 && strcmp(m, "POST") == 0) {
        mgmt_api_config_tls_reload(ctx); return 1;
    }
    if (strcmp(p, "/api/config/upstreams") == 0 && strcmp(m, "PUT") == 0) {
        mgmt_api_config_put_upstreams(ctx); return 1;
    }
    if (strcmp(p, "/api/config/server") == 0 && strcmp(m, "PUT") == 0) {
        mgmt_api_config_put_server(ctx); return 1;
    }
    if (strcmp(p, "/api/config/logging") == 0 && strcmp(m, "PUT") == 0) {
        mgmt_api_config_put_logging(ctx); return 1;
    }
    if (strcmp(p, "/api/config/rate_limit") == 0 && strcmp(m, "PUT") == 0) {
        mgmt_api_config_put_rate_limit(ctx); return 1;
    }
    if (strcmp(p, "/api/config/acl") == 0 && strcmp(m, "PUT") == 0) {
        mgmt_api_config_put_acl(ctx); return 1;
    }

    /* Certificate endpoints */
    if (strcmp(p, "/api/certs") == 0 && strcmp(m, "GET") == 0) {
        mgmt_api_certs_list(ctx); return 1;
    }
    if (strcmp(p, "/api/certs/upload") == 0 && strcmp(m, "POST") == 0) {
        mgmt_api_certs_upload(ctx); return 1;
    }
    if (strcmp(p, "/api/certs/generate") == 0 && strcmp(m, "POST") == 0) {
        mgmt_api_certs_generate(ctx); return 1;
    }
    if (strncmp(p, "/api/certs/", 11) == 0 && strstr(p, "/apply") && strcmp(m, "POST") == 0) {
        mgmt_api_certs_apply(ctx); return 1;
    }
    if (strncmp(p, "/api/certs/", 11) == 0 && strstr(p, "/details") && strcmp(m, "GET") == 0) {
        mgmt_api_certs_details(ctx); return 1;
    }

    /* Management endpoints */
    if (strcmp(p, "/api/mgmt/status") == 0 && strcmp(m, "GET") == 0) {
        mgmt_api_mgmt_status(ctx); return 1;
    }
    if (strcmp(p, "/api/mgmt/restart") == 0 && strcmp(m, "POST") == 0) {
        mgmt_api_mgmt_restart(ctx); return 1;
    }

    /* Log endpoints */
    if (strcmp(p, "/api/logs/stream") == 0 && strcmp(m, "GET") == 0) {
        mgmt_api_logs_stream(ctx); return 1;
    }
    if (strncmp(p, "/api/logs/recent", 16) == 0 && strcmp(m, "GET") == 0) {
        mgmt_api_logs_recent(ctx); return 1;
    }

    /* Crypto-agility endpoints */
    if (strcmp(p, "/api/algorithms") == 0 && strcmp(m, "GET") == 0) {
        mgmt_api_algorithms(ctx); return 1;
    }

    return 0; /* Not handled */
}
