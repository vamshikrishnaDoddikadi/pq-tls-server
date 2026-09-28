/**
 * @file server_config.c
 * @brief PQ-TLS Server Configuration Parser
 *
 * Invalid values are reported with file/line context and make loading fail,
 * rather than being silently replaced by defaults: a proxy that starts with
 * a configuration different from the one the operator wrote is worse than
 * one that refuses to start.
 *
 * @author Vamshi Krishna Doddikadi
 */

#include "server_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>

/* ======================================================================== */
/* Helpers                                                                  */
/* ======================================================================== */

static void trim(char *s) {
    if (!s) return;
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    if (*start == '\0') { s[0] = '\0'; return; }
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
    if (start != s) memmove(s, start, strlen(start) + 1);
}

static void safe_copy(char *dst, const char *src, size_t size) {
    if (!dst || !src || size == 0) return;
    size_t len = strlen(src);
    if (len >= size) len = size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Strict integer parse: whole string must be a base-10 number in [min,max]. */
static int parse_long(const char *s, long min, long max, long *out) {
    if (!s || !*s) return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s) return -1;
    while (*end && isspace((unsigned char)*end)) end++;
    if (*end != '\0' || v < min || v > max) return -1;
    *out = v;
    return 0;
}

static int parse_bool(const char *s, int *out) {
    if (!strcasecmp(s, "true") || !strcmp(s, "1") || !strcasecmp(s, "yes") || !strcasecmp(s, "on")) {
        *out = 1;
        return 0;
    }
    if (!strcasecmp(s, "false") || !strcmp(s, "0") || !strcasecmp(s, "no") || !strcasecmp(s, "off")) {
        *out = 0;
        return 0;
    }
    return -1;
}

/**
 * Parse "host:port" into an upstream.  weight defaults to 1.
 * Supports "unix:/path/to/sock", "[v6addr]:port", "tls://" and "http://"
 * prefixes and a ";weight=N" suffix.
 * @return 0 on success, -1 on a malformed specification.
 */
static int parse_upstream(const char *str, pq_upstream_t *u) {
    memset(u, 0, sizeof(*u));
    u->weight = 1;

    if (strncmp(str, "unix:", 5) == 0) {
        if (str[5] == '\0' || strlen(str) >= sizeof(u->host)) return -1;
        safe_copy(u->host, str, sizeof(u->host));
        return 0;
    }

    const char *p = str;
    if (strncmp(p, "tls://", 6) == 0) {
        u->use_tls = 1;
        p += 6;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }

    char buf[512];
    if (strlen(p) >= sizeof(buf)) return -1;
    safe_copy(buf, p, sizeof(buf));

    char *semi = strchr(buf, ';');
    if (semi) {
        *semi = '\0';
        const char *opt = semi + 1;
        if (strncmp(opt, "weight=", 7) != 0) return -1;
        long w;
        if (parse_long(opt + 7, 1, 100, &w) != 0) return -1;
        u->weight = (int)w;
    }

    const char *host = buf;
    const char *port_str = NULL;
    if (buf[0] == '[') {                        /* [IPv6]:port */
        char *rb = strchr(buf, ']');
        if (!rb) return -1;
        *rb = '\0';
        host = buf + 1;
        if (rb[1] == ':') port_str = rb + 2;
        else if (rb[1] != '\0') return -1;
    } else {
        char *colon = strrchr(buf, ':');
        if (colon) {
            *colon = '\0';
            port_str = colon + 1;
        }
    }
    if (!host[0] || strlen(host) >= sizeof(u->host)) return -1;
    safe_copy(u->host, host, sizeof(u->host));

    if (port_str) {
        long v;
        if (parse_long(port_str, 1, 65535, &v) != 0) return -1;
        u->port = (uint16_t)v;
    } else {
        u->port = u->use_tls ? 443 : 80;
    }
    return 0;
}

/* ======================================================================== */
/* Defaults                                                                 */
/* ======================================================================== */

void pq_server_config_defaults(pq_server_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    safe_copy(cfg->bind_address, "0.0.0.0", sizeof(cfg->bind_address));
    cfg->listen_port = 8443;
    /* Hybrid PQ groups first (IETF draft-ietf-tls-ecdhe-mlkem), then
     * classical fallbacks. Groups the loaded providers do not support are
     * skipped at startup. */
    safe_copy(cfg->tls_groups, "X25519MLKEM768:SecP256r1MLKEM768:X25519:P-256",
              sizeof(cfg->tls_groups));
    cfg->require_pq = 0;
    cfg->tls_min_version = 0x0304; /* TLS 1.3 */
    cfg->session_cache_size = 20000;
    cfg->handshake_timeout_ms = 10000;
    cfg->upstream_timeout_ms = 30000;
    cfg->upstream_connect_timeout_ms = 5000;
    cfg->proxy_mode = PQ_PROXY_MODE_HTTP;
    cfg->worker_threads = 0; /* auto */
    cfg->max_connections = 1024;
    cfg->drain_timeout_ms = 10000;
    cfg->log_level = 1; /* INFO */
    cfg->access_log = 1;
    cfg->health_port = 0; /* disabled */
    cfg->rate_limit_per_ip = 0; /* disabled */
    cfg->rate_limit_burst = 0;
    cfg->acl_mode = PQ_ACL_MODE_DISABLED;
    cfg->json_logging = 0;
}

/* ======================================================================== */
/* INI Parser                                                               */
/* ======================================================================== */

typedef enum { KEY_OK = 0, KEY_UNKNOWN = 1, KEY_INVALID = -1 } key_result_t;

#define INT_KEY(name, field, min, max) \
    if (strcmp(key, name) == 0) { \
        long _v; \
        if (parse_long(val, (min), (max), &_v) != 0) return KEY_INVALID; \
        cfg->field = (int)_v; \
        return KEY_OK; \
    }
#define BOOL_KEY(name, field) \
    if (strcmp(key, name) == 0) { \
        int _b; \
        if (parse_bool(val, &_b) != 0) return KEY_INVALID; \
        cfg->field = _b; \
        return KEY_OK; \
    }
#define STR_KEY(name, field) \
    if (strcmp(key, name) == 0) { \
        if (strlen(val) >= sizeof(cfg->field)) return KEY_INVALID; \
        safe_copy(cfg->field, val, sizeof(cfg->field)); \
        return KEY_OK; \
    }

static key_result_t apply_key(pq_server_config_t *cfg, const char *section,
                              const char *key, const char *val) {
    if (strcmp(section, "listen") == 0) {
        STR_KEY("address", bind_address);
        if (strcmp(key, "port") == 0) {
            long v;
            if (parse_long(val, 1, 65535, &v) != 0) return KEY_INVALID;
            cfg->listen_port = (uint16_t)v;
            return KEY_OK;
        }
    } else if (strcmp(section, "tls") == 0) {
        STR_KEY("cert", cert_file);
        STR_KEY("key", key_file);
        STR_KEY("ca", ca_file);
        BOOL_KEY("client_auth", require_client_auth);
        STR_KEY("groups", tls_groups);
        BOOL_KEY("require_pq", require_pq);
        INT_KEY("session_cache_size", session_cache_size, 0, 10000000);
        INT_KEY("handshake_timeout", handshake_timeout_ms, 100, 600000);
        if (strcmp(key, "min_version") == 0) {
            if (strcmp(val, "1.2") == 0)      cfg->tls_min_version = 0x0303;
            else if (strcmp(val, "1.3") == 0) cfg->tls_min_version = 0x0304;
            else return KEY_INVALID;
            return KEY_OK;
        }
    } else if (strcmp(section, "upstream") == 0) {
        if (strcmp(key, "backend") == 0) {
            if (cfg->upstream_count >= PQ_MAX_UPSTREAMS) return KEY_INVALID;
            if (parse_upstream(val, &cfg->upstreams[cfg->upstream_count]) != 0)
                return KEY_INVALID;
            cfg->upstream_count++;
            return KEY_OK;
        }
        INT_KEY("timeout", upstream_timeout_ms, 100, 86400000);
        INT_KEY("connect_timeout", upstream_connect_timeout_ms, 10, 600000);
        if (strcmp(key, "mode") == 0) {
            if (strcmp(val, "http") == 0)     cfg->proxy_mode = PQ_PROXY_MODE_HTTP;
            else if (strcmp(val, "tcp") == 0) cfg->proxy_mode = PQ_PROXY_MODE_TCP;
            else return KEY_INVALID;
            return KEY_OK;
        }
    } else if (strcmp(section, "server") == 0) {
        INT_KEY("workers", worker_threads, 0, 1024);
        INT_KEY("max_connections", max_connections, 1, 1000000);
        INT_KEY("drain_timeout", drain_timeout_ms, 0, 3600000);
        BOOL_KEY("daemonize", daemonize);
        STR_KEY("pid_file", pid_file);
    } else if (strcmp(section, "logging") == 0) {
        STR_KEY("file", log_file);
        BOOL_KEY("access_log", access_log);
        BOOL_KEY("json", json_logging);
        if (strcmp(key, "level") == 0) {
            if (strcmp(val, "debug") == 0)      cfg->log_level = 0;
            else if (strcmp(val, "info") == 0)  cfg->log_level = 1;
            else if (strcmp(val, "warn") == 0)  cfg->log_level = 2;
            else if (strcmp(val, "error") == 0) cfg->log_level = 3;
            else return KEY_INVALID;
            return KEY_OK;
        }
    } else if (strcmp(section, "health") == 0) {
        INT_KEY("port", health_port, 0, 65535);
    } else if (strcmp(section, "rate_limit") == 0) {
        INT_KEY("per_ip", rate_limit_per_ip, 0, 1000000);
        INT_KEY("burst", rate_limit_burst, 0, 1000000);
    } else if (strcmp(section, "acl") == 0) {
        if (strcmp(key, "mode") == 0) {
            if (strcmp(val, "allowlist") == 0)      cfg->acl_mode = PQ_ACL_MODE_ALLOWLIST;
            else if (strcmp(val, "blocklist") == 0) cfg->acl_mode = PQ_ACL_MODE_BLOCKLIST;
            else if (strcmp(val, "disabled") == 0)  cfg->acl_mode = PQ_ACL_MODE_DISABLED;
            else return KEY_INVALID;
            return KEY_OK;
        }
        if (strcmp(key, "entry") == 0) {
            if (cfg->acl_count >= PQ_MAX_ACL || strlen(val) >= 64) return KEY_INVALID;
            safe_copy(cfg->acl_entries[cfg->acl_count], val, 64);
            cfg->acl_count++;
            return KEY_OK;
        }
    } else if (strcmp(section, "mgmt") == 0) {
        STR_KEY("admin_user", mgmt_admin_user);
        STR_KEY("admin_pass_hash", mgmt_admin_pass_hash);
        STR_KEY("totp_secret", mgmt_totp_secret);
        STR_KEY("cert_store", cert_store_path);
        BOOL_KEY("enabled", mgmt_enabled);
        BOOL_KEY("localhost_only", mgmt_localhost_only);
    }
    return KEY_UNKNOWN;
}

#undef INT_KEY
#undef BOOL_KEY
#undef STR_KEY

int pq_server_config_load(pq_server_config_t *cfg, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "config: cannot open '%s': %s\n", path, strerror(errno));
        return -1;
    }

    char line[1024], section[64] = "";
    int lineno = 0, errors = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        if (!strchr(line, '\n') && !feof(fp)) {
            fprintf(stderr, "config: %s:%d: line too long\n", path, lineno);
            errors++;
            int c;
            while ((c = fgetc(fp)) != EOF && c != '\n') {}
            continue;
        }
        trim(line);
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';') continue;

        if (line[0] == '[') {
            char *end = strchr(line, ']');
            if (!end) {
                fprintf(stderr, "config: %s:%d: malformed section header\n", path, lineno);
                errors++;
                continue;
            }
            *end = '\0';
            safe_copy(section, line + 1, sizeof(section));
            trim(section);
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) {
            fprintf(stderr, "config: %s:%d: expected 'key = value'\n", path, lineno);
            errors++;
            continue;
        }
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);

        key_result_t r = apply_key(cfg, section, key, val);
        if (r == KEY_INVALID) {
            fprintf(stderr, "config: %s:%d: invalid value '%s' for [%s] %s\n",
                    path, lineno, val, section, key);
            errors++;
        } else if (r == KEY_UNKNOWN) {
            fprintf(stderr, "config: %s:%d: warning: unknown key [%s] %s (ignored)\n",
                    path, lineno, section, key);
        }
    }

    fclose(fp);
    return errors ? -1 : 0;
}

/* ======================================================================== */
/* CLI Parser                                                               */
/* ======================================================================== */

static int cli_int(const char *opt, const char *arg, long min, long max, long *out) {
    if (parse_long(arg, min, max, out) != 0) {
        fprintf(stderr, "invalid value '%s' for %s (expected %ld-%ld)\n", arg, opt, min, max);
        return -1;
    }
    return 0;
}

int pq_server_config_parse_args(pq_server_config_t *cfg, int argc, char **argv) {
    static struct option long_opts[] = {
        {"port",           required_argument, NULL, 'p'},
        {"cert",           required_argument, NULL, 'c'},
        {"key",            required_argument, NULL, 'k'},
        {"ca",             required_argument, NULL, 'a'},
        {"backend",        required_argument, NULL, 'b'},
        {"workers",        required_argument, NULL, 'w'},
        {"log",            required_argument, NULL, 'l'},
        {"verbose",        no_argument,       NULL, 'v'},
        {"daemon",         no_argument,       NULL, 'd'},
        {"config",         required_argument, NULL, 'f'},
        {"health-port",    required_argument, NULL, 'H'},
        {"groups",         required_argument, NULL, 'g'},
        {"require-pq",     no_argument,       NULL, 'Q'},
        {"rate-limit",     required_argument, NULL, 'R'},
        {"json-log",       no_argument,       NULL, 'j'},
        {"session-cache",  required_argument, NULL, 'S'},
        {"mode",           required_argument, NULL, 'm'},
        {"help",           no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    optind = 1;
    int opt;
    long v;
    while ((opt = getopt_long(argc, argv, "p:c:k:a:b:w:l:vdf:H:g:R:jS:m:hQ",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            if (cli_int("--port", optarg, 1, 65535, &v) != 0) return -1;
            cfg->listen_port = (uint16_t)v;
            break;
        case 'c': safe_copy(cfg->cert_file, optarg, sizeof(cfg->cert_file)); break;
        case 'k': safe_copy(cfg->key_file, optarg, sizeof(cfg->key_file)); break;
        case 'a': safe_copy(cfg->ca_file, optarg, sizeof(cfg->ca_file)); break;
        case 'b':
            if (cfg->upstream_count >= PQ_MAX_UPSTREAMS) {
                fprintf(stderr, "too many backends (max %d)\n", PQ_MAX_UPSTREAMS);
                return -1;
            }
            if (parse_upstream(optarg, &cfg->upstreams[cfg->upstream_count]) != 0) {
                fprintf(stderr, "invalid backend '%s' (expected host:port, [v6]:port, "
                        "unix:/path or host:port;weight=N)\n", optarg);
                return -1;
            }
            cfg->upstream_count++;
            break;
        case 'w':
            if (cli_int("--workers", optarg, 0, 1024, &v) != 0) return -1;
            cfg->worker_threads = (int)v;
            break;
        case 'l': safe_copy(cfg->log_file, optarg, sizeof(cfg->log_file)); break;
        case 'v': cfg->verbose = 1; cfg->log_level = 0; break;
        case 'd': cfg->daemonize = 1; break;
        case 'f':
            /* config file — already loaded before arg parsing */
            break;
        case 'H':
            if (cli_int("--health-port", optarg, 0, 65535, &v) != 0) return -1;
            cfg->health_port = (int)v;
            break;
        case 'g': safe_copy(cfg->tls_groups, optarg, sizeof(cfg->tls_groups)); break;
        case 'Q': cfg->require_pq = 1; break;
        case 'R':
            if (cli_int("--rate-limit", optarg, 0, 1000000, &v) != 0) return -1;
            cfg->rate_limit_per_ip = (int)v;
            if (cfg->rate_limit_burst == 0)
                cfg->rate_limit_burst = cfg->rate_limit_per_ip * 2;
            break;
        case 'j': cfg->json_logging = 1; break;
        case 'S':
            if (cli_int("--session-cache", optarg, 0, 10000000, &v) != 0) return -1;
            cfg->session_cache_size = (int)v;
            break;
        case 'm':
            if (strcmp(optarg, "http") == 0)     cfg->proxy_mode = PQ_PROXY_MODE_HTTP;
            else if (strcmp(optarg, "tcp") == 0) cfg->proxy_mode = PQ_PROXY_MODE_TCP;
            else {
                fprintf(stderr, "invalid value '%s' for --mode (expected http or tcp)\n", optarg);
                return -1;
            }
            break;
        case 'h':
            return 1; /* signal caller to print help */
        default:
            return -1;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "unexpected argument '%s'\n", argv[optind]);
        return -1;
    }
    return 0;
}

/* ======================================================================== */
/* Validate                                                                 */
/* ======================================================================== */

int pq_server_config_validate(const pq_server_config_t *cfg) {
    unsigned char addr[sizeof(struct in6_addr)];
    if (inet_pton(AF_INET, cfg->bind_address, addr) != 1 &&
        inet_pton(AF_INET6, cfg->bind_address, addr) != 1) {
        fprintf(stderr, "config: listen address '%s' is not a valid IPv4/IPv6 address\n",
                cfg->bind_address);
        return -1;
    }
    if (cfg->listen_port == 0) {
        fprintf(stderr, "config: listen port must be > 0\n");
        return -1;
    }
    if (cfg->cert_file[0] == '\0') {
        fprintf(stderr, "config: TLS certificate file is required (--cert or [tls] cert=)\n");
        return -1;
    }
    if (cfg->key_file[0] == '\0') {
        fprintf(stderr, "config: TLS private key file is required (--key or [tls] key=)\n");
        return -1;
    }
    if (access(cfg->cert_file, R_OK) != 0) {
        fprintf(stderr, "config: certificate file not readable: %s\n", cfg->cert_file);
        return -1;
    }
    if (access(cfg->key_file, R_OK) != 0) {
        fprintf(stderr, "config: key file not readable: %s\n", cfg->key_file);
        return -1;
    }
    if (cfg->upstream_count == 0) {
        fprintf(stderr, "config: at least one upstream backend is required (--backend or [upstream] backend=)\n");
        return -1;
    }
    for (int i = 0; i < cfg->upstream_count; i++) {
        const pq_upstream_t *u = &cfg->upstreams[i];
        if (u->use_tls) {
            /* Refuse rather than silently sending plaintext to a backend the
             * operator believes is encrypted. */
            fprintf(stderr, "config: backend 'tls://%s:%u': TLS to backends is not supported yet; "
                    "use a plain backend on a trusted network, a unix: socket, "
                    "or a local TLS sidecar\n", u->host, u->port);
            return -1;
        }
        if (strncmp(u->host, "unix:", 5) != 0 && u->port == 0) {
            fprintf(stderr, "config: backend '%s' has no valid port\n", u->host);
            return -1;
        }
    }
    if (cfg->require_client_auth && cfg->ca_file[0] == '\0') {
        fprintf(stderr, "config: CA file required when client auth is enabled\n");
        return -1;
    }
    if (cfg->max_connections < 1) {
        fprintf(stderr, "config: max_connections must be >= 1\n");
        return -1;
    }
    return 0;
}

/* ======================================================================== */
/* Print                                                                    */
/* ======================================================================== */

void pq_server_config_print(const pq_server_config_t *cfg) {
    printf("PQ-TLS Server Configuration:\n");
    printf("  Listen:       %s:%u\n", cfg->bind_address, cfg->listen_port);
    printf("  TLS cert:     %s\n", cfg->cert_file);
    printf("  TLS key:      %s\n", cfg->key_file);
    if (cfg->ca_file[0])
        printf("  CA file:      %s\n", cfg->ca_file);
    printf("  Client auth:  %s\n", cfg->require_client_auth ? "required" : "off");
    printf("  TLS groups:   %s\n", cfg->tls_groups[0] ? cfg->tls_groups : "(crypto registry)");
    printf("  Require PQ:   %s\n", cfg->require_pq ? "yes" : "no");
    printf("  Min TLS ver:  %s\n", cfg->tls_min_version == 0x0304 ? "1.3" : "1.2");
    printf("  Session cache: %d\n", cfg->session_cache_size);
    printf("  Proxy mode:   %s\n", cfg->proxy_mode == PQ_PROXY_MODE_TCP ? "tcp" : "http");
    printf("  Upstreams:    %d\n", cfg->upstream_count);
    for (int i = 0; i < cfg->upstream_count; i++) {
        printf("    [%d] %s%s:%u (weight %d)\n", i,
               cfg->upstreams[i].use_tls ? "tls://" : "",
               cfg->upstreams[i].host, cfg->upstreams[i].port,
               cfg->upstreams[i].weight);
    }
    printf("  Timeouts:     handshake %dms, idle %dms, connect %dms, drain %dms\n",
           cfg->handshake_timeout_ms, cfg->upstream_timeout_ms,
           cfg->upstream_connect_timeout_ms, cfg->drain_timeout_ms);
    printf("  Acceptors:    %d%s\n", cfg->worker_threads,
           cfg->worker_threads == 0 ? " (auto)" : "");
    printf("  Max conns:    %d\n", cfg->max_connections);
    printf("  Log level:    %d\n", cfg->log_level);
    printf("  JSON logging: %s\n", cfg->json_logging ? "yes" : "no");
    if (cfg->rate_limit_per_ip > 0)
        printf("  Rate limit:   %d/s per IP (burst %d)\n",
               cfg->rate_limit_per_ip, cfg->rate_limit_burst);
    if (cfg->acl_mode != PQ_ACL_MODE_DISABLED)
        printf("  ACL:          %s (%d entries)\n",
               cfg->acl_mode == PQ_ACL_MODE_ALLOWLIST ? "allowlist" : "blocklist",
               cfg->acl_count);
    if (cfg->health_port)
        printf("  Dashboard:    %s:%d\n",
               cfg->mgmt_localhost_only ? "127.0.0.1" : "0.0.0.0", cfg->health_port);
    if (cfg->daemonize)
        printf("  Daemonize:    yes\n");
    printf("\n");
}
