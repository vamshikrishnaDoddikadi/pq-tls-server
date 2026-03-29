/**
 * @file server_config.c
 * @brief PQ-TLS Server Configuration Parser
 * @author Vamshi Krishna Doddikadi
 */

#include "server_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>

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

/**
 * Parse "host:port" into an upstream.  weight defaults to 1.
 * Also supports "unix:/path/to/sock" for Unix domain sockets.
 */
static int parse_upstream(const char *str, pq_upstream_t *u) {
    memset(u, 0, sizeof(*u));
    u->weight = 1;

    /* Check for unix socket */
    if (strncmp(str, "unix:", 5) == 0) {
        safe_copy(u->host, str, sizeof(u->host));
        u->port = 0;
        return 0;
    }

    /* Check for tls:// prefix */
    const char *p = str;
    if (strncmp(p, "tls://", 6) == 0) {
        u->use_tls = 1;
        p += 6;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }

    /* Check for weight suffix: "host:port;weight=N" */
    char buf[512];
    safe_copy(buf, p, sizeof(buf));
    char *semi = strchr(buf, ';');
    if (semi) {
        *semi = '\0';
        char *wstr = strstr(semi + 1, "weight=");
        if (wstr) {
            u->weight = atoi(wstr + 7);
            if (u->weight < 1) u->weight = 1;
            if (u->weight > 100) u->weight = 100;
        }
    }

    /* Split host:port */
    const char *colon = strrchr(buf, ':');
    if (!colon) {
        safe_copy(u->host, buf, sizeof(u->host));
        u->port = u->use_tls ? 443 : 80;
    } else {
        size_t hlen = (size_t)(colon - buf);
        if (hlen >= sizeof(u->host)) hlen = sizeof(u->host) - 1;
        memcpy(u->host, buf, hlen);
        u->host[hlen] = '\0';
        u->port = (uint16_t)atoi(colon + 1);
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
    safe_copy(cfg->tls_groups, "X25519MLKEM768:X25519", sizeof(cfg->tls_groups));
    cfg->tls_min_version = 0x0304; /* TLS 1.3 */
    cfg->session_cache_size = 20000; /* Enable by default */
    cfg->upstream_timeout_ms = 30000;
    cfg->upstream_connect_timeout_ms = 5000;
    cfg->worker_threads = 0; /* auto */
    cfg->max_connections = 1024;
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

int pq_server_config_load(pq_server_config_t *cfg, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "config: cannot open '%s': %m\n", path);
        return -1;
    }

    char line[1024], section[64] = "";
    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#' || line[0] == ';') continue;

        /* Section header */
        if (line[0] == '[') {
            char *end = strchr(line, ']');
            if (end) {
                *end = '\0';
                safe_copy(section, line + 1, sizeof(section));
            }
            continue;
        }

        /* key = value */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);

        /* -- [listen] section -- */
        if (strcmp(section, "listen") == 0) {
            if (strcmp(key, "address") == 0)
                safe_copy(cfg->bind_address, val, sizeof(cfg->bind_address));
            else if (strcmp(key, "port") == 0)
                cfg->listen_port = (uint16_t)atoi(val);
        }
        /* -- [tls] section -- */
        else if (strcmp(section, "tls") == 0) {
            if (strcmp(key, "cert") == 0)
                safe_copy(cfg->cert_file, val, sizeof(cfg->cert_file));
            else if (strcmp(key, "key") == 0)
                safe_copy(cfg->key_file, val, sizeof(cfg->key_file));
            else if (strcmp(key, "ca") == 0)
                safe_copy(cfg->ca_file, val, sizeof(cfg->ca_file));
            else if (strcmp(key, "client_auth") == 0)
                cfg->require_client_auth = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            else if (strcmp(key, "groups") == 0)
                safe_copy(cfg->tls_groups, val, sizeof(cfg->tls_groups));
            else if (strcmp(key, "min_version") == 0) {
                if (strcmp(val, "1.2") == 0)      cfg->tls_min_version = 0x0303;
                else if (strcmp(val, "1.3") == 0)  cfg->tls_min_version = 0x0304;
            }
            else if (strcmp(key, "session_cache_size") == 0)
                cfg->session_cache_size = atoi(val);
        }
        /* -- [upstream] section -- */
        else if (strcmp(section, "upstream") == 0) {
            if (strcmp(key, "backend") == 0 && cfg->upstream_count < PQ_MAX_UPSTREAMS) {
                parse_upstream(val, &cfg->upstreams[cfg->upstream_count]);
                cfg->upstream_count++;
            }
            else if (strcmp(key, "timeout") == 0)
                cfg->upstream_timeout_ms = atoi(val);
            else if (strcmp(key, "connect_timeout") == 0)
                cfg->upstream_connect_timeout_ms = atoi(val);
        }
        /* -- [server] section -- */
        else if (strcmp(section, "server") == 0) {
            if (strcmp(key, "workers") == 0)
                cfg->worker_threads = atoi(val);
            else if (strcmp(key, "max_connections") == 0)
                cfg->max_connections = atoi(val);
            else if (strcmp(key, "daemonize") == 0)
                cfg->daemonize = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            else if (strcmp(key, "pid_file") == 0)
                safe_copy(cfg->pid_file, val, sizeof(cfg->pid_file));
        }
        /* -- [logging] section -- */
        else if (strcmp(section, "logging") == 0) {
            if (strcmp(key, "file") == 0)
                safe_copy(cfg->log_file, val, sizeof(cfg->log_file));
            else if (strcmp(key, "level") == 0) {
                if (strcmp(val, "debug") == 0)      cfg->log_level = 0;
                else if (strcmp(val, "info") == 0)   cfg->log_level = 1;
                else if (strcmp(val, "warn") == 0)   cfg->log_level = 2;
                else if (strcmp(val, "error") == 0)  cfg->log_level = 3;
            }
            else if (strcmp(key, "access_log") == 0)
                cfg->access_log = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
            else if (strcmp(key, "json") == 0)
                cfg->json_logging = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        }
        /* -- [health] section -- */
        else if (strcmp(section, "health") == 0) {
            if (strcmp(key, "port") == 0)
                cfg->health_port = atoi(val);
        }
        /* -- [rate_limit] section -- */
        else if (strcmp(section, "rate_limit") == 0) {
            if (strcmp(key, "per_ip") == 0)
                cfg->rate_limit_per_ip = atoi(val);
            else if (strcmp(key, "burst") == 0)
                cfg->rate_limit_burst = atoi(val);
        }
        /* -- [acl] section -- */
        else if (strcmp(section, "acl") == 0) {
            if (strcmp(key, "mode") == 0) {
                if (strcmp(val, "allowlist") == 0)      cfg->acl_mode = PQ_ACL_MODE_ALLOWLIST;
                else if (strcmp(val, "blocklist") == 0)  cfg->acl_mode = PQ_ACL_MODE_BLOCKLIST;
                else                                     cfg->acl_mode = PQ_ACL_MODE_DISABLED;
            }
            else if (strcmp(key, "entry") == 0 && cfg->acl_count < PQ_MAX_ACL) {
                safe_copy(cfg->acl_entries[cfg->acl_count], val, 64);
                cfg->acl_count++;
            }
        }
        /* -- [mgmt] section -- */
        else if (strcmp(section, "mgmt") == 0) {
            if (strcmp(key, "admin_user") == 0)
                safe_copy(cfg->mgmt_admin_user, val, sizeof(cfg->mgmt_admin_user));
            else if (strcmp(key, "admin_pass_hash") == 0)
                safe_copy(cfg->mgmt_admin_pass_hash, val, sizeof(cfg->mgmt_admin_pass_hash));
            else if (strcmp(key, "cert_store") == 0)
                safe_copy(cfg->cert_store_path, val, sizeof(cfg->cert_store_path));
            else if (strcmp(key, "enabled") == 0)
                cfg->mgmt_enabled = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
        }
    }

    fclose(fp);
    return 0;
}

/* ======================================================================== */
/* CLI Parser                                                               */
/* ======================================================================== */

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
        {"rate-limit",     required_argument, NULL, 'R'},
        {"json-log",       no_argument,       NULL, 'j'},
        {"session-cache",  required_argument, NULL, 'S'},
        {"help",           no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "p:c:k:a:b:w:l:vdf:H:g:R:jS:h",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p': cfg->listen_port = (uint16_t)atoi(optarg); break;
        case 'c': safe_copy(cfg->cert_file, optarg, sizeof(cfg->cert_file)); break;
        case 'k': safe_copy(cfg->key_file, optarg, sizeof(cfg->key_file)); break;
        case 'a': safe_copy(cfg->ca_file, optarg, sizeof(cfg->ca_file)); break;
        case 'b':
            if (cfg->upstream_count < PQ_MAX_UPSTREAMS) {
                parse_upstream(optarg, &cfg->upstreams[cfg->upstream_count]);
                cfg->upstream_count++;
            }
            break;
        case 'w': cfg->worker_threads = atoi(optarg); break;
        case 'l': safe_copy(cfg->log_file, optarg, sizeof(cfg->log_file)); break;
        case 'v': cfg->verbose = 1; cfg->log_level = 0; break;
        case 'd': cfg->daemonize = 1; break;
        case 'f':
            /* config file — already loaded before arg parsing */
            break;
        case 'H': cfg->health_port = atoi(optarg); break;
        case 'g': safe_copy(cfg->tls_groups, optarg, sizeof(cfg->tls_groups)); break;
        case 'R': cfg->rate_limit_per_ip = atoi(optarg);
                  if (cfg->rate_limit_burst == 0)
                      cfg->rate_limit_burst = cfg->rate_limit_per_ip * 2;
                  break;
        case 'j': cfg->json_logging = 1; break;
        case 'S': cfg->session_cache_size = atoi(optarg); break;
        case 'h':
            return 1; /* signal caller to print help */
        default:
            return -1;
        }
    }
    return 0;
}

/* ======================================================================== */
/* Validate                                                                 */
/* ======================================================================== */

int pq_server_config_validate(const pq_server_config_t *cfg) {
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
    if (cfg->require_client_auth && cfg->ca_file[0] == '\0') {
        fprintf(stderr, "config: CA file required when client auth is enabled\n");
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
    printf("  TLS groups:   %s\n", cfg->tls_groups);
    printf("  Min TLS ver:  %s\n", cfg->tls_min_version == 0x0304 ? "1.3" : "1.2");
    printf("  Session cache: %d\n", cfg->session_cache_size);
    printf("  Upstreams:    %d\n", cfg->upstream_count);
    for (int i = 0; i < cfg->upstream_count; i++) {
        printf("    [%d] %s%s:%u (weight %d)\n", i,
               cfg->upstreams[i].use_tls ? "tls://" : "",
               cfg->upstreams[i].host, cfg->upstreams[i].port,
               cfg->upstreams[i].weight);
    }
    printf("  Workers:      %d%s\n", cfg->worker_threads,
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
        printf("  Dashboard:    http://0.0.0.0:%d\n", cfg->health_port);
    if (cfg->daemonize)
        printf("  Daemonize:    yes\n");
    printf("\n");
}
