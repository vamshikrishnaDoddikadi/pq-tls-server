/**
 * @file server_config.h
 * @brief PQ-TLS Server Configuration
 *
 * INI-style configuration for the all-in-one PQ-TLS reverse proxy server.
 *
 * @author Vamshi Krishna Doddikadi
 */

#ifndef PQ_SERVER_CONFIG_H
#define PQ_SERVER_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#define PQ_MAX_PATH       1024
#define PQ_MAX_UPSTREAMS  16
#define PQ_MAX_GROUPS     512
#define PQ_MAX_ACL        256

/* ======================================================================== */
/* ACL mode (mirrors acl.h but avoids circular include)                     */
/* ======================================================================== */

typedef enum {
    PQ_ACL_MODE_DISABLED  = 0,
    PQ_ACL_MODE_ALLOWLIST = 1,
    PQ_ACL_MODE_BLOCKLIST = 2
} pq_acl_mode_t;

/* ======================================================================== */
/* Upstream backend definition                                              */
/* ======================================================================== */

typedef struct {
    char host[256];       /* hostname/IP, or "unix:/path/to/sock" */
    uint16_t port;
    int weight;           /* load-balancing weight (1-100)  */
    int use_tls;          /* connect to backend via TLS?    */
} pq_upstream_t;

/* ======================================================================== */
/* Full server configuration                                                */
/* ======================================================================== */

typedef struct {
    /* --- Listen --- */
    char      bind_address[64];
    uint16_t  listen_port;

    /* --- TLS --- */
    char      cert_file[PQ_MAX_PATH];
    char      key_file[PQ_MAX_PATH];
    char      ca_file[PQ_MAX_PATH];
    int       require_client_auth;
    char      tls_groups[PQ_MAX_GROUPS];  /* e.g. "X25519MLKEM768:X25519" */
    int       tls_min_version;            /* 0x0303=TLS1.2, 0x0304=TLS1.3 */
    int       session_cache_size;         /* 0 = disabled, >0 = cache size */

    /* --- Upstream backends --- */
    pq_upstream_t upstreams[PQ_MAX_UPSTREAMS];
    int           upstream_count;
    int           upstream_timeout_ms;
    int           upstream_connect_timeout_ms;

    /* --- Worker threads --- */
    int       worker_threads;             /* 0 = auto (nproc)             */
    int       max_connections;

    /* --- Logging --- */
    char      log_file[PQ_MAX_PATH];      /* empty = stderr               */
    int       log_level;                  /* 0=DEBUG 1=INFO 2=WARN 3=ERR  */
    int       access_log;                 /* enable per-request access log */
    int       json_logging;               /* structured JSON log output    */

    /* --- Health / metrics / dashboard --- */
    int       health_port;                /* 0 = disabled                  */

    /* --- Rate limiting --- */
    int       rate_limit_per_ip;          /* 0 = disabled, conns/sec/IP   */
    int       rate_limit_burst;           /* token bucket burst capacity   */

    /* --- Access control --- */
    pq_acl_mode_t acl_mode;
    char      acl_entries[PQ_MAX_ACL][64]; /* IP or CIDR entries          */
    int       acl_count;

    /* --- Process --- */
    int       daemonize;
    char      pid_file[PQ_MAX_PATH];

    /* --- Management UI --- */
    char      config_file_path[PQ_MAX_PATH]; /* Path to INI file (for save-back) */
    char      mgmt_admin_user[64];           /* Admin username                   */
    char      mgmt_admin_pass_hash[128];     /* PBKDF2 hash                      */
    char      cert_store_path[PQ_MAX_PATH];  /* Certificate store directory       */
    int       mgmt_enabled;                  /* Management UI on/off              */
    int       mgmt_localhost_only;           /* Bind mgmt UI to 127.0.0.1 only    */

    /* --- Misc --- */
    int       verbose;
} pq_server_config_t;

/**
 * Initialize configuration with sane defaults.
 */
void pq_server_config_defaults(pq_server_config_t *cfg);

/**
 * Load configuration from an INI file.  Values not present in the file
 * keep their defaults.
 *
 * @return 0 on success, -1 on error.
 */
int pq_server_config_load(pq_server_config_t *cfg, const char *path);

/**
 * Override configuration from CLI arguments.
 * Recognized flags: -p/--port, -c/--cert, -k/--key, --ca, --backend,
 *                   --workers, --log, -v/--verbose, -d/--daemon,
 *                   --health-port, --groups, --rate-limit, --json-log,
 *                   --session-cache
 *
 * @return 0 on success, -1 on error.
 */
int pq_server_config_parse_args(pq_server_config_t *cfg, int argc, char **argv);

/**
 * Validate configuration (cert/key exist, port > 0, at least one upstream, etc.).
 *
 * @return 0 on success, -1 on validation error (message printed to stderr).
 */
int pq_server_config_validate(const pq_server_config_t *cfg);

/**
 * Print configuration summary to stdout.
 */
void pq_server_config_print(const pq_server_config_t *cfg);

/* pq_server_config_save() is declared in mgmt/config_writer.h */

#endif /* PQ_SERVER_CONFIG_H */
