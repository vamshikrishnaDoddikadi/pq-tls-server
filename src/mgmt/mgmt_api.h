/**
 * @file mgmt_api.h
 * @brief REST API endpoint handlers for management dashboard
 */

#ifndef PQ_MGMT_API_H
#define PQ_MGMT_API_H

#include "../core/connection_manager.h"
#include "../core/server_config.h"

/**
 * Context passed to all API handlers.
 */
typedef struct {
    pq_conn_manager_t  *mgr;
    pq_server_config_t *config;       /* Mutable config */
    const char         *config_path;  /* Path to INI file for save-back */
    int                 client_fd;
    const char         *method;
    const char         *path;
    const char         *body;
    size_t              body_len;
    const char         *auth_token;   /* From cookie or Authorization header */
} mgmt_api_ctx_t;

/**
 * Route and dispatch an API request. Called after static file checks.
 * @return 1 if handled, 0 if not an API route.
 */
int mgmt_api_dispatch(mgmt_api_ctx_t *ctx);

/* Individual API handlers (called by dispatch) */
void mgmt_api_auth_login(mgmt_api_ctx_t *ctx);
void mgmt_api_auth_logout(mgmt_api_ctx_t *ctx);
void mgmt_api_auth_status(mgmt_api_ctx_t *ctx);
void mgmt_api_auth_setup(mgmt_api_ctx_t *ctx);

void mgmt_api_config_get(mgmt_api_ctx_t *ctx);
void mgmt_api_config_put_listen(mgmt_api_ctx_t *ctx);
void mgmt_api_config_put_tls(mgmt_api_ctx_t *ctx);
void mgmt_api_config_tls_reload(mgmt_api_ctx_t *ctx);
void mgmt_api_config_put_upstreams(mgmt_api_ctx_t *ctx);
void mgmt_api_config_put_server(mgmt_api_ctx_t *ctx);
void mgmt_api_config_put_logging(mgmt_api_ctx_t *ctx);
void mgmt_api_config_put_rate_limit(mgmt_api_ctx_t *ctx);
void mgmt_api_config_put_acl(mgmt_api_ctx_t *ctx);

void mgmt_api_certs_list(mgmt_api_ctx_t *ctx);
void mgmt_api_certs_upload(mgmt_api_ctx_t *ctx);
void mgmt_api_certs_generate(mgmt_api_ctx_t *ctx);
void mgmt_api_certs_apply(mgmt_api_ctx_t *ctx);
void mgmt_api_certs_details(mgmt_api_ctx_t *ctx);

void mgmt_api_mgmt_status(mgmt_api_ctx_t *ctx);
void mgmt_api_mgmt_restart(mgmt_api_ctx_t *ctx);

void mgmt_api_logs_stream(mgmt_api_ctx_t *ctx);
void mgmt_api_logs_recent(mgmt_api_ctx_t *ctx);

void mgmt_api_algorithms(mgmt_api_ctx_t *ctx);

#endif /* PQ_MGMT_API_H */
