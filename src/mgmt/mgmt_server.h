/**
 * @file mgmt_server.h
 * @brief Management HTTP server — replaces the read-only dashboard
 *
 * Runs on the health_port (9090), serving:
 *   - SPA frontend (embedded HTML/CSS/JS)
 *   - REST API for config, certs, management
 *   - Backward-compatible monitoring endpoints
 *   - SSE streaming for metrics and logs
 */

#ifndef PQ_MGMT_SERVER_H
#define PQ_MGMT_SERVER_H

#include "../core/connection_manager.h"
#include "../core/server_config.h"

/**
 * Start the management HTTP server (replaces pq_dashboard_start).
 * Runs in its own thread.
 *
 * @param mgr         Connection manager (for metrics + reload)
 * @param config      Mutable server config (for write-back)
 * @param port        HTTP port (typically 9090)
 * @param config_path Path to INI config file (for save-back)
 * @return 0 on success, -1 on error.
 */
int pq_mgmt_start(pq_conn_manager_t *mgr, pq_server_config_t *config,
                   int port, const char *config_path);

/**
 * Stop the management server.
 */
void pq_mgmt_stop(void);

#endif /* PQ_MGMT_SERVER_H */
