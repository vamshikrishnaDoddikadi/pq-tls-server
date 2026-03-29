/**
 * @file dashboard.h
 * @brief Live web dashboard with real-time metrics visualization
 * @author Vamshi Krishna Doddikadi
 *
 * Serves an embedded HTML/JS dashboard on the health port that displays:
 *   - Active connections (gauge)
 *   - Handshake rate (line chart)
 *   - PQ vs Classical negotiation ratio (pie chart)
 *   - Bytes throughput (line chart)
 *   - Backend health status
 *   - Latency percentiles
 *
 * Uses Server-Sent Events (SSE) for real-time updates without polling.
 */

#ifndef PQ_DASHBOARD_H
#define PQ_DASHBOARD_H

#include "../core/connection_manager.h"

/**
 * Start the dashboard HTTP server on the given port.
 * Runs in its own thread. Serves:
 *   GET /           -> HTML dashboard
 *   GET /metrics    -> Prometheus format
 *   GET /api/stats  -> JSON metrics
 *   GET /api/stream -> SSE real-time stream
 *   GET /health     -> {"status":"ok"}
 *
 * @return 0 on success, -1 on error.
 */
int pq_dashboard_start(pq_conn_manager_t *mgr, int port);

/**
 * Stop the dashboard server.
 */
void pq_dashboard_stop(void);

#endif /* PQ_DASHBOARD_H */
