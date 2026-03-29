/**
 * @file prometheus.c
 * @brief Prometheus-compatible metrics export
 * @author Vamshi Krishna Doddikadi
 */

#include "prometheus.h"
#include <stdio.h>
#include <stdatomic.h>

int pq_prometheus_format(const pq_conn_manager_t *mgr, char *buf, size_t len) {
    return snprintf(buf, len,
        "# HELP pqtls_connections_total Total connections accepted\n"
        "# TYPE pqtls_connections_total counter\n"
        "pqtls_connections_total %ld\n"
        "\n"
        "# HELP pqtls_connections_active Currently active connections\n"
        "# TYPE pqtls_connections_active gauge\n"
        "pqtls_connections_active %d\n"
        "\n"
        "# HELP pqtls_handshake_failures_total TLS handshake failures\n"
        "# TYPE pqtls_handshake_failures_total counter\n"
        "pqtls_handshake_failures_total %ld\n"
        "\n"
        "# HELP pqtls_bytes_received_total Bytes received from clients\n"
        "# TYPE pqtls_bytes_received_total counter\n"
        "pqtls_bytes_received_total %ld\n"
        "\n"
        "# HELP pqtls_bytes_sent_total Bytes sent to clients\n"
        "# TYPE pqtls_bytes_sent_total counter\n"
        "pqtls_bytes_sent_total %ld\n"
        "\n"
        "# HELP pqtls_pq_negotiations_total Post-quantum key exchanges negotiated\n"
        "# TYPE pqtls_pq_negotiations_total counter\n"
        "pqtls_pq_negotiations_total %ld\n"
        "\n"
        "# HELP pqtls_classical_negotiations_total Classical key exchanges negotiated\n"
        "# TYPE pqtls_classical_negotiations_total counter\n"
        "pqtls_classical_negotiations_total %ld\n"
        "\n"
        "# HELP pqtls_workers Number of worker threads\n"
        "# TYPE pqtls_workers gauge\n"
        "pqtls_workers %d\n",
        atomic_load(&mgr->total_connections),
        atomic_load(&mgr->active_connections),
        atomic_load(&mgr->total_handshake_failures),
        atomic_load(&mgr->total_bytes_in),
        atomic_load(&mgr->total_bytes_out),
        atomic_load(&mgr->pq_negotiations),
        atomic_load(&mgr->classical_negotiations),
        mgr->worker_count);
}
