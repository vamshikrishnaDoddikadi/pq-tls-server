/**
 * @file bench_agility.h
 * @brief ML-KEM Hybrid Benchmark Suite — Microbenchmark Harness
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Provides a reproducible benchmarking framework for comparing KEM/SIG
 * performance across the crypto-agility registry.  Measures keygen,
 * encapsulate, decapsulate times with statistical rigor.
 */

#ifndef PQ_BENCH_AGILITY_H
#define PQ_BENCH_AGILITY_H

#include "../common/crypto_registry.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Benchmark Result Structures
 * ======================================================================== */

typedef struct {
    double min_us;      /**< Minimum time (microseconds) */
    double max_us;      /**< Maximum time */
    double mean_us;     /**< Arithmetic mean */
    double median_us;   /**< Median */
    double stddev_us;   /**< Standard deviation */
    double p95_us;      /**< 95th percentile */
    double p99_us;      /**< 99th percentile */
    double ci95_low;    /**< 95% confidence interval lower bound */
    double ci95_high;   /**< 95% confidence interval upper bound */
    size_t samples;     /**< Number of valid samples */
} pq_bench_stats_t;

typedef struct {
    const char *algorithm_name;
    int nist_level;
    pq_algorithm_family_t family;

    /* KEM-specific benchmarks */
    pq_bench_stats_t keygen;
    pq_bench_stats_t encapsulate;
    pq_bench_stats_t decapsulate;

    /* Size metrics */
    size_t pk_bytes;
    size_t sk_bytes;
    size_t ct_bytes;
    size_t ss_bytes;
    size_t total_handshake_bytes;  /**< pk + ct (wire overhead) */
} pq_kem_bench_result_t;

typedef struct {
    const char *algorithm_name;
    int nist_level;

    pq_bench_stats_t keygen;
    pq_bench_stats_t sign;
    pq_bench_stats_t verify;

    size_t pk_bytes;
    size_t sig_bytes;
} pq_sig_bench_result_t;

typedef struct {
    const char *label;
    int nist_level;

    pq_bench_stats_t hybrid_keygen;     /**< Both classical + PQ keygen */
    pq_bench_stats_t hybrid_encapsulate;/**< Both encaps + combine */
    pq_bench_stats_t hybrid_decapsulate;/**< Both decaps + combine */
    pq_bench_stats_t combine;           /**< Combiner only */

    size_t total_pk_bytes;
    size_t total_ct_bytes;
    size_t total_handshake_bytes;
} pq_hybrid_bench_result_t;

/* ========================================================================
 * Benchmark Configuration
 * ======================================================================== */

typedef struct {
    int iterations;         /**< Total iterations per algorithm */
    int warmup_iterations;  /**< Discard first N (typically 10% of iterations) */
    int cpu_pin;            /**< CPU core to pin to (-1 = no pinning) */
    int disable_turbo;      /**< Attempt to disable turbo boost (needs root) */
    int verbose;            /**< Print progress during benchmarks */
} pq_bench_config_t;

/** Get default benchmark config (1000 iterations, 100 warmup) */
void pq_bench_config_default(pq_bench_config_t *cfg);

/* ========================================================================
 * Benchmark Execution
 * ======================================================================== */

/**
 * @brief Benchmark a single KEM provider
 */
int pq_bench_kem(const pq_kem_provider_t *provider,
                  const pq_bench_config_t *cfg,
                  pq_kem_bench_result_t *result);

/**
 * @brief Benchmark a single SIG provider
 */
int pq_bench_sig(const pq_sig_provider_t *provider,
                  const pq_bench_config_t *cfg,
                  pq_sig_bench_result_t *result);

/**
 * @brief Benchmark a hybrid KEM pair (classical + PQ + combiner)
 */
int pq_bench_hybrid(const pq_hybrid_kem_t *hybrid,
                     const pq_bench_config_t *cfg,
                     pq_hybrid_bench_result_t *result);

/**
 * @brief Benchmark all KEM providers in the registry
 *
 * @param reg      Registry with providers
 * @param cfg      Benchmark configuration
 * @param results  Output array (must be large enough)
 * @param max      Maximum results to write
 * @return Number of results written
 */
size_t pq_bench_all_kems(const pq_registry_t *reg,
                          const pq_bench_config_t *cfg,
                          pq_kem_bench_result_t *results, size_t max);

/**
 * @brief Benchmark all hybrid KEM pairs in the registry
 */
size_t pq_bench_all_hybrids(const pq_registry_t *reg,
                             const pq_bench_config_t *cfg,
                             pq_hybrid_bench_result_t *results, size_t max);

/* ========================================================================
 * Result Output
 * ======================================================================== */

/**
 * @brief Print KEM benchmark results as a formatted table
 */
void pq_bench_print_kem_results(const pq_kem_bench_result_t *results, size_t count);

/**
 * @brief Print hybrid benchmark results as a formatted table
 */
void pq_bench_print_hybrid_results(const pq_hybrid_bench_result_t *results, size_t count);

/**
 * @brief Export results as CSV for analysis pipeline
 */
int pq_bench_export_csv(const char *filename,
                         const pq_kem_bench_result_t *kem_results, size_t kem_count,
                         const pq_hybrid_bench_result_t *hybrid_results, size_t hybrid_count);

/**
 * @brief Export results as JSON
 */
int pq_bench_export_json(const char *filename,
                          const pq_kem_bench_result_t *kem_results, size_t kem_count,
                          const pq_hybrid_bench_result_t *hybrid_results, size_t hybrid_count);

#ifdef __cplusplus
}
#endif

#endif /* PQ_BENCH_AGILITY_H */
