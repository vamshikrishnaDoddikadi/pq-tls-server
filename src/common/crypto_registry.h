/**
 * @file crypto_registry.h
 * @brief Crypto-Agility Algorithm Registry
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Runtime registry that discovers, stores, and queries algorithm providers.
 * Supports both static (compiled-in) and dynamic (shared library plugin)
 * registration.
 *
 * Usage:
 *   pq_registry_t *reg = pq_registry_create();
 *   pq_registry_register_builtins(reg);          // ML-KEM, ML-DSA, X25519, ...
 *   pq_registry_load_plugins(reg, "/etc/pqc-proxy/algorithms/");
 *   pq_registry_set_kem_preference(reg, prefs, nprefs);
 *   const pq_kem_provider_t *p = pq_registry_select_kem(reg, "ML-KEM-768");
 */

#ifndef PQ_CRYPTO_REGISTRY_H
#define PQ_CRYPTO_REGISTRY_H

#include "crypto_provider.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Registry Limits
 * ======================================================================== */

#define PQ_REGISTRY_MAX_KEM_PROVIDERS   32
#define PQ_REGISTRY_MAX_SIG_PROVIDERS   32
#define PQ_REGISTRY_MAX_COMBINERS        8
#define PQ_REGISTRY_MAX_HYBRID_KEMS     32
#define PQ_REGISTRY_MAX_PLUGINS         16

/* ========================================================================
 * Negotiation Audit Log Entry
 * ======================================================================== */

/**
 * @brief Records the outcome of one algorithm negotiation
 */
typedef struct {
    uint64_t    timestamp_us;       /**< Microsecond timestamp */
    const char *selected_name;      /**< Algorithm that was selected */
    int         nist_level;         /**< Security level of selection */
    bool        is_hybrid;          /**< Was a hybrid KEM used? */
    bool        is_fallback;        /**< Did we fall back to classical? */
    const char *client_groups;      /**< Client's supported groups (truncated) */
    const char *reason;             /**< Why this algorithm was chosen */
} pq_negotiation_log_entry_t;

/* ========================================================================
 * Registry Opaque Type
 * ======================================================================== */

typedef struct pq_registry pq_registry_t;

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

/**
 * @brief Create a new empty registry
 * @return Registry handle, or NULL on allocation failure
 */
pq_registry_t *pq_registry_create(void);

/**
 * @brief Destroy registry and release all resources
 *
 * Calls cleanup() on every registered provider and unloads plugins.
 * @param reg  Registry to destroy (may be NULL)
 */
void pq_registry_destroy(pq_registry_t *reg);

/* ========================================================================
 * Provider Registration
 * ======================================================================== */

/**
 * @brief Register a KEM provider
 * @return PQ_SUCCESS or PQ_ERR_* on failure (duplicate name, table full)
 */
int pq_registry_register_kem(pq_registry_t *reg, const pq_kem_provider_t *provider);

/**
 * @brief Register a signature provider
 * @return PQ_SUCCESS or PQ_ERR_* on failure
 */
int pq_registry_register_sig(pq_registry_t *reg, const pq_sig_provider_t *provider);

/**
 * @brief Register a hybrid combiner
 * @return PQ_SUCCESS or PQ_ERR_* on failure
 */
int pq_registry_register_combiner(pq_registry_t *reg, const pq_hybrid_combiner_t *combiner);

/**
 * @brief Register a hybrid KEM pair (classical + PQ + combiner)
 * @return PQ_SUCCESS or PQ_ERR_* on failure
 */
int pq_registry_register_hybrid(pq_registry_t *reg, const pq_hybrid_kem_t *hybrid);

/**
 * @brief Register all built-in providers (ML-KEM, ML-DSA, X25519, Ed25519, ...)
 *
 * Convenience function that registers every compiled-in provider and the
 * default KDF-concat combiner.
 * @return PQ_SUCCESS or first error encountered
 */
int pq_registry_register_builtins(pq_registry_t *reg);

/* ========================================================================
 * Dynamic Plugin Loading
 * ======================================================================== */

/**
 * @brief Load all plugin shared libraries from a directory
 *
 * Scans dir for *.so files, dlopen()s each, calls pq_plugin_init(),
 * and registers the providers they expose.
 *
 * @param reg  Registry
 * @param dir  Directory path (e.g. "/etc/pqc-proxy/algorithms/")
 * @return Number of plugins loaded, or negative error code
 */
int pq_registry_load_plugins(pq_registry_t *reg, const char *dir);

/**
 * @brief Load a single plugin shared library
 * @return PQ_SUCCESS or error code
 */
int pq_registry_load_plugin(pq_registry_t *reg, const char *path);

/* ========================================================================
 * Provider Lookup
 * ======================================================================== */

/**
 * @brief Look up a KEM provider by canonical name
 * @return Provider pointer or NULL if not found
 */
const pq_kem_provider_t *pq_registry_find_kem(const pq_registry_t *reg,
                                                const char *name);

/**
 * @brief Look up a signature provider by canonical name
 * @return Provider pointer or NULL if not found
 */
const pq_sig_provider_t *pq_registry_find_sig(const pq_registry_t *reg,
                                                const char *name);

/**
 * @brief Look up a hybrid combiner by method
 * @return Combiner pointer or NULL if not found
 */
const pq_hybrid_combiner_t *pq_registry_find_combiner(const pq_registry_t *reg,
                                                       pq_combiner_method_t method);

/**
 * @brief Look up a hybrid KEM pair by TLS group name
 * @return Hybrid descriptor or NULL if not found
 */
const pq_hybrid_kem_t *pq_registry_find_hybrid(const pq_registry_t *reg,
                                                 const char *tls_group);

/* ========================================================================
 * Enumeration
 * ======================================================================== */

/**
 * @brief Get all registered KEM providers
 * @param reg    Registry
 * @param out    Output array of provider pointers
 * @param max    Maximum entries in out
 * @return Number of providers written
 */
size_t pq_registry_list_kems(const pq_registry_t *reg,
                              const pq_kem_provider_t **out, size_t max);

/**
 * @brief Get all registered SIG providers
 */
size_t pq_registry_list_sigs(const pq_registry_t *reg,
                              const pq_sig_provider_t **out, size_t max);

/**
 * @brief Get all registered hybrid KEM pairs
 */
size_t pq_registry_list_hybrids(const pq_registry_t *reg,
                                 const pq_hybrid_kem_t **out, size_t max);

/**
 * @brief Filter KEM providers by minimum NIST security level
 */
size_t pq_registry_filter_kems_by_level(const pq_registry_t *reg,
                                         int min_level,
                                         const pq_kem_provider_t **out,
                                         size_t max);

/**
 * @brief Filter KEM providers by algorithm family
 */
size_t pq_registry_filter_kems_by_family(const pq_registry_t *reg,
                                          pq_algorithm_family_t family,
                                          const pq_kem_provider_t **out,
                                          size_t max);

/* ========================================================================
 * Preference Ordering & TLS Group Generation
 * ======================================================================== */

/**
 * @brief Set KEM preference order for TLS negotiation
 *
 * The preference list is an ordered array of hybrid KEM names (TLS group
 * strings).  During TLS handshake, the first mutually-supported entry wins.
 *
 * @param reg    Registry
 * @param names  NULL-terminated array of TLS group name strings
 * @return PQ_SUCCESS or PQ_ERR_INVALID_PARAMETER if a name is unknown
 */
int pq_registry_set_kem_preference(pq_registry_t *reg, const char **names);

/**
 * @brief Set signature preference order
 */
int pq_registry_set_sig_preference(pq_registry_t *reg, const char **names);

/**
 * @brief Generate an OpenSSL-compatible groups string from preferences
 *
 * Produces a colon-separated string like "X25519MLKEM768:X25519:P256"
 * suitable for SSL_CTX_set1_curves_list().
 *
 * @param reg          Registry
 * @param buf          Output buffer
 * @param buf_size     Buffer size
 * @return Length of string (excluding NUL), or negative error code
 */
int pq_registry_generate_groups_string(const pq_registry_t *reg,
                                        char *buf, size_t buf_size);

/* ========================================================================
 * Policy Configuration
 * ======================================================================== */

/** Crypto-agility policy */
typedef struct {
    bool  allow_classical_only;   /**< false = hard-fail if no PQC available */
    int   min_nist_level;         /**< Minimum acceptable NIST security level */
    bool  log_negotiation;        /**< Write audit log for every negotiation */
    bool  prefer_hybrid;          /**< Prefer hybrid over pure-PQ */
} pq_crypto_policy_t;

/**
 * @brief Set the crypto-agility policy
 */
int pq_registry_set_policy(pq_registry_t *reg, const pq_crypto_policy_t *policy);

/**
 * @brief Get the current policy (read-only)
 */
const pq_crypto_policy_t *pq_registry_get_policy(const pq_registry_t *reg);

/* ========================================================================
 * Negotiation Audit Log
 * ======================================================================== */

/**
 * @brief Record a negotiation outcome
 *
 * Thread-safe; uses a lock-free ring buffer internally.
 */
int pq_registry_log_negotiation(pq_registry_t *reg,
                                 const pq_negotiation_log_entry_t *entry);

/**
 * @brief Read recent negotiation log entries
 * @param reg    Registry
 * @param out    Output array
 * @param max    Maximum entries to return
 * @return Number of entries written
 */
size_t pq_registry_get_negotiation_log(const pq_registry_t *reg,
                                        pq_negotiation_log_entry_t *out,
                                        size_t max);

/* ========================================================================
 * Capability Reporting (for management API)
 * ======================================================================== */

/**
 * @brief Emit a JSON summary of all registered algorithms
 *
 * Used by the /api/algorithms management endpoint.
 *
 * @param reg          Registry
 * @param buf          Output buffer
 * @param buf_size     Buffer size
 * @return Length of JSON string, or negative error
 */
int pq_registry_to_json(const pq_registry_t *reg, char *buf, size_t buf_size);

/**
 * @brief Get count of available KEM providers
 */
size_t pq_registry_kem_count(const pq_registry_t *reg);

/**
 * @brief Get count of available SIG providers
 */
size_t pq_registry_sig_count(const pq_registry_t *reg);

#ifdef __cplusplus
}
#endif

#endif /* PQ_CRYPTO_REGISTRY_H */
