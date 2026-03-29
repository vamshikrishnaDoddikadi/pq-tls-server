/**
 * @file pq_config.h
 * @brief Post-Quantum TLS Configuration Management
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module provides configuration management for the PQ-TLS implementation,
 * including algorithm selection, TLS version control, and performance tuning.
 * Configurations can be loaded from and saved to INI-style files.
 */

#ifndef PQ_CONFIG_H
#define PQ_CONFIG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Configuration Structure
 * ======================================================================== */

/**
 * @brief Post-Quantum TLS configuration structure
 *
 * Contains all configurable parameters for the PQ-TLS implementation,
 * including algorithm selection, protocol versions, and operational settings.
 */
typedef struct pq_config_t {
    /* KEM configuration */
    int default_kem_algorithm;      /**< Default ML-KEM variant (PQ_KEM_MLKEM512/768/1024) */
    int enable_classical_kem;       /**< Allow X25519 fallback (0=no, 1=yes) */
    int enable_hybrid_kem;          /**< Enable hybrid mode (0=no, 1=yes) */
    
    /* Signature configuration */
    int default_sig_algorithm;      /**< Default ML-DSA variant (PQ_SIG_MLDSA44/65/87) */
    int enable_classical_sig;       /**< Allow Ed25519/ECDSA/RSA fallback (0=no, 1=yes) */
    
    /* TLS configuration */
    int tls_min_version;            /**< Minimum TLS version (0x0303=TLS 1.2, 0x0304=TLS 1.3) */
    int tls_max_version;            /**< Maximum TLS version (0x0303=TLS 1.2, 0x0304=TLS 1.3) */
    int enable_pq_only_mode;        /**< Disable all classical algorithms (0=no, 1=yes) */
    
    /* HPKE configuration */
    int default_hpke_kem;           /**< Default HPKE KEM (HPKE_KEM_*) */
    int default_hpke_aead;          /**< Default HPKE AEAD (HPKE_AEAD_*) */
    
    /* Hybrid KEX configuration */
    int default_hybrid_mode;        /**< HYBRID_MODE_CONCAT or HYBRID_MODE_XOR */
    int default_classical_kex;      /**< HYBRID_CLASSICAL_X25519 or HYBRID_CLASSICAL_P256 */
    
    /* Performance tuning */
    int enable_constant_time;       /**< Force constant-time operations (0=no, 1=yes) */
    int enable_memory_lock;         /**< Use mlock for sensitive data (0=no, 1=yes) */
    
    /* Logging and debugging */
    int log_level;                  /**< 0=none, 1=error, 2=warn, 3=info, 4=debug */
    int enable_benchmarking;        /**< Enable performance metrics (0=no, 1=yes) */
} pq_config_t;

/* ========================================================================
 * Configuration Management Functions
 * ======================================================================== */

/**
 * @brief Initialize configuration with default values
 *
 * Creates a new configuration structure and initializes it with secure
 * default values suitable for most use cases.
 *
 * Default configuration:
 * - KEM: ML-KEM-768 (balanced security/performance)
 * - Signature: ML-DSA-65 (NIST Level 3)
 * - TLS: 1.2 minimum, 1.3 maximum
 * - Hybrid mode: CONCAT with X25519
 * - Constant-time operations: enabled
 * - Log level: warnings
 *
 * @return Pointer to initialized configuration, or NULL on failure
 *
 * @note The returned configuration must be freed with pq_config_free()
 */
pq_config_t* pq_config_init(void);

/**
 * @brief Free configuration structure
 *
 * Securely clears and frees all memory associated with the configuration.
 *
 * @param config Configuration to free (may be NULL)
 */
void pq_config_free(pq_config_t *config);

/**
 * @brief Load configuration from INI-style file
 *
 * Reads configuration from a file in INI format with sections for different
 * configuration categories. Unknown keys are ignored. Missing keys retain
 * their current values.
 *
 * @param config Configuration structure to populate
 * @param filename Path to configuration file
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note Configuration is validated after loading
 */
int pq_config_load(pq_config_t *config, const char *filename);

/**
 * @brief Save configuration to INI-style file
 *
 * Writes the current configuration to a file in INI format with comments
 * explaining each option.
 *
 * @param config Configuration to save
 * @param filename Path to output file
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_config_save(const pq_config_t *config, const char *filename);

/**
 * @brief Set default KEM algorithm
 *
 * Updates the default KEM algorithm and validates the choice.
 *
 * @param config Configuration to update
 * @param algorithm KEM algorithm identifier (PQ_KEM_MLKEM512/768/1024)
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_config_set_kem(pq_config_t *config, int algorithm);

/**
 * @brief Set default signature algorithm
 *
 * Updates the default signature algorithm and validates the choice.
 *
 * @param config Configuration to update
 * @param algorithm Signature algorithm identifier (PQ_SIG_MLDSA44/65/87)
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_config_set_sig(pq_config_t *config, int algorithm);

/**
 * @brief Set TLS version range
 *
 * Updates the minimum and maximum TLS versions and validates the range.
 *
 * @param config Configuration to update
 * @param min Minimum TLS version (0x0303 for TLS 1.2, 0x0304 for TLS 1.3)
 * @param max Maximum TLS version (0x0303 for TLS 1.2, 0x0304 for TLS 1.3)
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_config_set_tls_version(pq_config_t *config, int min, int max);

/**
 * @brief Validate configuration
 *
 * Checks that all configuration values are valid and consistent.
 * Validates:
 * - Algorithm identifiers are recognized
 * - TLS version range is valid
 * - Log level is in valid range
 * - Conflicting options are not set
 *
 * @param config Configuration to validate
 * @return PQ_SUCCESS if valid, error code describing the problem otherwise
 */
int pq_config_validate(const pq_config_t *config);

/**
 * @brief Convert configuration to human-readable string
 *
 * Generates a formatted string representation of the configuration suitable
 * for display or logging.
 *
 * @param config Configuration to convert
 * @return Pointer to static buffer containing formatted string, or NULL on error
 *
 * @note The returned pointer is to a static buffer that will be overwritten
 *       on subsequent calls. Copy the string if you need to preserve it.
 */
const char* pq_config_to_string(const pq_config_t *config);

/**
 * @brief Get default KEM algorithm
 *
 * @param config Configuration to query
 * @return KEM algorithm identifier, or -1 on error
 */
int pq_config_get_kem(const pq_config_t *config);

/**
 * @brief Get default signature algorithm
 *
 * @param config Configuration to query
 * @return Signature algorithm identifier, or -1 on error
 */
int pq_config_get_sig(const pq_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* PQ_CONFIG_H */
