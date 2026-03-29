/**
 * @file oqs_tls_integration.h
 * @brief OQS (Open Quantum Safe) TLS Integration for Post-Quantum Cryptography
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 * 
 * This header defines the interface for integrating liboqs post-quantum
 * algorithms with OpenSSL TLS 1.3 connections.
 */

#ifndef OQS_TLS_INTEGRATION_H
#define OQS_TLS_INTEGRATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Algorithm Enumerations
 * ============================================================================ */

/**
 * @brief ML-KEM (Kyber) Key Encapsulation Mechanism variants
 * FIPS 203 compliant algorithms
 */
typedef enum {
    OQS_KEM_NONE = 0,
    OQS_KEM_ML_KEM_512,      /**< ML-KEM-512 (128-bit security) */
    OQS_KEM_ML_KEM_768,      /**< ML-KEM-768 (192-bit security) */
    OQS_KEM_ML_KEM_1024,     /**< ML-KEM-1024 (256-bit security) */
    OQS_KEM_KYBER_512,       /**< Kyber-512 (legacy) */
    OQS_KEM_KYBER_768,       /**< Kyber-768 (legacy) */
    OQS_KEM_KYBER_1024,      /**< Kyber-1024 (legacy) */
    OQS_KEM_COUNT
} oqs_kem_algorithm_t;

/**
 * @brief ML-DSA (Dilithium) Digital Signature Algorithm variants
 * FIPS 204 compliant algorithms
 */
typedef enum {
    OQS_SIG_NONE = 0,
    OQS_SIG_ML_DSA_44,       /**< ML-DSA-44 (128-bit security) */
    OQS_SIG_ML_DSA_65,       /**< ML-DSA-65 (192-bit security) */
    OQS_SIG_ML_DSA_87,       /**< ML-DSA-87 (256-bit security) */
    OQS_SIG_DILITHIUM_2,     /**< Dilithium2 (legacy) */
    OQS_SIG_DILITHIUM_3,     /**< Dilithium3 (legacy) */
    OQS_SIG_DILITHIUM_5,     /**< Dilithium5 (legacy) */
    OQS_SIG_SPHINCS_SHA2_128F,
    OQS_SIG_SPHINCS_SHA2_192F,
    OQS_SIG_SPHINCS_SHA2_256F,
    OQS_SIG_COUNT
} oqs_sig_algorithm_t;

/**
 * @brief Hybrid key exchange modes
 */
typedef enum {
    OQS_HYBRID_NONE = 0,
    OQS_HYBRID_X25519_MLKEM768,    /**< X25519 + ML-KEM-768 */
    OQS_HYBRID_P256_MLKEM768,      /**< P-256 + ML-KEM-768 */
    OQS_HYBRID_P384_MLKEM1024,     /**< P-384 + ML-KEM-1024 */
    OQS_HYBRID_X25519_KYBER768,    /**< X25519 + Kyber-768 (legacy) */
    OQS_HYBRID_COUNT
} oqs_hybrid_mode_t;

/**
 * @brief NIST Security Levels
 */
typedef enum {
    OQS_SECURITY_LEVEL_1 = 1,  /**< 128-bit classical security */
    OQS_SECURITY_LEVEL_3 = 3,  /**< 192-bit classical security */
    OQS_SECURITY_LEVEL_5 = 5   /**< 256-bit classical security */
} oqs_security_level_t;

/* ============================================================================
 * Configuration Structures
 * ============================================================================ */

/**
 * @brief Algorithm performance metrics
 */
typedef struct {
    double keygen_time_ms;     /**< Key generation time in milliseconds */
    double encaps_time_ms;     /**< Encapsulation time in milliseconds */
    double decaps_time_ms;     /**< Decapsulation time in milliseconds */
    double sign_time_ms;       /**< Signing time in milliseconds */
    double verify_time_ms;     /**< Verification time in milliseconds */
    size_t public_key_size;    /**< Public key size in bytes */
    size_t secret_key_size;    /**< Secret key size in bytes */
    size_t ciphertext_size;    /**< Ciphertext/signature size in bytes */
    size_t shared_secret_size; /**< Shared secret size in bytes */
} oqs_algorithm_metrics_t;

/**
 * @brief OQS TLS Configuration
 */
typedef struct {
    oqs_kem_algorithm_t kem_algorithm;
    oqs_sig_algorithm_t sig_algorithm;
    oqs_hybrid_mode_t hybrid_mode;
    oqs_security_level_t min_security_level;
    bool enable_hybrid;           /**< Enable hybrid classical+PQ mode */
    bool prefer_pq;               /**< Prefer PQ algorithms over classical */
    bool allow_classical_fallback;/**< Allow fallback to classical if PQ fails */
    const char *cert_file;        /**< Path to certificate file */
    const char *key_file;         /**< Path to private key file */
    const char *ca_file;          /**< Path to CA certificate file */
} oqs_tls_config_t;

/**
 * @brief OQS TLS Context
 */
typedef struct oqs_tls_context oqs_tls_context_t;

/* ============================================================================
 * Initialization and Cleanup
 * ============================================================================ */

/**
 * @brief Initialize the OQS TLS subsystem
 * @return 0 on success, negative error code on failure
 */
int oqs_tls_init(void);

/**
 * @brief Cleanup the OQS TLS subsystem
 */
void oqs_tls_cleanup(void);

/**
 * @brief Check if OQS is available and properly initialized
 * @return true if OQS is available
 */
bool oqs_tls_is_available(void);

/* ============================================================================
 * Context Management
 * ============================================================================ */

/**
 * @brief Create a new OQS TLS context
 * @param config Configuration for the context
 * @return New context or NULL on failure
 */
oqs_tls_context_t *oqs_tls_context_new(const oqs_tls_config_t *config);

/**
 * @brief Free an OQS TLS context
 * @param ctx Context to free
 */
void oqs_tls_context_free(oqs_tls_context_t *ctx);

/**
 * @brief Get default configuration
 * @param config Configuration structure to fill
 */
void oqs_tls_config_default(oqs_tls_config_t *config);

/* ============================================================================
 * Algorithm Information
 * ============================================================================ */

/**
 * @brief Get the name of a KEM algorithm
 * @param alg Algorithm enum value
 * @return Algorithm name string
 */
const char *oqs_kem_algorithm_name(oqs_kem_algorithm_t alg);

/**
 * @brief Get the name of a signature algorithm
 * @param alg Algorithm enum value
 * @return Algorithm name string
 */
const char *oqs_sig_algorithm_name(oqs_sig_algorithm_t alg);

/**
 * @brief Get the security level of a KEM algorithm
 * @param alg Algorithm enum value
 * @return Security level
 */
oqs_security_level_t oqs_kem_security_level(oqs_kem_algorithm_t alg);

/**
 * @brief Get the security level of a signature algorithm
 * @param alg Algorithm enum value
 * @return Security level
 */
oqs_security_level_t oqs_sig_security_level(oqs_sig_algorithm_t alg);

/**
 * @brief Check if a KEM algorithm is available
 * @param alg Algorithm to check
 * @return true if available
 */
bool oqs_kem_is_available(oqs_kem_algorithm_t alg);

/**
 * @brief Check if a signature algorithm is available
 * @param alg Algorithm to check
 * @return true if available
 */
bool oqs_sig_is_available(oqs_sig_algorithm_t alg);

/* ============================================================================
 * Benchmarking
 * ============================================================================ */

/**
 * @brief Benchmark a KEM algorithm
 * @param alg Algorithm to benchmark
 * @param iterations Number of iterations
 * @param metrics Output metrics structure
 * @return 0 on success, negative error code on failure
 */
int oqs_kem_benchmark(oqs_kem_algorithm_t alg, int iterations, 
                      oqs_algorithm_metrics_t *metrics);

/**
 * @brief Benchmark a signature algorithm
 * @param alg Algorithm to benchmark
 * @param iterations Number of iterations
 * @param metrics Output metrics structure
 * @return 0 on success, negative error code on failure
 */
int oqs_sig_benchmark(oqs_sig_algorithm_t alg, int iterations,
                      oqs_algorithm_metrics_t *metrics);

/* ============================================================================
 * TLS Integration
 * ============================================================================ */

/**
 * @brief Configure SSL context for PQ algorithms
 * @param ctx OQS TLS context
 * @param ssl_ctx OpenSSL SSL_CTX pointer
 * @return 0 on success, negative error code on failure
 */
int oqs_tls_configure_ssl_ctx(oqs_tls_context_t *ctx, void *ssl_ctx);

/**
 * @brief Get the hybrid group string for OpenSSL
 * @param mode Hybrid mode
 * @return Group string (e.g., "x25519_mlkem768")
 */
const char *oqs_hybrid_group_string(oqs_hybrid_mode_t mode);

/**
 * @brief Create hybrid key exchange groups string
 * @param modes Array of hybrid modes
 * @param count Number of modes
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return Length of string or negative error code
 */
int oqs_create_groups_string(const oqs_hybrid_mode_t *modes, size_t count,
                             char *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* OQS_TLS_INTEGRATION_H */
