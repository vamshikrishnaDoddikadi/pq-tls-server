/**
 * @file pq_errors.h
 * @brief Error code definitions and error handling utilities for PQ-TLS
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module provides comprehensive error handling for the PQ-TLS implementation,
 * including error codes across multiple domains (general, crypto, network, TLS,
 * config, and algorithm) and utility functions for error reporting.
 */

#ifndef PQ_ERRORS_H
#define PQ_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Success code
 */
#define PQ_SUCCESS 0

/* ========================================================================
 * General Error Codes (1-99)
 * ======================================================================== */

/** @brief Memory allocation failed */
#define PQ_ERR_MEMORY_ALLOCATION 1

/** @brief Invalid parameter provided */
#define PQ_ERR_INVALID_PARAMETER 2

/** @brief NULL pointer encountered */
#define PQ_ERR_NULL_POINTER 3

/** @brief Buffer size too small */
#define PQ_ERR_BUFFER_TOO_SMALL 4

/* ========================================================================
 * Cryptographic Error Codes (1000-1099)
 * ======================================================================== */

/** @brief Cryptographic operation failed */
#define PQ_ERR_CRYPTO_FAILED 1000

/** @brief Invalid format encountered */
#define PQ_ERR_INVALID_FORMAT 1001

/** @brief Key generation failed */
#define PQ_ERR_KEY_GENERATION_FAILED 1002

/** @brief Signature operation failed */
#define PQ_ERR_SIGNATURE_FAILED 1003

/** @brief Signature verification failed */
#define PQ_ERR_VERIFICATION_FAILED 1004

/** @brief Encryption operation failed */
#define PQ_ERR_ENCRYPTION_FAILED 1005

/** @brief Decryption operation failed */
#define PQ_ERR_DECRYPTION_FAILED 1006

/* ========================================================================
 * Network Error Codes (2000-2099)
 * ======================================================================== */

/** @brief Network operation failed */
#define PQ_ERR_NETWORK_FAILED 2000

/** @brief Connection establishment failed */
#define PQ_ERR_CONNECTION_FAILED 2001

/** @brief Operation timed out */
#define PQ_ERR_TIMEOUT 2002

/* ========================================================================
 * TLS Error Codes (3000-3099)
 * ======================================================================== */

/** @brief TLS handshake failed */
#define PQ_ERR_TLS_HANDSHAKE_FAILED 3000

/** @brief TLS certificate is invalid */
#define PQ_ERR_TLS_CERTIFICATE_INVALID 3001

/* ========================================================================
 * Configuration Error Codes (4000-4099)
 * ======================================================================== */

/** @brief Configuration is invalid */
#define PQ_ERR_CONFIG_INVALID 4000

/** @brief Configuration loading failed */
#define PQ_ERR_CONFIG_LOAD_FAILED 4001

/** @brief Configuration saving failed */
#define PQ_ERR_CONFIG_SAVE_FAILED 4002

/* ========================================================================
 * Algorithm Error Codes (5000-5099)
 * ======================================================================== */

/** @brief Invalid algorithm specified */
#define PQ_ERR_INVALID_ALGORITHM 5000

/** @brief Algorithm not supported */
#define PQ_ERR_UNSUPPORTED_ALGORITHM 5001

/** @brief Algorithm not available */
#define PQ_ERR_ALGORITHM_NOT_AVAILABLE 5002

/* ========================================================================
 * Error Domain Enumeration
 * ======================================================================== */

/**
 * @brief Error domain enumeration
 *
 * Categorizes error codes into logical domains for better error handling
 * and reporting.
 */
typedef enum {
    PQ_DOMAIN_GENERAL = 0,    /**< General errors (1-99) */
    PQ_DOMAIN_CRYPTO = 1,     /**< Cryptographic errors (1000-1099) */
    PQ_DOMAIN_NETWORK = 2,    /**< Network errors (2000-2099) */
    PQ_DOMAIN_TLS = 3,        /**< TLS errors (3000-3099) */
    PQ_DOMAIN_CONFIG = 4,     /**< Configuration errors (4000-4099) */
    PQ_DOMAIN_ALGORITHM = 5   /**< Algorithm errors (5000-5099) */
} pq_error_domain_t;

/* ========================================================================
 * Error Handling Functions
 * ======================================================================== */

/**
 * @brief Get human-readable error message for an error code
 *
 * @param code Error code to look up
 * @return Constant string describing the error, or "Unknown error" if not found
 */
const char* pq_error_string(int code);

/**
 * @brief Get the error domain for a given error code
 *
 * @param code Error code to analyze
 * @return Error domain enumeration value
 */
pq_error_domain_t pq_error_domain(int code);

/**
 * @brief Get human-readable name for an error domain
 *
 * @param domain Error domain enumeration value
 * @return Constant string naming the domain, or "Unknown" if invalid
 */
const char* pq_error_domain_string(pq_error_domain_t domain);

#ifdef __cplusplus
}
#endif

#endif /* PQ_ERRORS_H */
