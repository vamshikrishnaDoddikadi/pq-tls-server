/**
 * @file pq_errors.c
 * @brief Error handling implementation for PQ-TLS
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module implements comprehensive error handling utilities including
 * error code to string mapping, domain classification, and error reporting
 * functions for the PQ-TLS implementation.
 */

#include "pq_errors.h"
#include <stdio.h>

/* ========================================================================
 * Error Message Mapping Table
 * ======================================================================== */

/**
 * @brief Static mapping of error codes to human-readable messages
 *
 * This table provides descriptive error messages for all defined error codes
 * across all domains. The table is searched linearly by pq_error_string().
 */
static const struct {
    int code;
    const char* message;
} error_messages[] = {
    /* Success */
    {PQ_SUCCESS, "Success"},
    
    /* General Errors (1-99) */
    {PQ_ERR_MEMORY_ALLOCATION, "Memory allocation failed"},
    {PQ_ERR_INVALID_PARAMETER, "Invalid parameter provided"},
    {PQ_ERR_NULL_POINTER, "NULL pointer encountered"},
    {PQ_ERR_BUFFER_TOO_SMALL, "Buffer size too small"},
    
    /* Cryptographic Errors (1000-1099) */
    {PQ_ERR_CRYPTO_FAILED, "Cryptographic operation failed"},
    {PQ_ERR_INVALID_FORMAT, "Invalid format encountered"},
    {PQ_ERR_KEY_GENERATION_FAILED, "Key generation failed"},
    {PQ_ERR_SIGNATURE_FAILED, "Signature operation failed"},
    {PQ_ERR_VERIFICATION_FAILED, "Signature verification failed"},
    {PQ_ERR_ENCRYPTION_FAILED, "Encryption operation failed"},
    {PQ_ERR_DECRYPTION_FAILED, "Decryption operation failed"},
    
    /* Network Errors (2000-2099) */
    {PQ_ERR_NETWORK_FAILED, "Network operation failed"},
    {PQ_ERR_CONNECTION_FAILED, "Connection establishment failed"},
    {PQ_ERR_TIMEOUT, "Operation timed out"},
    
    /* TLS Errors (3000-3099) */
    {PQ_ERR_TLS_HANDSHAKE_FAILED, "TLS handshake failed"},
    {PQ_ERR_TLS_CERTIFICATE_INVALID, "TLS certificate is invalid"},
    
    /* Configuration Errors (4000-4099) */
    {PQ_ERR_CONFIG_INVALID, "Configuration is invalid"},
    {PQ_ERR_CONFIG_LOAD_FAILED, "Configuration loading failed"},
    {PQ_ERR_CONFIG_SAVE_FAILED, "Configuration saving failed"},

    /* Algorithm Errors (5000-5099) */
    {PQ_ERR_INVALID_ALGORITHM, "Invalid algorithm specified"},
    {PQ_ERR_UNSUPPORTED_ALGORITHM, "Algorithm not supported"},
    {PQ_ERR_ALGORITHM_NOT_AVAILABLE, "Algorithm not available"}
};

/**
 * @brief Number of entries in the error_messages table
 */
#define ERROR_MESSAGE_COUNT (sizeof(error_messages) / sizeof(error_messages[0]))

/* ========================================================================
 * Error Handling Function Implementations
 * ======================================================================== */

/**
 * @brief Get human-readable error message for an error code
 *
 * Searches the error_messages table for the given error code and returns
 * the corresponding descriptive message. If the code is not found, returns
 * a generic "Unknown error" message.
 *
 * @param code Error code to look up
 * @return Constant string describing the error, never NULL
 */
const char* pq_error_string(int code) {
    for (size_t i = 0; i < ERROR_MESSAGE_COUNT; i++) {
        if (error_messages[i].code == code) {
            return error_messages[i].message;
        }
    }
    return "Unknown error";
}

/**
 * @brief Get the error domain for a given error code
 *
 * Analyzes the error code value to determine which domain it belongs to
 * based on the defined error code ranges:
 * - 0: Success (treated as general)
 * - 1-99: General errors
 * - 1000-1099: Cryptographic errors
 * - 2000-2099: Network errors
 * - 3000-3099: TLS errors
 * - 4000-4099: Configuration errors
 * - 5000-5099: Algorithm errors
 *
 * @param code Error code to analyze
 * @return Error domain enumeration value
 */
pq_error_domain_t pq_error_domain(int code) {
    if (code == PQ_SUCCESS || (code >= 1 && code <= 99)) {
        return PQ_DOMAIN_GENERAL;
    }
    else if (code >= 1000 && code <= 1099) {
        return PQ_DOMAIN_CRYPTO;
    }
    else if (code >= 2000 && code <= 2099) {
        return PQ_DOMAIN_NETWORK;
    }
    else if (code >= 3000 && code <= 3099) {
        return PQ_DOMAIN_TLS;
    }
    else if (code >= 4000 && code <= 4099) {
        return PQ_DOMAIN_CONFIG;
    }
    else if (code >= 5000 && code <= 5099) {
        return PQ_DOMAIN_ALGORITHM;
    }
    
    /* Default to general domain for unknown codes */
    return PQ_DOMAIN_GENERAL;
}

/**
 * @brief Get human-readable name for an error domain
 *
 * Converts an error domain enumeration value to a descriptive string name.
 * This is useful for logging and error reporting where the domain context
 * needs to be displayed.
 *
 * @param domain Error domain enumeration value
 * @return Constant string naming the domain, never NULL
 */
const char* pq_error_domain_string(pq_error_domain_t domain) {
    switch (domain) {
        case PQ_DOMAIN_GENERAL:
            return "General";
        case PQ_DOMAIN_CRYPTO:
            return "Cryptographic";
        case PQ_DOMAIN_NETWORK:
            return "Network";
        case PQ_DOMAIN_TLS:
            return "TLS";
        case PQ_DOMAIN_CONFIG:
            return "Configuration";
        case PQ_DOMAIN_ALGORITHM:
            return "Algorithm";
        default:
            return "Unknown";
    }
}
