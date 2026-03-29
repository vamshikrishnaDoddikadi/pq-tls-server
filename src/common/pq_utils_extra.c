/**
 * @file pq_utils_extra.c
 * @brief Extended utility functions implementation for PQ-TLS
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module implements additional utility functions including constant-time
 * operations for side-channel resistance, hex encoding/decoding, and result
 * code handling.
 */

#include "pq_utils_extra.h"
#include "pq_errors.h"
#include <stdint.h>
#include <string.h>
#include <ctype.h>

/* ========================================================================
 * Constant-Time Operations Implementation
 * ======================================================================== */

/**
 * @brief Constant-time equality check for uint32_t values
 *
 * This implementation uses bit spreading to determine equality without
 * conditional branches. Any difference between the values will propagate
 * through the XOR and shift operations, ensuring constant execution time
 * regardless of input values.
 *
 * Algorithm:
 * 1. XOR the values (result is 0 if equal, non-zero if different)
 * 2. Spread any set bit to the LSB through successive OR-shifts
 * 3. Invert and mask to get 1 for equality, 0 for inequality
 *
 * @param a First value to compare
 * @param b Second value to compare
 * @return 1 if values are equal, 0 otherwise
 */
int pq_constant_time_equals_uint32(uint32_t a, uint32_t b) {
    /* XOR produces 0 if equal, non-zero if different */
    uint32_t diff = a ^ b;
    
    /* Spread any set bit to the LSB through successive OR-shifts */
    diff |= diff >> 16;
    diff |= diff >> 8;
    diff |= diff >> 4;
    diff |= diff >> 2;
    diff |= diff >> 1;
    
    /* Invert and mask: if diff was 0, LSB is now 1; otherwise 0 */
    return (int)((~diff) & 1U);
}

/**
 * @brief Constant-time memory comparison
 *
 * This function compares two memory regions in constant time by processing
 * the entire buffer regardless of where differences are found. It uses
 * bitwise OR accumulation to detect differences without early exit.
 *
 * @param a Pointer to first memory region
 * @param b Pointer to second memory region
 * @param len Number of bytes to compare
 * @return 0 if regions are equal, non-zero otherwise
 */
int pq_timing_safe_cmp(const void *a, const void *b, size_t len) {
    const unsigned char *ua = (const unsigned char *)a;
    const unsigned char *ub = (const unsigned char *)b;
    unsigned char result = 0;
    
    /* Accumulate all differences using bitwise OR */
    /* This ensures we process the entire buffer without early exit */
    for (size_t i = 0; i < len; i++) {
        result |= ua[i] ^ ub[i];
    }
    
    /* Return 0 if equal, non-zero if different */
    return (int)result;
}

/* ========================================================================
 * Result Code Handling Implementation
 * ======================================================================== */

/**
 * @brief Check if a result code indicates an error
 *
 * PQ_SUCCESS (0) is the only success code; all other values indicate errors.
 *
 * @param result Result code to check
 * @return 1 if result is an error, 0 if success
 */
int pq_result_is_error(int result) {
    return (result != PQ_SUCCESS) ? 1 : 0;
}

/**
 * @brief Convert result code to human-readable string
 *
 * This function delegates to the error handling system to provide
 * consistent error messages across the PQ-TLS implementation.
 *
 * @param result Result code to convert
 * @return Constant string describing the result, never NULL
 */
const char* pq_result_to_string(int result) {
    return pq_error_string(result);
}

/* ========================================================================
 * Hex Encoding/Decoding Implementation
 * ======================================================================== */

/**
 * @brief Encode binary data to hexadecimal string
 *
 * Converts each byte to two uppercase hexadecimal characters and
 * null-terminates the result. Validates buffer size before encoding.
 *
 * @param data Pointer to binary data to encode
 * @param data_len Length of binary data in bytes
 * @param hex_str Output buffer for hexadecimal string
 * @param hex_str_len Size of output buffer
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_hex_encode(const uint8_t *data, size_t data_len,
                  char *hex_str, size_t hex_str_len) {
    /* Validate input parameters */
    if (data == NULL || hex_str == NULL) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Check buffer size: need 2 chars per byte plus null terminator */
    if (hex_str_len < (data_len * 2 + 1)) {
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Hexadecimal character lookup table */
    static const char hex_chars[] = "0123456789ABCDEF";
    
    /* Encode each byte as two hex characters */
    for (size_t i = 0; i < data_len; i++) {
        hex_str[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        hex_str[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    
    /* Null-terminate the string */
    hex_str[data_len * 2] = '\0';
    
    return PQ_SUCCESS;
}

/**
 * @brief Decode hexadecimal string to binary data
 *
 * Parses a hexadecimal string (case-insensitive) and converts it to binary.
 * Validates that the string contains only valid hex characters and has even length.
 *
 * @param hex_str Hexadecimal string to decode
 * @param data Output buffer for binary data
 * @param data_len Size of output buffer
 * @return PQ_SUCCESS on success, error code on failure
 */
int pq_hex_decode(const char *hex_str, uint8_t *data, size_t data_len) {
    /* Validate input parameters */
    if (hex_str == NULL || data == NULL) {
        return PQ_ERR_NULL_POINTER;
    }
    
    /* Get input string length */
    size_t hex_len = strlen(hex_str);
    
    /* Hex string must have even length (2 chars per byte) */
    if (hex_len % 2 != 0) {
        return PQ_ERR_INVALID_FORMAT;
    }
    
    /* Check output buffer size */
    if (data_len < (hex_len / 2)) {
        return PQ_ERR_BUFFER_TOO_SMALL;
    }
    
    /* Decode each pair of hex characters to one byte */
    for (size_t i = 0; i < hex_len; i += 2) {
        uint8_t high, low;
        
        /* Convert high nibble */
        if (hex_str[i] >= '0' && hex_str[i] <= '9') {
            high = hex_str[i] - '0';
        } else if (hex_str[i] >= 'A' && hex_str[i] <= 'F') {
            high = hex_str[i] - 'A' + 10;
        } else if (hex_str[i] >= 'a' && hex_str[i] <= 'f') {
            high = hex_str[i] - 'a' + 10;
        } else {
            return PQ_ERR_INVALID_FORMAT;
        }
        
        /* Convert low nibble */
        if (hex_str[i + 1] >= '0' && hex_str[i + 1] <= '9') {
            low = hex_str[i + 1] - '0';
        } else if (hex_str[i + 1] >= 'A' && hex_str[i + 1] <= 'F') {
            low = hex_str[i + 1] - 'A' + 10;
        } else if (hex_str[i + 1] >= 'a' && hex_str[i + 1] <= 'f') {
            low = hex_str[i + 1] - 'a' + 10;
        } else {
            return PQ_ERR_INVALID_FORMAT;
        }
        
        /* Combine nibbles into byte */
        data[i / 2] = (high << 4) | low;
    }
    
    return PQ_SUCCESS;
}
