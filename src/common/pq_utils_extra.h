/**
 * @file pq_utils_extra.h
 * @brief Extended utility functions for PQ-TLS
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module provides additional utility functions for the PQ-TLS implementation,
 * including constant-time operations for side-channel resistance, hex encoding/decoding,
 * and result code handling.
 */

#ifndef PQ_UTILS_EXTRA_H
#define PQ_UTILS_EXTRA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Constant-Time Operations
 * ======================================================================== */

/**
 * @brief Constant-time equality check for uint32_t values
 *
 * This function compares two uint32_t values in constant time to prevent
 * timing side-channel attacks. It uses bitwise operations without conditional
 * branches based on the input values.
 *
 * @param a First value to compare
 * @param b Second value to compare
 * @return 1 if values are equal, 0 otherwise
 *
 * @note This function is designed to be resistant to timing attacks by
 *       ensuring execution time is independent of input values.
 */
int pq_constant_time_equals_uint32(uint32_t a, uint32_t b);

/**
 * @brief Constant-time memory comparison
 *
 * Compares two memory regions in constant time, processing the entire buffer
 * regardless of where differences are found. This prevents timing attacks that
 * could leak information about the position of differences.
 *
 * @param a Pointer to first memory region
 * @param b Pointer to second memory region
 * @param len Number of bytes to compare
 * @return 0 if regions are equal, non-zero otherwise
 *
 * @note Unlike memcmp(), this function always processes the entire buffer
 *       and does not return early when a difference is found.
 */
int pq_timing_safe_cmp(const void *a, const void *b, size_t len);

/* ========================================================================
 * Result Code Handling
 * ======================================================================== */

/**
 * @brief Check if a result code indicates an error
 *
 * Determines whether a result code represents an error condition.
 * PQ_SUCCESS (0) is considered success; all other values are errors.
 *
 * @param result Result code to check
 * @return 1 if result is an error, 0 if success
 */
int pq_result_is_error(int result);

/**
 * @brief Convert result code to human-readable string
 *
 * Converts a result code to a descriptive string message using the
 * error handling system from pq_errors.h.
 *
 * @param result Result code to convert
 * @return Constant string describing the result, never NULL
 */
const char* pq_result_to_string(int result);

/* ========================================================================
 * Hex Encoding/Decoding
 * ======================================================================== */

/**
 * @brief Encode binary data to hexadecimal string
 *
 * Converts binary data to a null-terminated hexadecimal string representation.
 * Each byte is encoded as two hexadecimal characters (uppercase).
 *
 * @param data Pointer to binary data to encode
 * @param data_len Length of binary data in bytes
 * @param hex_str Output buffer for hexadecimal string
 * @param hex_str_len Size of output buffer (must be at least data_len * 2 + 1)
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note The output buffer must be large enough to hold the encoded string
 *       plus null terminator (data_len * 2 + 1 bytes).
 */
int pq_hex_encode(const uint8_t *data, size_t data_len, 
                  char *hex_str, size_t hex_str_len);

/**
 * @brief Decode hexadecimal string to binary data
 *
 * Converts a hexadecimal string to binary data. The input string must contain
 * an even number of valid hexadecimal characters (0-9, A-F, a-f).
 *
 * @param hex_str Hexadecimal string to decode
 * @param data Output buffer for binary data
 * @param data_len Size of output buffer (must be at least strlen(hex_str) / 2)
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note The input string length must be even. The output buffer must be
 *       large enough to hold the decoded data (strlen(hex_str) / 2 bytes).
 */
int pq_hex_decode(const char *hex_str, uint8_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* PQ_UTILS_EXTRA_H */
