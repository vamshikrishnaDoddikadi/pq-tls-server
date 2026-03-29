/**
 * @file pq_kem.h
 * @brief ML-KEM (Kyber) Key Encapsulation Mechanism for PQ-TLS
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module provides ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)
 * support for post-quantum TLS. ML-KEM is standardized as FIPS 203 and provides
 * quantum-resistant key encapsulation for secure key exchange.
 *
 * Supported algorithms:
 * - ML-KEM-512: NIST Security Level 1 (128-bit quantum security)
 * - ML-KEM-768: NIST Security Level 3 (192-bit quantum security)
 * - ML-KEM-1024: NIST Security Level 5 (256-bit quantum security)
 */

#ifndef PQ_KEM_H
#define PQ_KEM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * ML-KEM Algorithm Identifiers
 * ======================================================================== */

/**
 * @brief ML-KEM algorithm enumeration
 *
 * These identifiers map to the standardized ML-KEM variants from FIPS 203.
 * Kyber aliases are provided for backward compatibility with pre-standardization
 * implementations.
 */
typedef enum {
    PQ_KEM_MLKEM512 = 0,    /**< ML-KEM-512 (NIST Level 1, 128-bit quantum security) */
    PQ_KEM_MLKEM768 = 1,    /**< ML-KEM-768 (NIST Level 3, 192-bit quantum security) */
    PQ_KEM_MLKEM1024 = 2,   /**< ML-KEM-1024 (NIST Level 5, 256-bit quantum security) */
    
    /* Kyber aliases for backward compatibility */
    PQ_KEM_KYBER512 = PQ_KEM_MLKEM512,    /**< Alias for ML-KEM-512 */
    PQ_KEM_KYBER768 = PQ_KEM_MLKEM768,    /**< Alias for ML-KEM-768 */
    PQ_KEM_KYBER1024 = PQ_KEM_MLKEM1024   /**< Alias for ML-KEM-1024 */
} pq_kem_algorithm_t;

/* ========================================================================
 * ML-KEM Key and Ciphertext Sizes
 * ======================================================================== */

/* ML-KEM-512 sizes (NIST Level 1) */
#define PQ_KEM_MLKEM512_PUBLICKEY_BYTES    800   /**< Public key size */
#define PQ_KEM_MLKEM512_SECRETKEY_BYTES    1632  /**< Secret key size */
#define PQ_KEM_MLKEM512_CIPHERTEXT_BYTES   768   /**< Ciphertext size */
#define PQ_KEM_MLKEM512_SHAREDSECRET_BYTES 32    /**< Shared secret size */

/* ML-KEM-768 sizes (NIST Level 3) */
#define PQ_KEM_MLKEM768_PUBLICKEY_BYTES    1184  /**< Public key size */
#define PQ_KEM_MLKEM768_SECRETKEY_BYTES    2400  /**< Secret key size */
#define PQ_KEM_MLKEM768_CIPHERTEXT_BYTES   1088  /**< Ciphertext size */
#define PQ_KEM_MLKEM768_SHAREDSECRET_BYTES 32    /**< Shared secret size */

/* ML-KEM-1024 sizes (NIST Level 5) */
#define PQ_KEM_MLKEM1024_PUBLICKEY_BYTES    1568  /**< Public key size */
#define PQ_KEM_MLKEM1024_SECRETKEY_BYTES    3168  /**< Secret key size */
#define PQ_KEM_MLKEM1024_CIPHERTEXT_BYTES   1568  /**< Ciphertext size */
#define PQ_KEM_MLKEM1024_SHAREDSECRET_BYTES 32    /**< Shared secret size */

/* ========================================================================
 * ML-KEM Core Operations
 * ======================================================================== */

/**
 * @brief Generate ML-KEM key pair
 *
 * Generates a public/secret key pair for the specified ML-KEM algorithm.
 * The keys can be used for key encapsulation and decapsulation operations.
 *
 * @param algorithm ML-KEM algorithm identifier (PQ_KEM_MLKEM512/768/1024)
 * @param pk Output buffer for public key (must be pq_kem_publickey_bytes() size)
 * @param sk Output buffer for secret key (must be pq_kem_secretkey_bytes() size)
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note Buffers must be pre-allocated with sufficient size for the algorithm.
 *       Use pq_kem_publickey_bytes() and pq_kem_secretkey_bytes() to determine sizes.
 */
int pq_kem_keypair(int algorithm, uint8_t *pk, uint8_t *sk);

/**
 * @brief Encapsulate shared secret with ML-KEM
 *
 * Generates a random shared secret and encapsulates it using the recipient's
 * public key. The ciphertext can be sent to the recipient who can recover
 * the shared secret using their secret key.
 *
 * @param algorithm ML-KEM algorithm identifier (PQ_KEM_MLKEM512/768/1024)
 * @param ct Output buffer for ciphertext (must be pq_kem_ciphertext_bytes() size)
 * @param ss Output buffer for shared secret (must be pq_kem_sharedsecret_bytes() size)
 * @param pk Recipient's public key
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note The shared secret is randomly generated and should be used immediately
 *       for key derivation. Do not reuse shared secrets.
 */
int pq_kem_encapsulate(int algorithm, uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/**
 * @brief Decapsulate shared secret with ML-KEM
 *
 * Recovers the shared secret from a ciphertext using the recipient's secret key.
 * The recovered shared secret will match the one generated during encapsulation.
 *
 * @param algorithm ML-KEM algorithm identifier (PQ_KEM_MLKEM512/768/1024)
 * @param ss Output buffer for shared secret (must be pq_kem_sharedsecret_bytes() size)
 * @param ct Ciphertext containing encapsulated shared secret
 * @param sk Recipient's secret key
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note Decapsulation is deterministic - the same ciphertext and secret key
 *       will always produce the same shared secret.
 */
int pq_kem_decapsulate(int algorithm, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* ========================================================================
 * ML-KEM Size Query Functions
 * ======================================================================== */

/**
 * @brief Get public key size for ML-KEM algorithm
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Public key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_kem_publickey_bytes(int algorithm);

/**
 * @brief Get secret key size for ML-KEM algorithm
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Secret key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_kem_secretkey_bytes(int algorithm);

/**
 * @brief Get ciphertext size for ML-KEM algorithm
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Ciphertext size in bytes, or 0 if algorithm is invalid
 */
size_t pq_kem_ciphertext_bytes(int algorithm);

/**
 * @brief Get shared secret size for ML-KEM algorithm
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Shared secret size in bytes (always 32 for ML-KEM), or 0 if algorithm is invalid
 */
size_t pq_kem_sharedsecret_bytes(int algorithm);

/**
 * @brief Get algorithm name string
 *
 * Returns the standardized algorithm name for use with liboqs.
 *
 * @param algorithm ML-KEM algorithm identifier
 * @return Algorithm name string ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"),
 *         or NULL if algorithm is invalid
 */
const char* pq_kem_algorithm_name(int algorithm);

#ifdef __cplusplus
}
#endif

#endif /* PQ_KEM_H */
