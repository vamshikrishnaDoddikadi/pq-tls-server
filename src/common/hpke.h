/**
 * @file hpke.h
 * @brief RFC 9180 Hybrid Public Key Encryption (HPKE) for PQ-TLS
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module implements RFC 9180 HPKE (Hybrid Public Key Encryption) with
 * support for post-quantum key encapsulation mechanisms (ML-KEM) and hybrid
 * modes combining classical (X25519) with post-quantum algorithms.
 *
 * Supported KEM algorithms:
 * - X25519: Classical ECDH (RFC 7748)
 * - ML-KEM-768: Post-quantum KEM (FIPS 203)
 * - X25519+ML-KEM-768: Hybrid concatenation mode
 *
 * Supported AEAD algorithms:
 * - AES-256-GCM: AES in Galois/Counter Mode
 * - ChaCha20-Poly1305: ChaCha20 stream cipher with Poly1305 MAC
 */

#ifndef HPKE_H
#define HPKE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * HPKE Algorithm Identifiers (RFC 9180)
 * ======================================================================== */

/**
 * @brief KEM algorithm identifiers
 *
 * These identifiers follow RFC 9180 codepoints where applicable.
 * Hybrid modes use custom codepoints in the private use range.
 */
typedef enum {
    HPKE_KEM_X25519 = 0x0020,                    /**< X25519 ECDH (RFC 7748) */
    HPKE_KEM_MLKEM768 = 0x0030,                  /**< ML-KEM-768 (FIPS 203) */
    HPKE_KEM_X25519_MLKEM768_CONCAT = 0x1001    /**< Hybrid: X25519 + ML-KEM-768 (concatenation) */
} pq_hpke_kem_t;

/**
 * @brief AEAD algorithm identifiers
 *
 * These identifiers follow RFC 9180 codepoints.
 */
typedef enum {
    HPKE_AEAD_AES256GCM = 0x0001,    /**< AES-256-GCM */
    HPKE_AEAD_CHACHAPOLY = 0x0003    /**< ChaCha20-Poly1305 */
} pq_hpke_aead_t;

/* ========================================================================
 * HPKE Context Structure
 * ======================================================================== */

/**
 * @brief HPKE context structure
 *
 * Maintains state for HPKE operations including algorithm selection
 * and key material.
 */
typedef struct pq_hpke_t {
    int kem;                /**< KEM algorithm identifier */
    int aead;               /**< AEAD algorithm identifier */
    uint8_t *secret_key;    /**< Secret key material (owned by context) */
    size_t secret_key_len;  /**< Length of secret key in bytes */
} pq_hpke_t;

/* ========================================================================
 * HPKE Key and Encapsulated Data Sizes
 * ======================================================================== */

/* X25519 sizes */
#define HPKE_X25519_PUBLICKEY_BYTES     32   /**< X25519 public key size */
#define HPKE_X25519_SECRETKEY_BYTES     32   /**< X25519 secret key size */
#define HPKE_X25519_ENCAPSULATED_BYTES  32   /**< X25519 encapsulated key size */
#define HPKE_X25519_SHAREDSECRET_BYTES  32   /**< X25519 shared secret size */

/* ML-KEM-768 sizes (from FIPS 203) */
#define HPKE_MLKEM768_PUBLICKEY_BYTES     1184  /**< ML-KEM-768 public key size */
#define HPKE_MLKEM768_SECRETKEY_BYTES     2400  /**< ML-KEM-768 secret key size */
#define HPKE_MLKEM768_ENCAPSULATED_BYTES  1088  /**< ML-KEM-768 ciphertext size */
#define HPKE_MLKEM768_SHAREDSECRET_BYTES  32    /**< ML-KEM-768 shared secret size */

/* Hybrid X25519+ML-KEM-768 sizes (concatenation mode) */
#define HPKE_HYBRID_PUBLICKEY_BYTES     (HPKE_X25519_PUBLICKEY_BYTES + HPKE_MLKEM768_PUBLICKEY_BYTES)        /**< 1216 bytes */
#define HPKE_HYBRID_SECRETKEY_BYTES     (HPKE_X25519_SECRETKEY_BYTES + HPKE_MLKEM768_SECRETKEY_BYTES)        /**< 2432 bytes */
#define HPKE_HYBRID_ENCAPSULATED_BYTES  (HPKE_X25519_ENCAPSULATED_BYTES + HPKE_MLKEM768_ENCAPSULATED_BYTES)  /**< 1120 bytes */
#define HPKE_HYBRID_SHAREDSECRET_BYTES  (HPKE_X25519_SHAREDSECRET_BYTES + HPKE_MLKEM768_SHAREDSECRET_BYTES)  /**< 64 bytes */

/* AEAD parameters */
#define HPKE_AEAD_IV_BYTES   12  /**< IV/nonce size for GCM and ChaCha20-Poly1305 */
#define HPKE_AEAD_TAG_BYTES  16  /**< Authentication tag size */

/* ========================================================================
 * HPKE Context Management
 * ======================================================================== */

/**
 * @brief Initialize HPKE context
 *
 * Creates a new HPKE context with specified KEM and AEAD algorithms.
 * The context must be freed with pq_hpke_free() when no longer needed.
 *
 * @param kem KEM algorithm identifier (HPKE_KEM_*)
 * @param aead AEAD algorithm identifier (HPKE_AEAD_*)
 * @return Pointer to initialized HPKE context, or NULL on failure
 *
 * @note The returned context owns its internal buffers and must be freed.
 */
pq_hpke_t* pq_hpke_init(int kem, int aead);

/**
 * @brief Free HPKE context
 *
 * Securely clears and frees all memory associated with the HPKE context.
 * After calling this function, the context pointer is invalid.
 *
 * @param hpke HPKE context to free (may be NULL)
 *
 * @note All secret key material is securely zeroed before deallocation.
 */
void pq_hpke_free(pq_hpke_t *hpke);

/* ========================================================================
 * HPKE Key Operations
 * ======================================================================== */

/**
 * @brief Generate HPKE key pair
 *
 * Generates a public/secret key pair for the KEM algorithm specified
 * in the HPKE context.
 *
 * @param hpke HPKE context
 * @param pk Output buffer for public key (must be pq_hpke_publickey_bytes() size)
 * @param pk_len Size of public key buffer
 * @param sk Output buffer for secret key (must be pq_hpke_secretkey_bytes() size)
 * @param sk_len Size of secret key buffer
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note For hybrid mode, keys are concatenated: X25519_PK || ML-KEM-768_PK
 */
int pq_hpke_keygen(pq_hpke_t *hpke, uint8_t *pk, size_t pk_len,
                   uint8_t *sk, size_t sk_len);

/**
 * @brief Encapsulate shared secret (sender side)
 *
 * Generates a random shared secret and encapsulates it using the recipient's
 * public key. Returns both the encapsulated key (to send) and the shared
 * secret (to use for encryption).
 *
 * @param hpke HPKE context
 * @param enc Output buffer for encapsulated key (must be pq_hpke_encapsulated_bytes() size)
 * @param enc_len Output parameter for actual encapsulated key length
 * @param ss Output buffer for shared secret (must be pq_hpke_sharedsecret_bytes() size)
 * @param ss_len Size of shared secret buffer
 * @param pk Recipient's public key
 * @param pk_len Length of public key
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note For hybrid mode, encapsulated keys are concatenated: X25519_ENC || ML-KEM-768_ENC
 *       and shared secrets are concatenated: X25519_SS || ML-KEM-768_SS
 */
int pq_hpke_encapsulate(pq_hpke_t *hpke, uint8_t *enc, size_t *enc_len,
                        uint8_t *ss, size_t ss_len,
                        const uint8_t *pk, size_t pk_len);

/**
 * @brief Decapsulate shared secret (receiver side)
 *
 * Recovers the shared secret from an encapsulated key using the recipient's
 * secret key.
 *
 * @param hpke HPKE context
 * @param ss Output buffer for shared secret (must be pq_hpke_sharedsecret_bytes() size)
 * @param ss_len Size of shared secret buffer
 * @param enc Encapsulated key from sender
 * @param enc_len Length of encapsulated key
 * @param sk Recipient's secret key
 * @param sk_len Length of secret key
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note For hybrid mode, the recovered shared secret is concatenated: X25519_SS || ML-KEM-768_SS
 */
int pq_hpke_decapsulate(pq_hpke_t *hpke, uint8_t *ss, size_t ss_len,
                        const uint8_t *enc, size_t enc_len,
                        const uint8_t *sk, size_t sk_len);

/* ========================================================================
 * HPKE AEAD Operations
 * ======================================================================== */

/**
 * @brief Seal (encrypt and authenticate) plaintext
 *
 * Encrypts plaintext using the AEAD algorithm specified in the HPKE context.
 * The ciphertext includes: IV (12 bytes) || encrypted_data || tag (16 bytes)
 *
 * @param hpke HPKE context
 * @param ct Output buffer for ciphertext (must be pt_len + 12 + 16 bytes)
 * @param ct_len Output parameter for actual ciphertext length
 * @param pt Plaintext to encrypt
 * @param pt_len Length of plaintext
 * @param aad Additional authenticated data (may be NULL if aad_len is 0)
 * @param aad_len Length of additional authenticated data
 * @param ss Shared secret from encapsulation (first 32 bytes used as key)
 * @param ss_len Length of shared secret
 * @return PQ_SUCCESS on success, error code on failure
 *
 * @note A random IV is generated for each encryption. The IV is prepended
 *       to the ciphertext and the authentication tag is appended.
 */
int pq_hpke_seal(pq_hpke_t *hpke, uint8_t *ct, size_t *ct_len,
                 const uint8_t *pt, size_t pt_len,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ss, size_t ss_len);

/**
 * @brief Open (decrypt and verify) ciphertext
 *
 * Decrypts ciphertext using the AEAD algorithm specified in the HPKE context.
 * Verifies the authentication tag before returning plaintext.
 *
 * @param hpke HPKE context
 * @param pt Output buffer for plaintext (must be ct_len - 12 - 16 bytes)
 * @param pt_len Output parameter for actual plaintext length
 * @param ct Ciphertext to decrypt (IV || encrypted_data || tag)
 * @param ct_len Length of ciphertext
 * @param aad Additional authenticated data (must match seal AAD)
 * @param aad_len Length of additional authenticated data
 * @param ss Shared secret from decapsulation (first 32 bytes used as key)
 * @param ss_len Length of shared secret
 * @return PQ_SUCCESS on success, PQ_ERR_VERIFICATION_FAILED if tag invalid
 *
 * @note The IV is extracted from the first 12 bytes of ciphertext.
 *       Authentication tag verification failure returns PQ_ERR_VERIFICATION_FAILED.
 */
int pq_hpke_open(pq_hpke_t *hpke, uint8_t *pt, size_t *pt_len,
                 const uint8_t *ct, size_t ct_len,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *ss, size_t ss_len);

/* ========================================================================
 * HPKE Size Query Functions
 * ======================================================================== */

/**
 * @brief Get public key size for KEM algorithm
 *
 * @param kem KEM algorithm identifier
 * @return Public key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_hpke_publickey_bytes(int kem);

/**
 * @brief Get secret key size for KEM algorithm
 *
 * @param kem KEM algorithm identifier
 * @return Secret key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_hpke_secretkey_bytes(int kem);

/**
 * @brief Get encapsulated key size for KEM algorithm
 *
 * @param kem KEM algorithm identifier
 * @return Encapsulated key size in bytes, or 0 if algorithm is invalid
 */
size_t pq_hpke_encapsulated_bytes(int kem);

/**
 * @brief Get shared secret size for KEM algorithm
 *
 * @param kem KEM algorithm identifier
 * @return Shared secret size in bytes, or 0 if algorithm is invalid
 */
size_t pq_hpke_sharedsecret_bytes(int kem);

#ifdef __cplusplus
}
#endif

#endif /* HPKE_H */
