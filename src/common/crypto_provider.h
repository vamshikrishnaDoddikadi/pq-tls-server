/**
 * @file crypto_provider.h
 * @brief Crypto-Agility Provider Interface for PQ-TLS
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Defines the pluggable provider interface that all KEM and signature
 * implementations must satisfy.  This is the heart of the crypto-agility
 * layer: operators can swap algorithms at runtime without recompiling.
 *
 * Provider lifecycle:
 *   1. Provider is registered (static or dynamic plugin)
 *   2. Registry queries provider metadata for capability advertisement
 *   3. Policy engine selects providers based on preference/security level
 *   4. TLS handshake engine invokes provider operations
 */

#ifndef PQ_CRYPTO_PROVIDER_H
#define PQ_CRYPTO_PROVIDER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Algorithm Family and Status
 * ======================================================================== */

/** Algorithm family identifiers */
typedef enum {
    PQ_ALG_FAMILY_LATTICE     = 0,  /**< Lattice-based (ML-KEM, ML-DSA) */
    PQ_ALG_FAMILY_CODE        = 1,  /**< Code-based (HQC, BIKE) */
    PQ_ALG_FAMILY_HASH        = 2,  /**< Hash-based (SPHINCS+, XMSS) */
    PQ_ALG_FAMILY_ISOGENY     = 3,  /**< Isogeny-based (future) */
    PQ_ALG_FAMILY_CLASSICAL   = 4,  /**< Classical (X25519, P-256, Ed25519, RSA) */
    PQ_ALG_FAMILY_HYBRID      = 5   /**< Hybrid classical+PQ combination */
} pq_algorithm_family_t;

/** Algorithm standardization status */
typedef enum {
    PQ_ALG_STATUS_STANDARD    = 0,  /**< NIST/IETF standardized (FIPS 203/204) */
    PQ_ALG_STATUS_CANDIDATE   = 1,  /**< NIST round 4 candidate (HQC, BIKE) */
    PQ_ALG_STATUS_DRAFT       = 2,  /**< Internet-Draft stage */
    PQ_ALG_STATUS_EXPERIMENTAL= 3,  /**< Research / experimental */
    PQ_ALG_STATUS_DEPRECATED  = 4   /**< Deprecated (Kyber pre-standard, etc.) */
} pq_algorithm_status_t;

/** Provider type */
typedef enum {
    PQ_PROVIDER_KEM  = 0,   /**< Key Encapsulation Mechanism */
    PQ_PROVIDER_SIG  = 1    /**< Digital Signature Algorithm */
} pq_provider_type_t;

/* ========================================================================
 * Algorithm Metadata
 * ======================================================================== */

/**
 * @brief Algorithm metadata returned by providers
 *
 * Contains all static information about an algorithm needed for
 * policy decisions, capability advertisement, and audit logging.
 */
typedef struct {
    /* Identity */
    const char          *name;          /**< Canonical name, e.g. "ML-KEM-768" */
    const char          *oid;           /**< NIST/IANA OID string (dot notation) */
    const char          *tls_group;     /**< OpenSSL group name for TLS negotiation */

    /* Classification */
    pq_algorithm_family_t family;
    pq_algorithm_status_t status;
    int                   nist_level;   /**< NIST security level (1,2,3,5) or 0 */

    /* Sizes (bytes) */
    size_t pk_size;          /**< Public key size */
    size_t sk_size;          /**< Secret key size */
    size_t ct_size;          /**< Ciphertext size (KEM) or max signature size (SIG) */
    size_t ss_size;          /**< Shared secret size (KEM only, 0 for SIG) */
} pq_algorithm_metadata_t;

/* ========================================================================
 * KEM Provider Interface
 * ======================================================================== */

/**
 * @brief KEM provider vtable
 *
 * Every KEM implementation (ML-KEM, HQC, X25519, etc.) must provide
 * a filled-in instance of this structure.  The registry stores pointers
 * to these vtables.
 *
 * Thread safety: All function pointers must be safe to call concurrently
 * from multiple worker threads.  Implementations must not use shared
 * mutable state unless internally synchronized.
 */
typedef struct pq_kem_provider {
    /** Return the canonical algorithm name */
    const char* (*name)(void);

    /** Return full algorithm metadata */
    const pq_algorithm_metadata_t* (*metadata)(void);

    /**
     * Generate a key pair.
     * @param pk  Output public key buffer (pk_size bytes)
     * @param sk  Output secret key buffer (sk_size bytes)
     * @return PQ_SUCCESS or error code
     */
    int (*keygen)(uint8_t *pk, uint8_t *sk);

    /**
     * Encapsulate: generate shared secret and ciphertext.
     * @param pk  Recipient public key
     * @param ct  Output ciphertext buffer (ct_size bytes)
     * @param ss  Output shared secret buffer (ss_size bytes)
     * @return PQ_SUCCESS or error code
     */
    int (*encapsulate)(const uint8_t *pk, uint8_t *ct, uint8_t *ss);

    /**
     * Decapsulate: recover shared secret from ciphertext.
     * @param sk  Recipient secret key
     * @param ct  Ciphertext
     * @param ss  Output shared secret buffer (ss_size bytes)
     * @return PQ_SUCCESS or error code
     */
    int (*decapsulate)(const uint8_t *sk, const uint8_t *ct, uint8_t *ss);

    /**
     * Check whether this provider is available at runtime.
     * May check for hardware support, library presence, etc.
     */
    bool (*is_available)(void);

    /** Provider-specific cleanup (called on registry shutdown) */
    void (*cleanup)(void);
} pq_kem_provider_t;

/* ========================================================================
 * Signature Provider Interface
 * ======================================================================== */

/**
 * @brief Signature provider vtable
 *
 * Every signature implementation (ML-DSA, Ed25519, ECDSA, etc.) must
 * provide a filled-in instance of this structure.
 */
typedef struct pq_sig_provider {
    /** Return the canonical algorithm name */
    const char* (*name)(void);

    /** Return full algorithm metadata */
    const pq_algorithm_metadata_t* (*metadata)(void);

    /**
     * Generate a signing key pair.
     * @param pk  Output public key buffer (pk_size bytes)
     * @param sk  Output secret key buffer (sk_size bytes)
     * @return PQ_SUCCESS or error code
     */
    int (*keygen)(uint8_t *pk, uint8_t *sk);

    /**
     * Sign a message.
     * @param sk       Signer's secret key
     * @param msg      Message to sign
     * @param msg_len  Message length
     * @param sig      Output signature buffer (ct_size bytes max)
     * @param sig_len  Output actual signature length
     * @return PQ_SUCCESS or error code
     */
    int (*sign)(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                uint8_t *sig, size_t *sig_len);

    /**
     * Verify a signature.
     * @param pk       Signer's public key
     * @param msg      Message that was signed
     * @param msg_len  Message length
     * @param sig      Signature to verify
     * @param sig_len  Signature length
     * @return PQ_SUCCESS if valid, PQ_ERR_VERIFICATION_FAILED otherwise
     */
    int (*verify)(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len);

    /**
     * Check whether this provider is available at runtime.
     */
    bool (*is_available)(void);

    /** Provider-specific cleanup */
    void (*cleanup)(void);
} pq_sig_provider_t;

/* ========================================================================
 * Hybrid Combiner Interface
 * ======================================================================== */

/** Combiner method identifiers */
typedef enum {
    PQ_COMBINER_KDF_CONCAT = 0,  /**< KDF(classical_ss || pq_ss) — IETF draft */
    PQ_COMBINER_XOR        = 1,  /**< classical_ss XOR pq_ss (fixed 32 bytes) */
    PQ_COMBINER_DUAL_PRF   = 2   /**< Dual-PRF combiner (future) */
} pq_combiner_method_t;

/**
 * @brief Hybrid combiner vtable
 *
 * Takes a classical shared secret and a PQ shared secret and produces
 * a single hybrid shared secret.  The combiner is itself pluggable to
 * accommodate different standards bodies' requirements.
 */
typedef struct pq_hybrid_combiner {
    /** Combiner method identifier */
    pq_combiner_method_t method;

    /** Human-readable name */
    const char *name;

    /**
     * Combine two shared secrets into one.
     * @param classical_ss      Classical shared secret
     * @param classical_ss_len  Classical shared secret length
     * @param pq_ss             Post-quantum shared secret
     * @param pq_ss_len         Post-quantum shared secret length
     * @param out               Output buffer (out_len bytes)
     * @param out_len           Output length (set by caller to buffer size,
     *                          updated to actual output length)
     * @param context           Optional context string for domain separation
     * @param context_len       Context string length (0 if no context)
     * @return PQ_SUCCESS or error code
     */
    int (*combine)(const uint8_t *classical_ss, size_t classical_ss_len,
                   const uint8_t *pq_ss, size_t pq_ss_len,
                   uint8_t *out, size_t *out_len,
                   const uint8_t *context, size_t context_len);

    /**
     * Return the output size for given input sizes.
     */
    size_t (*output_size)(size_t classical_ss_len, size_t pq_ss_len);
} pq_hybrid_combiner_t;

/* ========================================================================
 * Hybrid KEM Pair Descriptor
 * ======================================================================== */

/**
 * @brief Describes a hybrid KEM configuration
 *
 * Used in the preference list to specify a (classical, pq) KEM pair
 * along with the combiner method.
 */
typedef struct {
    const char              *label;         /**< Display name, e.g. "X25519+ML-KEM-768" */
    const char              *tls_group;     /**< OpenSSL group name for TLS */
    const pq_kem_provider_t *classical;     /**< Classical KEM provider (or NULL) */
    const pq_kem_provider_t *pq;            /**< PQ KEM provider (or NULL for classical-only) */
    const pq_hybrid_combiner_t *combiner;   /**< Combiner (NULL if not hybrid) */
    int                      nist_level;    /**< Effective NIST security level */
} pq_hybrid_kem_t;

/* ========================================================================
 * Plugin Descriptor (for dynamic loading)
 * ======================================================================== */

/** Plugin API version — bump on breaking changes */
#define PQ_PLUGIN_API_VERSION 1

/**
 * @brief Plugin descriptor returned by a shared library's entry point
 *
 * Dynamic plugins expose a single function:
 *   const pq_plugin_descriptor_t* pq_plugin_init(void);
 *
 * The descriptor tells the registry what providers the plugin offers.
 */
typedef struct {
    int api_version;                        /**< Must equal PQ_PLUGIN_API_VERSION */
    const char *plugin_name;                /**< e.g. "hqc-provider" */
    const char *plugin_version;             /**< e.g. "1.0.0" */

    const pq_kem_provider_t **kem_providers;  /**< NULL-terminated array */
    size_t kem_count;

    const pq_sig_provider_t **sig_providers;  /**< NULL-terminated array */
    size_t sig_count;
} pq_plugin_descriptor_t;

/** Plugin entry point function signature */
typedef const pq_plugin_descriptor_t* (*pq_plugin_init_fn)(void);

#ifdef __cplusplus
}
#endif

#endif /* PQ_CRYPTO_PROVIDER_H */
