/**
 * @file hpke.h
 * @brief RFC 9180 Hybrid Public Key Encryption (HPKE), Base mode, for PQ-TLS
 * @author Vamshi Krishna Doddikadi
 * @date 2024-11-26
 *
 * This module implements RFC 9180 HPKE in Base mode (mode_base = 0x00):
 *
 *   - LabeledExtract / LabeledExpand with the "HPKE-v1" prefix and suite_id
 *     (RFC 9180 section 4)
 *   - DHKEM(X25519, HKDF-SHA256) with ExtractAndExpand over
 *     kem_context = enc || pkRm (section 4.1)
 *   - the key schedule deriving key / base_nonce / exporter_secret from the
 *     KEM shared secret, `info`, and the (empty) default PSK (section 5.1)
 *   - per-message nonce = base_nonce XOR I2OSP(seq, Nn) with a strictly
 *     increasing sequence number (section 5.2)
 *   - the secret export interface (section 5.3)
 *
 * KDF: HKDF-SHA256 only (kdf_id 0x0001).
 *
 * KEMs:
 *   - HPKE_KEM_X25519 (0x0020): DHKEM(X25519, HKDF-SHA256), RFC 9180.
 *     Verified against the RFC 9180 Appendix A.1 / A.2 test vectors.
 *
 *   - HPKE_KEM_MLKEM768 (0x0041): ML-KEM-768 (FIPS 203) used directly as the
 *     HPKE KEM (its 32-byte shared secret is the HPKE shared_secret), using
 *     the codepoint registered for ML-KEM-768 by draft-ietf-hpke-pq.  Public
 *     keys and encapsulations use the FIPS 203 encodings.  The private key
 *     here is the 2400-byte expanded FIPS 203 decapsulation key (not the
 *     64-byte seed form), and this mode has NOT been validated against that
 *     draft's test vectors, so do not assume interoperability.
 *
 *   - HPKE_KEM_X25519_MLKEM768_CONCAT (0x1001): X-WING-STYLE HYBRID,
 *     PRIVATE CODEPOINT, NOT INTEROPERABLE.
 *       shared_secret = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
 *     with XWingLabel = "\.//^\" (0x5c 0x2e 0x2f 0x2f 0x5e 0x5c), i.e. the
 *     X-Wing combiner of draft-connolly-cfrg-xwing-kem.  However the key and
 *     ciphertext SERIALIZATION differs from X-Wing (X25519 component first,
 *     expanded 2432-byte private key instead of a 32-byte seed), and 0x1001
 *     is not an IANA HPKE KEM identifier.  It therefore does NOT interoperate
 *     with X-Wing (IANA KEM id 0x647a, "MLKEM768-X25519") or with any other
 *     registered HPKE KEM.  Use it only between two instances of this code.
 *     Because OpenSSL rejects an all-zero X25519 output, decapsulation fails
 *     (instead of returning an implicit-rejection key) for low-order ct_X.
 *
 * AEADs (RFC 9180 codepoints): AES-128-GCM (0x0001), AES-256-GCM (0x0002),
 * ChaCha20-Poly1305 (0x0003).
 *
 * Typical use:
 *   sender:    pq_hpke_init() -> pq_hpke_setup_base_sender(pkR, info) -> enc
 *              pq_hpke_seal() (repeatable, seq increments)
 *   recipient: pq_hpke_init() -> pq_hpke_setup_base_recipient(enc, skR, info)
 *              pq_hpke_open() in the same order as the sender sealed
 * A context is one-directional: a sender context only seals, a recipient
 * context only opens.
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
 * The values are used on the wire inside suite_id, so they determine
 * interoperability.  See the file comment for the status of each KEM.
 */
typedef enum {
    HPKE_KEM_X25519 = 0x0020,                 /**< DHKEM(X25519, HKDF-SHA256), RFC 9180 */
    HPKE_KEM_MLKEM768 = 0x0041,               /**< ML-KEM-768 (draft-ietf-hpke-pq codepoint) */
    HPKE_KEM_X25519_MLKEM768_CONCAT = 0x1001  /**< X-Wing-style hybrid, PRIVATE, not interoperable */
} pq_hpke_kem_t;

/** KDF identifier: HKDF-SHA256 (the only KDF supported) */
#define HPKE_KDF_HKDF_SHA256 0x0001

/**
 * @brief AEAD algorithm identifiers (RFC 9180 section 7.3)
 */
typedef enum {
    HPKE_AEAD_AES128GCM = 0x0001,    /**< AES-128-GCM */
    HPKE_AEAD_AES256GCM = 0x0002,    /**< AES-256-GCM */
    HPKE_AEAD_CHACHAPOLY = 0x0003    /**< ChaCha20-Poly1305 */
} pq_hpke_aead_t;

/** HPKE mode identifiers (only Base mode is implemented) */
#define HPKE_MODE_BASE 0x00

/* ========================================================================
 * HPKE Context
 * ======================================================================== */

/**
 * @brief Opaque HPKE context
 *
 * Holds the algorithm selection and, after one of the setup functions, the
 * key schedule output (key, base_nonce, exporter_secret) and the sequence
 * number.  All secret state is wiped by pq_hpke_free().
 *
 * A context is NOT thread-safe; use one context per sender/recipient.
 */
typedef struct pq_hpke_t pq_hpke_t;

/* ========================================================================
 * HPKE Key and Encapsulated Data Sizes
 * ======================================================================== */

/* X25519 sizes (DHKEM: Npk = Nenc = Nsk = 32, Nsecret = 32) */
#define HPKE_X25519_PUBLICKEY_BYTES     32   /**< X25519 public key size */
#define HPKE_X25519_SECRETKEY_BYTES     32   /**< X25519 secret key size */
#define HPKE_X25519_ENCAPSULATED_BYTES  32   /**< X25519 encapsulated key size */
#define HPKE_X25519_SHAREDSECRET_BYTES  32   /**< DHKEM Nsecret */

/* ML-KEM-768 sizes (from FIPS 203) */
#define HPKE_MLKEM768_PUBLICKEY_BYTES     1184  /**< ML-KEM-768 public key size */
#define HPKE_MLKEM768_SECRETKEY_BYTES     2400  /**< ML-KEM-768 (expanded) secret key size */
#define HPKE_MLKEM768_ENCAPSULATED_BYTES  1088  /**< ML-KEM-768 ciphertext size */
#define HPKE_MLKEM768_SHAREDSECRET_BYTES  32    /**< ML-KEM-768 shared secret size */

/* X-Wing-style hybrid sizes: X25519 component first, then ML-KEM-768 */
#define HPKE_HYBRID_PUBLICKEY_BYTES     (HPKE_X25519_PUBLICKEY_BYTES + HPKE_MLKEM768_PUBLICKEY_BYTES)        /**< 1216 bytes */
#define HPKE_HYBRID_SECRETKEY_BYTES     (HPKE_X25519_SECRETKEY_BYTES + HPKE_MLKEM768_SECRETKEY_BYTES)        /**< 2432 bytes */
#define HPKE_HYBRID_ENCAPSULATED_BYTES  (HPKE_X25519_ENCAPSULATED_BYTES + HPKE_MLKEM768_ENCAPSULATED_BYTES)  /**< 1120 bytes */
#define HPKE_HYBRID_SHAREDSECRET_BYTES  32   /**< SHA3-256 combiner output */

/* AEAD parameters */
#define HPKE_AEAD_NONCE_BYTES 12  /**< Nn for all supported AEADs */
#define HPKE_AEAD_IV_BYTES    HPKE_AEAD_NONCE_BYTES  /**< Legacy alias of HPKE_AEAD_NONCE_BYTES */
#define HPKE_AEAD_TAG_BYTES   16  /**< Nt: authentication tag size */

/** Largest exporter output allowed by RFC 9180 for HKDF-SHA256 (255 * Nh) */
#define HPKE_EXPORT_MAX_BYTES (255u * 32u)

/* ========================================================================
 * HPKE Context Management
 * ======================================================================== */

/**
 * @brief Create an HPKE context for the given KEM and AEAD
 *
 * @param kem  KEM identifier (HPKE_KEM_*)
 * @param aead AEAD identifier (HPKE_AEAD_*)
 * @return New context, or NULL if an algorithm is unsupported or on OOM
 */
pq_hpke_t* pq_hpke_init(int kem, int aead);

/**
 * @brief Securely wipe and free an HPKE context (NULL is accepted)
 */
void pq_hpke_free(pq_hpke_t *hpke);

/* ========================================================================
 * KEM Operations
 * ======================================================================== */

/**
 * @brief Generate a recipient key pair for the context's KEM
 *
 * @param pk     Output public key; pk_len must be >= pq_hpke_publickey_bytes()
 * @param pk_len Capacity of @p pk (exactly pq_hpke_publickey_bytes() are written)
 * @param sk     Output secret key; sk_len must be >= pq_hpke_secretkey_bytes()
 * @param sk_len Capacity of @p sk (exactly pq_hpke_secretkey_bytes() are written)
 * @return PQ_SUCCESS or error code (outputs are wiped on failure)
 *
 * @note Hybrid layout: pk = X25519_pk || ML-KEM-768_pk, sk = X25519_sk || ML-KEM-768_sk
 */
int pq_hpke_keygen(pq_hpke_t *hpke, uint8_t *pk, size_t pk_len,
                   uint8_t *sk, size_t sk_len);

/**
 * @brief DeriveKeyPair(ikm) for DHKEM(X25519, HKDF-SHA256) (RFC 9180 7.1.3)
 *
 * Deterministically derives a key pair from input keying material.  Only
 * supported for HPKE_KEM_X25519; other KEMs return
 * PQ_ERR_UNSUPPORTED_ALGORITHM.  @p ikm should have at least Nsk (32) bytes
 * of entropy.
 */
int pq_hpke_derive_keypair(pq_hpke_t *hpke, const uint8_t *ikm, size_t ikm_len,
                           uint8_t *pk, size_t pk_len,
                           uint8_t *sk, size_t sk_len);

/**
 * @brief KEM Encap(pkR): produce (shared_secret, enc)
 *
 * This is the raw KEM step.  Most callers should use
 * pq_hpke_setup_base_sender(), which also runs the key schedule.
 *
 * @param enc     Output encapsulation
 * @param enc_cap Capacity of @p enc; must be >= pq_hpke_encapsulated_bytes()
 * @param enc_len Output: bytes written to @p enc
 * @param ss      Output KEM shared secret (Nsecret = 32 bytes for every KEM)
 * @param ss_len  Capacity of @p ss; must be >= pq_hpke_sharedsecret_bytes()
 * @param pk      Recipient public key
 * @param pk_len  Must equal pq_hpke_publickey_bytes() exactly
 * @return PQ_SUCCESS or error code
 */
int pq_hpke_encapsulate(pq_hpke_t *hpke, uint8_t *enc, size_t enc_cap, size_t *enc_len,
                        uint8_t *ss, size_t ss_len,
                        const uint8_t *pk, size_t pk_len);

/**
 * @brief KEM Decap(enc, skR): recover the KEM shared secret
 *
 * @param ss      Output KEM shared secret (Nsecret = 32 bytes)
 * @param ss_len  Capacity of @p ss; must be >= pq_hpke_sharedsecret_bytes()
 * @param enc     Encapsulation; enc_len must equal pq_hpke_encapsulated_bytes()
 * @param sk      Recipient secret key; sk_len must equal pq_hpke_secretkey_bytes()
 * @return PQ_SUCCESS or error code
 */
int pq_hpke_decapsulate(pq_hpke_t *hpke, uint8_t *ss, size_t ss_len,
                        const uint8_t *enc, size_t enc_len,
                        const uint8_t *sk, size_t sk_len);

/* ========================================================================
 * Base-mode Setup (RFC 9180 section 5.1.1)
 * ======================================================================== */

/**
 * @brief SetupBaseS(pkR, info): encapsulate and derive the sender context
 *
 * Runs Encap(pkR) and KeySchedule(mode_base, shared_secret, info, "", "")
 * and stores key / base_nonce / exporter_secret in @p hpke (seq = 0).
 * The context must not have been set up before.
 *
 * @param enc      Output encapsulation to send to the recipient
 * @param enc_cap  Capacity of @p enc (>= pq_hpke_encapsulated_bytes())
 * @param enc_len  Output: bytes written
 * @param pkR      Recipient public key (exact length)
 * @param info     Application-supplied info bound into the key schedule
 *                 (may be NULL when info_len == 0)
 */
int pq_hpke_setup_base_sender(pq_hpke_t *hpke,
                              uint8_t *enc, size_t enc_cap, size_t *enc_len,
                              const uint8_t *pkR, size_t pkR_len,
                              const uint8_t *info, size_t info_len);

/**
 * @brief SetupBaseR(enc, skR, info): decapsulate and derive the recipient context
 *
 * The context must not have been set up before.  @p enc and @p skR must have
 * exactly the KEM's encapsulation / secret-key sizes.
 */
int pq_hpke_setup_base_recipient(pq_hpke_t *hpke,
                                 const uint8_t *enc, size_t enc_len,
                                 const uint8_t *skR, size_t skR_len,
                                 const uint8_t *info, size_t info_len);

/**
 * @brief Deterministic SetupBaseS for known-answer tests ONLY
 *
 * Identical to pq_hpke_setup_base_sender() except that the ephemeral key
 * pair is DeriveKeyPair(ikmE) instead of fresh randomness, as in the
 * RFC 9180 Appendix A test vectors.  Only HPKE_KEM_X25519 is supported.
 *
 * @warning NEVER use outside of tests: reusing ikmE for two encryptions to
 *          the same recipient reuses the ephemeral key and destroys security.
 */
int pq_hpke_setup_base_sender_derand(pq_hpke_t *hpke,
                                     const uint8_t *ikmE, size_t ikmE_len,
                                     uint8_t *enc, size_t enc_cap, size_t *enc_len,
                                     const uint8_t *pkR, size_t pkR_len,
                                     const uint8_t *info, size_t info_len);

/* ========================================================================
 * Encryption Context Operations (RFC 9180 sections 5.2 and 5.3)
 * ======================================================================== */

/**
 * @brief ContextS.Seal(aad, pt)
 *
 * Encrypts with nonce = base_nonce XOR I2OSP(seq, 12) and then increments
 * seq.  Output format: ciphertext || tag (pt_len + HPKE_AEAD_TAG_BYTES bytes);
 * the nonce is NOT transmitted - the recipient must open messages in order.
 *
 * @param ct      Output buffer
 * @param ct_cap  Capacity of @p ct; must be >= pt_len + HPKE_AEAD_TAG_BYTES
 * @param ct_len  Output: bytes written
 * @param pt_len  Must be <= INT_MAX - HPKE_AEAD_TAG_BYTES
 * @param aad_len Must be <= INT_MAX
 * @return PQ_SUCCESS, or an error (context not a sender context, sequence
 *         number exhausted, bad lengths, crypto failure)
 */
int pq_hpke_seal(pq_hpke_t *hpke, uint8_t *ct, size_t ct_cap, size_t *ct_len,
                 const uint8_t *pt, size_t pt_len,
                 const uint8_t *aad, size_t aad_len);

/**
 * @brief ContextR.Open(aad, ct)
 *
 * Verifies and decrypts using nonce = base_nonce XOR I2OSP(seq, 12); seq is
 * incremented only on success.  On failure nothing is released: the
 * plaintext buffer is wiped.
 *
 * @param pt      Output buffer
 * @param pt_cap  Capacity of @p pt; must be >= ct_len - HPKE_AEAD_TAG_BYTES
 * @param pt_len  Output: bytes written
 * @param ct      ciphertext || tag, as produced by pq_hpke_seal()
 * @return PQ_SUCCESS, PQ_ERR_VERIFICATION_FAILED if authentication fails,
 *         or another error code
 */
int pq_hpke_open(pq_hpke_t *hpke, uint8_t *pt, size_t pt_cap, size_t *pt_len,
                 const uint8_t *ct, size_t ct_len,
                 const uint8_t *aad, size_t aad_len);

/**
 * @brief Context.Export(exporter_context, L)
 *
 * out = LabeledExpand(exporter_secret, "sec", exporter_context, L)
 *
 * @param out_len L; 1 <= L <= HPKE_EXPORT_MAX_BYTES
 */
int pq_hpke_export(pq_hpke_t *hpke,
                   const uint8_t *exporter_context, size_t exporter_context_len,
                   uint8_t *out, size_t out_len);

/* ========================================================================
 * HPKE Size Query Functions
 * ======================================================================== */

/** @return Npk for @p kem, or 0 if unsupported */
size_t pq_hpke_publickey_bytes(int kem);

/** @return Nsk (serialized secret key size used by this module), or 0 */
size_t pq_hpke_secretkey_bytes(int kem);

/** @return Nenc for @p kem, or 0 if unsupported */
size_t pq_hpke_encapsulated_bytes(int kem);

/** @return Nsecret for @p kem (32 for every supported KEM), or 0 */
size_t pq_hpke_sharedsecret_bytes(int kem);

#ifdef __cplusplus
}
#endif

#endif /* HPKE_H */
