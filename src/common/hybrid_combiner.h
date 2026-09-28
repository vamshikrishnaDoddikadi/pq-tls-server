/**
 * @file hybrid_combiner.h
 * @brief Pluggable Hybrid Combiner Implementations
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Provides built-in hybrid combiners for merging classical and PQ
 * shared secrets.  The combiner is itself pluggable to accommodate
 * different standards bodies' requirements (IETF, NIST, etc.).
 *
 * Built-in combiners (pq_hybrid_combiner_t vtables):
 *   - KDF-Concat: HKDF-SHA256 over length-framed classical_ss || pq_ss,
 *     with the caller-supplied context bound into the HKDF info.
 *   - XOR: classical_ss XOR pq_ss.  DEPRECATED and INSECURE - see below.
 *
 * Standalone combiner function:
 *   - pq_combiner_xwing_style(): the X-Wing / "QSF" construction
 *     SHA3-256(ss_pq || ss_t || ct_t || pk_t || label), used by the HPKE
 *     hybrid KEM and by hybrid_kex.c.
 *
 * SECURITY NOTE - ciphertext / public-key binding
 * -----------------------------------------------
 * A generic KEM combiner is only IND-CCA secure (when just one component is
 * IND-CCA) if the derived key also depends on the component ciphertexts and
 * public keys, or if the components are known to be ciphertext-binding.
 * The pq_hybrid_combiner_t::combine() interface (crypto_provider.h) only
 * receives the two shared secrets plus an opaque @p context, so the ONLY
 * way to bind ciphertexts/public keys through it is via @p context.
 * Callers of the KDF-Concat combiner SHOULD therefore pass the 32-byte
 * digest produced by pq_combiner_transcript_hash() as the context.
 */

#ifndef PQ_HYBRID_COMBINER_H
#define PQ_HYBRID_COMBINER_H

#include "crypto_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Output size of pq_combiner_transcript_hash() */
#define PQ_COMBINER_TRANSCRIPT_HASH_BYTES 32

/** Output size of pq_combiner_xwing_style() */
#define PQ_COMBINER_XWING_SS_BYTES 32

/**
 * @brief X-Wing label: the six ASCII bytes "\.//^\" (0x5c 0x2e 0x2f 0x2f 0x5e 0x5c)
 *
 * From draft-connolly-cfrg-xwing-kem.  Only use this label when the inputs
 * are exactly X-Wing's (ML-KEM-768 + X25519).
 */
#define PQ_XWING_LABEL "\x5c\x2e\x2f\x2f\x5e\x5c"
#define PQ_XWING_LABEL_BYTES 6

/**
 * @brief Get the KDF-Concat combiner
 *
 * out = HKDF-SHA256(salt = "",
 *                   ikm  = I2OSP(len(classical_ss), 2) || classical_ss ||
 *                          I2OSP(len(pq_ss), 2)        || pq_ss,
 *                   info = "pq-tls-kdf-concat-v2" || context,
 *                   L    = 32)
 *
 * When @p context is empty, the fixed label "pq-tls-hybrid-v1" is used.
 *
 * @warning Without a transcript-binding context (see
 *          pq_combiner_transcript_hash()) this is NOT a generic IND-CCA
 *          combiner: the output does not depend on the ciphertexts or
 *          public keys.  It is acceptable only when the PQ component is
 *          ciphertext-binding (e.g. ML-KEM) AND the classical component is
 *          used as in TLS 1.3, where the transcript is bound separately.
 */
const pq_hybrid_combiner_t *pq_combiner_kdf_concat(void);

/**
 * @brief Get the XOR combiner
 *
 * out = classical_ss XOR pq_ss (both exactly 32 bytes).
 *
 * @deprecated INSECURE.  XOR of two shared secrets is not an IND-CCA-secure
 *             KEM combiner: an attacker who can re-use or maul one component
 *             ciphertext can cancel/control that component's contribution,
 *             and the output binds neither ciphertexts nor public keys.
 *             Kept ONLY for API/registry compatibility (it is registered so
 *             that it can be looked up by method).  No built-in hybrid pair
 *             selects it, and new code MUST NOT use it - use
 *             pq_combiner_kdf_concat() with a transcript context, or
 *             pq_combiner_xwing_style().
 */
const pq_hybrid_combiner_t *pq_combiner_xor(void);

/**
 * @brief Hash a hybrid KEM transcript into a 32-byte binding context
 *
 * digest = SHA3-256("pq-tls-kem-transcript-v1" ||
 *                   I2OSP(len(ct_c),4)  || ct_c  ||
 *                   I2OSP(len(ct_pq),4) || ct_pq ||
 *                   I2OSP(len(pk_c),4)  || pk_c  ||
 *                   I2OSP(len(pk_pq),4) || pk_pq)
 *
 * Pass the digest as the @p context argument of a combiner's combine()
 * so that the combined secret binds the ciphertexts and public keys
 * (KitchenSink-style combiner).  Any field may be empty (NULL, 0).
 *
 * @param out  Output buffer of PQ_COMBINER_TRANSCRIPT_HASH_BYTES bytes
 * @return PQ_SUCCESS or error code
 */
int pq_combiner_transcript_hash(const uint8_t *ct_c, size_t ct_c_len,
                                const uint8_t *ct_pq, size_t ct_pq_len,
                                const uint8_t *pk_c, size_t pk_c_len,
                                const uint8_t *pk_pq, size_t pk_pq_len,
                                uint8_t out[PQ_COMBINER_TRANSCRIPT_HASH_BYTES]);

/**
 * @brief X-Wing-style ("QSF") combiner
 *
 * out = SHA3-256(ss_pq || ss_t || ct_t || pk_t || label)
 *
 * With ss_pq = ML-KEM-768 shared secret, ss_t = X25519 shared secret,
 * ct_t = X25519 ephemeral public key, pk_t = recipient X25519 public key
 * and label = PQ_XWING_LABEL this is exactly the X-Wing combiner of
 * draft-connolly-cfrg-xwing-kem.  The PQ ciphertext is deliberately not
 * hashed: this construction is only IND-CCA when the PQ KEM is
 * ciphertext-second-preimage resistant (true for ML-KEM).
 *
 * Requirements on the caller (for an unambiguous encoding):
 *   - every input except @p label MUST have a length that is fixed for the
 *     chosen parameter set, and
 *   - @p label MUST uniquely identify that parameter set, and no label in
 *     use may be a suffix of another.
 *
 * @param out  Output buffer of PQ_COMBINER_XWING_SS_BYTES bytes
 * @return PQ_SUCCESS or error code
 */
int pq_combiner_xwing_style(const uint8_t *ss_pq, size_t ss_pq_len,
                            const uint8_t *ss_t, size_t ss_t_len,
                            const uint8_t *ct_t, size_t ct_t_len,
                            const uint8_t *pk_t, size_t pk_t_len,
                            const uint8_t *label, size_t label_len,
                            uint8_t out[PQ_COMBINER_XWING_SS_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQ_HYBRID_COMBINER_H */
