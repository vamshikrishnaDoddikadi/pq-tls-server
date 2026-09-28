/**
 * @file sig_providers.c
 * @brief Signature Provider Implementations using liboqs + OpenSSL
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Adapts pq_sig.h to the pq_sig_provider_t interface (crypto_provider.h).
 *
 * sign() contract: per crypto_provider.h the signature buffer is metadata()
 * ->ct_size bytes and *sig_len is OUTPUT only.  pq_sig_sign() needs the
 * buffer capacity in *sig_len, so the wrappers below always set it to
 * ct_size first (never trusting the caller's input value, which may be 0 or
 * uninitialised).
 *
 * is_available() runs pq_sig_self_test() once per algorithm (pthread_once,
 * so it is thread-safe and cheap after the first call): it checks that the
 * backend exists, that liboqs's sizes match the constants used for the
 * metadata below, and that a sign/verify round trip works.  All key
 * material used by the self test is wiped.
 */

#include "sig_providers.h"
#include "pq_sig.h"
#include "pq_errors.h"

#include <pthread.h>
#include <stdbool.h>
#include <string.h>

/* ========================================================================
 * Shared helpers
 * ======================================================================== */

static int provider_sign(int alg, const pq_algorithm_metadata_t *meta,
                         const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                         uint8_t *sig, size_t *sig_len)
{
    if (!sig_len) return PQ_ERR_NULL_POINTER;
    *sig_len = meta->ct_size;   /* buffer capacity per the provider contract */
    return pq_sig_sign(alg, sig, sig_len, msg, msg_len, sk);
}

#define DEFINE_SIG_PROVIDER(tag, ALG, NAME, OID, FAMILY, LEVEL, PK, SK, SIG)        \
    static const char *tag##_name(void) { return NAME; }                              \
                                                                                      \
    static const pq_algorithm_metadata_t tag##_meta = {                               \
        .name       = NAME,                                                           \
        .oid        = OID,                                                            \
        .tls_group  = NULL,                                                           \
        .family     = FAMILY,                                                         \
        .status     = PQ_ALG_STATUS_STANDARD,                                         \
        .nist_level = LEVEL,                                                          \
        .pk_size    = PK,                                                             \
        .sk_size    = SK,                                                             \
        .ct_size    = SIG,                                                            \
        .ss_size    = 0,                                                              \
    };                                                                                \
                                                                                      \
    static const pq_algorithm_metadata_t *tag##_metadata(void) { return &tag##_meta; }\
                                                                                      \
    static int tag##_keygen(uint8_t *pk, uint8_t *sk)                                 \
    {                                                                                 \
        return pq_sig_keypair(ALG, pk, sk);                                           \
    }                                                                                 \
                                                                                      \
    static int tag##_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,      \
                          uint8_t *sig, size_t *sig_len)                              \
    {                                                                                 \
        return provider_sign(ALG, &tag##_meta, sk, msg, msg_len, sig, sig_len);       \
    }                                                                                 \
                                                                                      \
    static int tag##_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,    \
                            const uint8_t *sig, size_t sig_len)                       \
    {                                                                                 \
        return pq_sig_verify(ALG, msg, msg_len, sig, sig_len, pk);                    \
    }                                                                                 \
                                                                                      \
    static pthread_once_t tag##_once = PTHREAD_ONCE_INIT;                             \
    static bool tag##_available = false;                                              \
    static void tag##_probe(void)                                                     \
    {                                                                                 \
        tag##_available = (pq_sig_self_test(ALG) == PQ_SUCCESS);                      \
    }                                                                                 \
    static bool tag##_is_available(void)                                              \
    {                                                                                 \
        pthread_once(&tag##_once, tag##_probe);                                       \
        return tag##_available;                                                       \
    }                                                                                 \
                                                                                      \
    static void tag##_cleanup(void) { }                                               \
                                                                                      \
    static const pq_sig_provider_t tag##_provider = {                                 \
        .name          = tag##_name,                                                  \
        .metadata      = tag##_metadata,                                              \
        .keygen        = tag##_keygen,                                                \
        .sign          = tag##_sign,                                                  \
        .verify        = tag##_verify,                                                \
        .is_available  = tag##_is_available,                                          \
        .cleanup       = tag##_cleanup,                                               \
    }

/* ========================================================================
 * ML-DSA-44 (NIST Level 2)
 * ======================================================================== */

DEFINE_SIG_PROVIDER(mldsa44, PQ_SIG_MLDSA44, "ML-DSA-44", "2.16.840.1.101.3.4.3.17",
                    PQ_ALG_FAMILY_LATTICE, 2,
                    PQ_SIG_MLDSA44_PUBLICKEY_BYTES, PQ_SIG_MLDSA44_SECRETKEY_BYTES,
                    PQ_SIG_MLDSA44_SIGNATURE_BYTES);

const pq_sig_provider_t *pq_sig_provider_mldsa44(void) { return &mldsa44_provider; }

/* ========================================================================
 * ML-DSA-65 (NIST Level 3)
 * ======================================================================== */

DEFINE_SIG_PROVIDER(mldsa65, PQ_SIG_MLDSA65, "ML-DSA-65", "2.16.840.1.101.3.4.3.18",
                    PQ_ALG_FAMILY_LATTICE, 3,
                    PQ_SIG_MLDSA65_PUBLICKEY_BYTES, PQ_SIG_MLDSA65_SECRETKEY_BYTES,
                    PQ_SIG_MLDSA65_SIGNATURE_BYTES);

const pq_sig_provider_t *pq_sig_provider_mldsa65(void) { return &mldsa65_provider; }

/* ========================================================================
 * ML-DSA-87 (NIST Level 5)
 * ======================================================================== */

DEFINE_SIG_PROVIDER(mldsa87, PQ_SIG_MLDSA87, "ML-DSA-87", "2.16.840.1.101.3.4.3.19",
                    PQ_ALG_FAMILY_LATTICE, 5,
                    PQ_SIG_MLDSA87_PUBLICKEY_BYTES, PQ_SIG_MLDSA87_SECRETKEY_BYTES,
                    PQ_SIG_MLDSA87_SIGNATURE_BYTES);

const pq_sig_provider_t *pq_sig_provider_mldsa87(void) { return &mldsa87_provider; }

/* ========================================================================
 * Ed25519 (Classical)
 * ======================================================================== */

DEFINE_SIG_PROVIDER(ed25519, PQ_SIG_ED25519, "Ed25519", "1.3.101.112",
                    PQ_ALG_FAMILY_CLASSICAL, 1,
                    PQ_SIG_ED25519_PUBLICKEY_BYTES, PQ_SIG_ED25519_SECRETKEY_BYTES,
                    PQ_SIG_ED25519_SIGNATURE_BYTES);

const pq_sig_provider_t *pq_sig_provider_ed25519(void) { return &ed25519_provider; }
