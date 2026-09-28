/**
 * @file kem_mlkem.c
 * @brief ML-KEM Provider Implementations using liboqs
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Implements pq_kem_provider_t for ML-KEM-512, ML-KEM-768, ML-KEM-1024
 * by delegating to the existing pq_kem.h / liboqs functions.
 *
 * Sizes: the metadata uses the FIPS 203 constants from pq_kem.h.  pq_kem.c
 * verifies on every operation that liboqs reports exactly these sizes (and
 * fails otherwise), and is_available() additionally checks them against
 * OQS_KEM_new() once, so a mismatched liboqs can never cause callers that
 * allocate from metadata() to overflow.
 *
 * is_available() runs a keygen/encaps/decaps self test once per algorithm
 * (pthread_once: thread-safe, cheap after the first call).  All secret
 * material it touches is wiped.
 */

#include "kem_mlkem.h"
#include "pq_kem.h"
#include "pq_errors.h"

#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================
 * Shared self test
 * ======================================================================== */

static bool mlkem_self_test(int alg, const pq_algorithm_metadata_t *meta)
{
    /* 1. liboqs must provide the algorithm with the expected sizes */
    const char *oqs_name = pq_kem_algorithm_name(alg);
    OQS_KEM *kem = oqs_name ? OQS_KEM_new(oqs_name) : NULL;
    if (!kem) return false;
    bool sizes_ok = kem->length_public_key == meta->pk_size &&
                    kem->length_secret_key == meta->sk_size &&
                    kem->length_ciphertext == meta->ct_size &&
                    kem->length_shared_secret == meta->ss_size;
    OQS_KEM_free(kem);
    if (!sizes_ok) return false;

    /* 2. Round trip */
    uint8_t *pk = malloc(meta->pk_size);
    uint8_t *sk = malloc(meta->sk_size);
    uint8_t *ct = malloc(meta->ct_size);
    uint8_t *ss1 = malloc(meta->ss_size);
    uint8_t *ss2 = malloc(meta->ss_size);
    bool ok = false;

    if (pk && sk && ct && ss1 && ss2 &&
        pq_kem_keypair(alg, pk, sk) == PQ_SUCCESS &&
        pq_kem_encapsulate(alg, ct, ss1, pk) == PQ_SUCCESS &&
        pq_kem_decapsulate(alg, ss2, ct, sk) == PQ_SUCCESS &&
        CRYPTO_memcmp(ss1, ss2, meta->ss_size) == 0) {
        ok = true;
    }

    if (sk)  OPENSSL_cleanse(sk, meta->sk_size);
    if (ss1) OPENSSL_cleanse(ss1, meta->ss_size);
    if (ss2) OPENSSL_cleanse(ss2, meta->ss_size);
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    return ok;
}

#define DEFINE_MLKEM_PROVIDER(tag, ALG, NAME, OID, LEVEL, PK, SK, CT, SS)            \
    static const char *tag##_name(void) { return NAME; }                              \
                                                                                      \
    static const pq_algorithm_metadata_t tag##_meta = {                               \
        .name       = NAME,                                                           \
        .oid        = OID,                                                            \
        .tls_group  = NULL, /* pure KEM, not directly a TLS group */                  \
        .family     = PQ_ALG_FAMILY_LATTICE,                                          \
        .status     = PQ_ALG_STATUS_STANDARD,                                         \
        .nist_level = LEVEL,                                                          \
        .pk_size    = PK,                                                             \
        .sk_size    = SK,                                                             \
        .ct_size    = CT,                                                             \
        .ss_size    = SS,                                                             \
    };                                                                                \
                                                                                      \
    static const pq_algorithm_metadata_t *tag##_metadata(void) { return &tag##_meta; }\
                                                                                      \
    static int tag##_keygen(uint8_t *pk, uint8_t *sk)                                 \
    {                                                                                 \
        return pq_kem_keypair(ALG, pk, sk);                                           \
    }                                                                                 \
                                                                                      \
    static int tag##_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)         \
    {                                                                                 \
        return pq_kem_encapsulate(ALG, ct, ss, pk);                                   \
    }                                                                                 \
                                                                                      \
    static int tag##_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)   \
    {                                                                                 \
        return pq_kem_decapsulate(ALG, ss, ct, sk);                                   \
    }                                                                                 \
                                                                                      \
    static pthread_once_t tag##_once = PTHREAD_ONCE_INIT;                             \
    static bool tag##_available = false;                                              \
    static void tag##_probe(void) { tag##_available = mlkem_self_test(ALG, &tag##_meta); } \
    static bool tag##_is_available(void)                                              \
    {                                                                                 \
        pthread_once(&tag##_once, tag##_probe);                                       \
        return tag##_available;                                                       \
    }                                                                                 \
                                                                                      \
    static void tag##_cleanup(void) { /* nothing to do */ }                           \
                                                                                      \
    static const pq_kem_provider_t tag##_provider = {                                 \
        .name          = tag##_name,                                                  \
        .metadata      = tag##_metadata,                                              \
        .keygen        = tag##_keygen,                                                \
        .encapsulate   = tag##_encapsulate,                                           \
        .decapsulate   = tag##_decapsulate,                                           \
        .is_available  = tag##_is_available,                                          \
        .cleanup       = tag##_cleanup,                                               \
    }

/* ========================================================================
 * ML-KEM-512
 * ======================================================================== */

DEFINE_MLKEM_PROVIDER(mlkem512, PQ_KEM_MLKEM512, "ML-KEM-512", "2.16.840.1.101.3.4.4.1", 1,
                      PQ_KEM_MLKEM512_PUBLICKEY_BYTES, PQ_KEM_MLKEM512_SECRETKEY_BYTES,
                      PQ_KEM_MLKEM512_CIPHERTEXT_BYTES, PQ_KEM_MLKEM512_SHAREDSECRET_BYTES);

const pq_kem_provider_t *pq_kem_provider_mlkem512(void)
{
    return &mlkem512_provider;
}

/* ========================================================================
 * ML-KEM-768
 * ======================================================================== */

DEFINE_MLKEM_PROVIDER(mlkem768, PQ_KEM_MLKEM768, "ML-KEM-768", "2.16.840.1.101.3.4.4.2", 3,
                      PQ_KEM_MLKEM768_PUBLICKEY_BYTES, PQ_KEM_MLKEM768_SECRETKEY_BYTES,
                      PQ_KEM_MLKEM768_CIPHERTEXT_BYTES, PQ_KEM_MLKEM768_SHAREDSECRET_BYTES);

const pq_kem_provider_t *pq_kem_provider_mlkem768(void)
{
    return &mlkem768_provider;
}

/* ========================================================================
 * ML-KEM-1024
 * ======================================================================== */

DEFINE_MLKEM_PROVIDER(mlkem1024, PQ_KEM_MLKEM1024, "ML-KEM-1024", "2.16.840.1.101.3.4.4.3", 5,
                      PQ_KEM_MLKEM1024_PUBLICKEY_BYTES, PQ_KEM_MLKEM1024_SECRETKEY_BYTES,
                      PQ_KEM_MLKEM1024_CIPHERTEXT_BYTES, PQ_KEM_MLKEM1024_SHAREDSECRET_BYTES);

const pq_kem_provider_t *pq_kem_provider_mlkem1024(void)
{
    return &mlkem1024_provider;
}
