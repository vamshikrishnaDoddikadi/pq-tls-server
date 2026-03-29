/**
 * @file kem_mlkem.c
 * @brief ML-KEM Provider Implementations using liboqs
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Implements pq_kem_provider_t for ML-KEM-512, ML-KEM-768, ML-KEM-1024
 * by delegating to the existing pq_kem.h / liboqs functions.
 */

#include "kem_mlkem.h"
#include "pq_kem.h"
#include "pq_errors.h"

#include <string.h>
#include <stdbool.h>

/* ========================================================================
 * ML-KEM-512
 * ======================================================================== */

static const char *mlkem512_name(void) { return "ML-KEM-512"; }

static const pq_algorithm_metadata_t mlkem512_meta = {
    .name       = "ML-KEM-512",
    .oid        = "2.16.840.1.101.3.4.4.1",
    .tls_group  = NULL, /* pure KEM, not directly a TLS group */
    .family     = PQ_ALG_FAMILY_LATTICE,
    .status     = PQ_ALG_STATUS_STANDARD,
    .nist_level = 1,
    .pk_size    = PQ_KEM_MLKEM512_PUBLICKEY_BYTES,
    .sk_size    = PQ_KEM_MLKEM512_SECRETKEY_BYTES,
    .ct_size    = PQ_KEM_MLKEM512_CIPHERTEXT_BYTES,
    .ss_size    = PQ_KEM_MLKEM512_SHAREDSECRET_BYTES,
};

static const pq_algorithm_metadata_t *mlkem512_metadata(void) { return &mlkem512_meta; }

static int mlkem512_keygen(uint8_t *pk, uint8_t *sk)
{
    return pq_kem_keypair(PQ_KEM_MLKEM512, pk, sk);
}

static int mlkem512_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    return pq_kem_encapsulate(PQ_KEM_MLKEM512, ct, ss, pk);
}

static int mlkem512_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    return pq_kem_decapsulate(PQ_KEM_MLKEM512, ss, ct, sk);
}

static bool mlkem512_is_available(void)
{
    /* Attempt a keygen to verify liboqs has ML-KEM-512 compiled in */
    uint8_t pk[PQ_KEM_MLKEM512_PUBLICKEY_BYTES];
    uint8_t sk[PQ_KEM_MLKEM512_SECRETKEY_BYTES];
    return pq_kem_keypair(PQ_KEM_MLKEM512, pk, sk) == PQ_SUCCESS;
}

static void mlkem512_cleanup(void) { /* nothing to do */ }

static const pq_kem_provider_t mlkem512_provider = {
    .name          = mlkem512_name,
    .metadata      = mlkem512_metadata,
    .keygen        = mlkem512_keygen,
    .encapsulate   = mlkem512_encapsulate,
    .decapsulate   = mlkem512_decapsulate,
    .is_available  = mlkem512_is_available,
    .cleanup       = mlkem512_cleanup,
};

const pq_kem_provider_t *pq_kem_provider_mlkem512(void)
{
    return &mlkem512_provider;
}

/* ========================================================================
 * ML-KEM-768
 * ======================================================================== */

static const char *mlkem768_name(void) { return "ML-KEM-768"; }

static const pq_algorithm_metadata_t mlkem768_meta = {
    .name       = "ML-KEM-768",
    .oid        = "2.16.840.1.101.3.4.4.2",
    .tls_group  = NULL,
    .family     = PQ_ALG_FAMILY_LATTICE,
    .status     = PQ_ALG_STATUS_STANDARD,
    .nist_level = 3,
    .pk_size    = PQ_KEM_MLKEM768_PUBLICKEY_BYTES,
    .sk_size    = PQ_KEM_MLKEM768_SECRETKEY_BYTES,
    .ct_size    = PQ_KEM_MLKEM768_CIPHERTEXT_BYTES,
    .ss_size    = PQ_KEM_MLKEM768_SHAREDSECRET_BYTES,
};

static const pq_algorithm_metadata_t *mlkem768_metadata(void) { return &mlkem768_meta; }

static int mlkem768_keygen(uint8_t *pk, uint8_t *sk)
{
    return pq_kem_keypair(PQ_KEM_MLKEM768, pk, sk);
}

static int mlkem768_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    return pq_kem_encapsulate(PQ_KEM_MLKEM768, ct, ss, pk);
}

static int mlkem768_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    return pq_kem_decapsulate(PQ_KEM_MLKEM768, ss, ct, sk);
}

static bool mlkem768_is_available(void)
{
    uint8_t pk[PQ_KEM_MLKEM768_PUBLICKEY_BYTES];
    uint8_t sk[PQ_KEM_MLKEM768_SECRETKEY_BYTES];
    return pq_kem_keypair(PQ_KEM_MLKEM768, pk, sk) == PQ_SUCCESS;
}

static void mlkem768_cleanup(void) { }

static const pq_kem_provider_t mlkem768_provider = {
    .name          = mlkem768_name,
    .metadata      = mlkem768_metadata,
    .keygen        = mlkem768_keygen,
    .encapsulate   = mlkem768_encapsulate,
    .decapsulate   = mlkem768_decapsulate,
    .is_available  = mlkem768_is_available,
    .cleanup       = mlkem768_cleanup,
};

const pq_kem_provider_t *pq_kem_provider_mlkem768(void)
{
    return &mlkem768_provider;
}

/* ========================================================================
 * ML-KEM-1024
 * ======================================================================== */

static const char *mlkem1024_name(void) { return "ML-KEM-1024"; }

static const pq_algorithm_metadata_t mlkem1024_meta = {
    .name       = "ML-KEM-1024",
    .oid        = "2.16.840.1.101.3.4.4.3",
    .tls_group  = NULL,
    .family     = PQ_ALG_FAMILY_LATTICE,
    .status     = PQ_ALG_STATUS_STANDARD,
    .nist_level = 5,
    .pk_size    = PQ_KEM_MLKEM1024_PUBLICKEY_BYTES,
    .sk_size    = PQ_KEM_MLKEM1024_SECRETKEY_BYTES,
    .ct_size    = PQ_KEM_MLKEM1024_CIPHERTEXT_BYTES,
    .ss_size    = PQ_KEM_MLKEM1024_SHAREDSECRET_BYTES,
};

static const pq_algorithm_metadata_t *mlkem1024_metadata(void) { return &mlkem1024_meta; }

static int mlkem1024_keygen(uint8_t *pk, uint8_t *sk)
{
    return pq_kem_keypair(PQ_KEM_MLKEM1024, pk, sk);
}

static int mlkem1024_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    return pq_kem_encapsulate(PQ_KEM_MLKEM1024, ct, ss, pk);
}

static int mlkem1024_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    return pq_kem_decapsulate(PQ_KEM_MLKEM1024, ss, ct, sk);
}

static bool mlkem1024_is_available(void)
{
    uint8_t pk[PQ_KEM_MLKEM1024_PUBLICKEY_BYTES];
    uint8_t sk[PQ_KEM_MLKEM1024_SECRETKEY_BYTES];
    return pq_kem_keypair(PQ_KEM_MLKEM1024, pk, sk) == PQ_SUCCESS;
}

static void mlkem1024_cleanup(void) { }

static const pq_kem_provider_t mlkem1024_provider = {
    .name          = mlkem1024_name,
    .metadata      = mlkem1024_metadata,
    .keygen        = mlkem1024_keygen,
    .encapsulate   = mlkem1024_encapsulate,
    .decapsulate   = mlkem1024_decapsulate,
    .is_available  = mlkem1024_is_available,
    .cleanup       = mlkem1024_cleanup,
};

const pq_kem_provider_t *pq_kem_provider_mlkem1024(void)
{
    return &mlkem1024_provider;
}
