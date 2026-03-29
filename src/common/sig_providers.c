/**
 * @file sig_providers.c
 * @brief Signature Provider Implementations using liboqs + OpenSSL
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 */

#include "sig_providers.h"
#include "pq_sig.h"
#include "pq_errors.h"

#include <string.h>
#include <stdbool.h>

/* ========================================================================
 * ML-DSA-44 (NIST Level 2)
 * ======================================================================== */

static const char *mldsa44_name(void) { return "ML-DSA-44"; }

static const pq_algorithm_metadata_t mldsa44_meta = {
    .name       = "ML-DSA-44",
    .oid        = "2.16.840.1.101.3.4.3.17",
    .tls_group  = NULL,
    .family     = PQ_ALG_FAMILY_LATTICE,
    .status     = PQ_ALG_STATUS_STANDARD,
    .nist_level = 2,
    .pk_size    = PQ_SIG_MLDSA44_PUBLICKEY_BYTES,
    .sk_size    = PQ_SIG_MLDSA44_SECRETKEY_BYTES,
    .ct_size    = PQ_SIG_MLDSA44_SIGNATURE_BYTES,
    .ss_size    = 0,
};

static const pq_algorithm_metadata_t *mldsa44_metadata(void) { return &mldsa44_meta; }

static int mldsa44_keygen(uint8_t *pk, uint8_t *sk)
{
    return pq_sig_keypair(PQ_SIG_MLDSA44, pk, sk);
}

static int mldsa44_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                         uint8_t *sig, size_t *sig_len)
{
    return pq_sig_sign(PQ_SIG_MLDSA44, sig, sig_len, msg, msg_len, sk);
}

static int mldsa44_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len)
{
    return pq_sig_verify(PQ_SIG_MLDSA44, msg, msg_len, sig, sig_len, pk);
}

static bool mldsa44_is_available(void)
{
    uint8_t pk[PQ_SIG_MLDSA44_PUBLICKEY_BYTES];
    uint8_t sk[PQ_SIG_MLDSA44_SECRETKEY_BYTES];
    return pq_sig_keypair(PQ_SIG_MLDSA44, pk, sk) == PQ_SUCCESS;
}

static void mldsa44_cleanup(void) { }

static const pq_sig_provider_t mldsa44_provider = {
    .name          = mldsa44_name,
    .metadata      = mldsa44_metadata,
    .keygen        = mldsa44_keygen,
    .sign          = mldsa44_sign,
    .verify        = mldsa44_verify,
    .is_available  = mldsa44_is_available,
    .cleanup       = mldsa44_cleanup,
};

const pq_sig_provider_t *pq_sig_provider_mldsa44(void) { return &mldsa44_provider; }

/* ========================================================================
 * ML-DSA-65 (NIST Level 3)
 * ======================================================================== */

static const char *mldsa65_name(void) { return "ML-DSA-65"; }

static const pq_algorithm_metadata_t mldsa65_meta = {
    .name       = "ML-DSA-65",
    .oid        = "2.16.840.1.101.3.4.3.18",
    .tls_group  = NULL,
    .family     = PQ_ALG_FAMILY_LATTICE,
    .status     = PQ_ALG_STATUS_STANDARD,
    .nist_level = 3,
    .pk_size    = PQ_SIG_MLDSA65_PUBLICKEY_BYTES,
    .sk_size    = PQ_SIG_MLDSA65_SECRETKEY_BYTES,
    .ct_size    = PQ_SIG_MLDSA65_SIGNATURE_BYTES,
    .ss_size    = 0,
};

static const pq_algorithm_metadata_t *mldsa65_metadata(void) { return &mldsa65_meta; }

static int mldsa65_keygen(uint8_t *pk, uint8_t *sk)
{
    return pq_sig_keypair(PQ_SIG_MLDSA65, pk, sk);
}

static int mldsa65_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                         uint8_t *sig, size_t *sig_len)
{
    return pq_sig_sign(PQ_SIG_MLDSA65, sig, sig_len, msg, msg_len, sk);
}

static int mldsa65_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len)
{
    return pq_sig_verify(PQ_SIG_MLDSA65, msg, msg_len, sig, sig_len, pk);
}

static bool mldsa65_is_available(void)
{
    uint8_t pk[PQ_SIG_MLDSA65_PUBLICKEY_BYTES];
    uint8_t sk[PQ_SIG_MLDSA65_SECRETKEY_BYTES];
    return pq_sig_keypair(PQ_SIG_MLDSA65, pk, sk) == PQ_SUCCESS;
}

static void mldsa65_cleanup(void) { }

static const pq_sig_provider_t mldsa65_provider = {
    .name          = mldsa65_name,
    .metadata      = mldsa65_metadata,
    .keygen        = mldsa65_keygen,
    .sign          = mldsa65_sign,
    .verify        = mldsa65_verify,
    .is_available  = mldsa65_is_available,
    .cleanup       = mldsa65_cleanup,
};

const pq_sig_provider_t *pq_sig_provider_mldsa65(void) { return &mldsa65_provider; }

/* ========================================================================
 * ML-DSA-87 (NIST Level 5)
 * ======================================================================== */

static const char *mldsa87_name(void) { return "ML-DSA-87"; }

static const pq_algorithm_metadata_t mldsa87_meta = {
    .name       = "ML-DSA-87",
    .oid        = "2.16.840.1.101.3.4.3.19",
    .tls_group  = NULL,
    .family     = PQ_ALG_FAMILY_LATTICE,
    .status     = PQ_ALG_STATUS_STANDARD,
    .nist_level = 5,
    .pk_size    = PQ_SIG_MLDSA87_PUBLICKEY_BYTES,
    .sk_size    = PQ_SIG_MLDSA87_SECRETKEY_BYTES,
    .ct_size    = PQ_SIG_MLDSA87_SIGNATURE_BYTES,
    .ss_size    = 0,
};

static const pq_algorithm_metadata_t *mldsa87_metadata(void) { return &mldsa87_meta; }

static int mldsa87_keygen(uint8_t *pk, uint8_t *sk)
{
    return pq_sig_keypair(PQ_SIG_MLDSA87, pk, sk);
}

static int mldsa87_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                         uint8_t *sig, size_t *sig_len)
{
    return pq_sig_sign(PQ_SIG_MLDSA87, sig, sig_len, msg, msg_len, sk);
}

static int mldsa87_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len)
{
    return pq_sig_verify(PQ_SIG_MLDSA87, msg, msg_len, sig, sig_len, pk);
}

static bool mldsa87_is_available(void)
{
    uint8_t pk[PQ_SIG_MLDSA87_PUBLICKEY_BYTES];
    uint8_t sk[PQ_SIG_MLDSA87_SECRETKEY_BYTES];
    return pq_sig_keypair(PQ_SIG_MLDSA87, pk, sk) == PQ_SUCCESS;
}

static void mldsa87_cleanup(void) { }

static const pq_sig_provider_t mldsa87_provider = {
    .name          = mldsa87_name,
    .metadata      = mldsa87_metadata,
    .keygen        = mldsa87_keygen,
    .sign          = mldsa87_sign,
    .verify        = mldsa87_verify,
    .is_available  = mldsa87_is_available,
    .cleanup       = mldsa87_cleanup,
};

const pq_sig_provider_t *pq_sig_provider_mldsa87(void) { return &mldsa87_provider; }

/* ========================================================================
 * Ed25519 (Classical)
 * ======================================================================== */

static const char *ed25519_name(void) { return "Ed25519"; }

static const pq_algorithm_metadata_t ed25519_meta = {
    .name       = "Ed25519",
    .oid        = "1.3.101.112",
    .tls_group  = NULL,
    .family     = PQ_ALG_FAMILY_CLASSICAL,
    .status     = PQ_ALG_STATUS_STANDARD,
    .nist_level = 1,
    .pk_size    = PQ_SIG_ED25519_PUBLICKEY_BYTES,
    .sk_size    = PQ_SIG_ED25519_SECRETKEY_BYTES,
    .ct_size    = PQ_SIG_ED25519_SIGNATURE_BYTES,
    .ss_size    = 0,
};

static const pq_algorithm_metadata_t *ed25519_metadata(void) { return &ed25519_meta; }

static int ed25519_keygen(uint8_t *pk, uint8_t *sk)
{
    return pq_sig_keypair(PQ_SIG_ED25519, pk, sk);
}

static int ed25519_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                         uint8_t *sig, size_t *sig_len)
{
    return pq_sig_sign(PQ_SIG_ED25519, sig, sig_len, msg, msg_len, sk);
}

static int ed25519_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len)
{
    return pq_sig_verify(PQ_SIG_ED25519, msg, msg_len, sig, sig_len, pk);
}

static bool ed25519_is_available(void)
{
    uint8_t pk[PQ_SIG_ED25519_PUBLICKEY_BYTES];
    uint8_t sk[PQ_SIG_ED25519_SECRETKEY_BYTES];
    return pq_sig_keypair(PQ_SIG_ED25519, pk, sk) == PQ_SUCCESS;
}

static void ed25519_cleanup(void) { }

static const pq_sig_provider_t ed25519_provider = {
    .name          = ed25519_name,
    .metadata      = ed25519_metadata,
    .keygen        = ed25519_keygen,
    .sign          = ed25519_sign,
    .verify        = ed25519_verify,
    .is_available  = ed25519_is_available,
    .cleanup       = ed25519_cleanup,
};

const pq_sig_provider_t *pq_sig_provider_ed25519(void) { return &ed25519_provider; }
