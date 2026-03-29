/**
 * @file kem_hqc.c
 * @brief HQC KEM Provider using liboqs
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Implements pq_kem_provider_t for HQC-128, HQC-192, HQC-256.
 * Uses liboqs OQS_KEM API directly (same library as ML-KEM).
 *
 * Note: HQC key and ciphertext sizes are significantly larger than
 * ML-KEM, which is an important benchmark data point.
 */

#include "kem_hqc.h"
#include "pq_errors.h"

#include <string.h>
#include <stdbool.h>

/* We call liboqs directly for HQC since pq_kem.h only wraps ML-KEM */
#ifdef __has_include
#if __has_include(<oqs/oqs.h>)
#include <oqs/oqs.h>
#define HQC_HAVE_OQS 1
#endif
#endif

#ifndef HQC_HAVE_OQS
/* Fallback: try to include anyway (build system ensures availability) */
#include <oqs/oqs.h>
#define HQC_HAVE_OQS 1
#endif

/* ========================================================================
 * HQC size constants (from liboqs / NIST submission)
 * ======================================================================== */

/* HQC-128 (NIST Level 1) */
#define HQC128_PK_SIZE    2249
#define HQC128_SK_SIZE    2289
#define HQC128_CT_SIZE    4481
#define HQC128_SS_SIZE    64

/* HQC-192 (NIST Level 3) */
#define HQC192_PK_SIZE    4522
#define HQC192_SK_SIZE    4562
#define HQC192_CT_SIZE    9026
#define HQC192_SS_SIZE    64

/* HQC-256 (NIST Level 5) */
#define HQC256_PK_SIZE    7245
#define HQC256_SK_SIZE    7285
#define HQC256_CT_SIZE    14469
#define HQC256_SS_SIZE    64

/* ========================================================================
 * Helper: generic liboqs KEM operations
 * ======================================================================== */

static int oqs_kem_keygen(const char *alg_name, uint8_t *pk, uint8_t *sk)
{
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) return PQ_ERR_ALGORITHM_NOT_AVAILABLE;

    OQS_STATUS status = OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_free(kem);
    return (status == OQS_SUCCESS) ? PQ_SUCCESS : PQ_ERR_KEY_GENERATION_FAILED;
}

static int oqs_kem_encaps(const char *alg_name, const uint8_t *pk,
                           uint8_t *ct, uint8_t *ss)
{
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) return PQ_ERR_ALGORITHM_NOT_AVAILABLE;

    OQS_STATUS status = OQS_KEM_encaps(kem, ct, ss, pk);
    OQS_KEM_free(kem);
    return (status == OQS_SUCCESS) ? PQ_SUCCESS : PQ_ERR_ENCRYPTION_FAILED;
}

static int oqs_kem_decaps(const char *alg_name, const uint8_t *sk,
                           const uint8_t *ct, uint8_t *ss)
{
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) return PQ_ERR_ALGORITHM_NOT_AVAILABLE;

    OQS_STATUS status = OQS_KEM_decaps(kem, ss, ct, sk);
    OQS_KEM_free(kem);
    return (status == OQS_SUCCESS) ? PQ_SUCCESS : PQ_ERR_DECRYPTION_FAILED;
}

static bool oqs_kem_check(const char *alg_name)
{
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) return false;
    OQS_KEM_free(kem);
    return true;
}

/* ========================================================================
 * HQC-128
 * ======================================================================== */

static const char *hqc128_name(void) { return "HQC-128"; }

static const pq_algorithm_metadata_t hqc128_meta = {
    .name       = "HQC-128",
    .oid        = NULL,  /* not yet assigned by NIST */
    .tls_group  = NULL,  /* not yet in oqs-provider group list */
    .family     = PQ_ALG_FAMILY_CODE,
    .status     = PQ_ALG_STATUS_CANDIDATE,
    .nist_level = 1,
    .pk_size    = HQC128_PK_SIZE,
    .sk_size    = HQC128_SK_SIZE,
    .ct_size    = HQC128_CT_SIZE,
    .ss_size    = HQC128_SS_SIZE,
};

static const pq_algorithm_metadata_t *hqc128_metadata(void) { return &hqc128_meta; }
static int hqc128_keygen(uint8_t *pk, uint8_t *sk) { return oqs_kem_keygen("HQC-128", pk, sk); }
static int hqc128_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss) { return oqs_kem_encaps("HQC-128", pk, ct, ss); }
static int hqc128_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss) { return oqs_kem_decaps("HQC-128", sk, ct, ss); }
static bool hqc128_is_available(void) { return oqs_kem_check("HQC-128"); }
static void hqc128_cleanup(void) { }

static const pq_kem_provider_t hqc128_provider = {
    .name = hqc128_name, .metadata = hqc128_metadata,
    .keygen = hqc128_keygen, .encapsulate = hqc128_encapsulate,
    .decapsulate = hqc128_decapsulate, .is_available = hqc128_is_available,
    .cleanup = hqc128_cleanup,
};

const pq_kem_provider_t *pq_kem_provider_hqc128(void) { return &hqc128_provider; }

/* ========================================================================
 * HQC-192
 * ======================================================================== */

static const char *hqc192_name(void) { return "HQC-192"; }

static const pq_algorithm_metadata_t hqc192_meta = {
    .name = "HQC-192", .oid = NULL, .tls_group = NULL,
    .family = PQ_ALG_FAMILY_CODE, .status = PQ_ALG_STATUS_CANDIDATE,
    .nist_level = 3,
    .pk_size = HQC192_PK_SIZE, .sk_size = HQC192_SK_SIZE,
    .ct_size = HQC192_CT_SIZE, .ss_size = HQC192_SS_SIZE,
};

static const pq_algorithm_metadata_t *hqc192_metadata(void) { return &hqc192_meta; }
static int hqc192_keygen(uint8_t *pk, uint8_t *sk) { return oqs_kem_keygen("HQC-192", pk, sk); }
static int hqc192_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss) { return oqs_kem_encaps("HQC-192", pk, ct, ss); }
static int hqc192_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss) { return oqs_kem_decaps("HQC-192", sk, ct, ss); }
static bool hqc192_is_available(void) { return oqs_kem_check("HQC-192"); }
static void hqc192_cleanup(void) { }

static const pq_kem_provider_t hqc192_provider = {
    .name = hqc192_name, .metadata = hqc192_metadata,
    .keygen = hqc192_keygen, .encapsulate = hqc192_encapsulate,
    .decapsulate = hqc192_decapsulate, .is_available = hqc192_is_available,
    .cleanup = hqc192_cleanup,
};

const pq_kem_provider_t *pq_kem_provider_hqc192(void) { return &hqc192_provider; }

/* ========================================================================
 * HQC-256
 * ======================================================================== */

static const char *hqc256_name(void) { return "HQC-256"; }

static const pq_algorithm_metadata_t hqc256_meta = {
    .name = "HQC-256", .oid = NULL, .tls_group = NULL,
    .family = PQ_ALG_FAMILY_CODE, .status = PQ_ALG_STATUS_CANDIDATE,
    .nist_level = 5,
    .pk_size = HQC256_PK_SIZE, .sk_size = HQC256_SK_SIZE,
    .ct_size = HQC256_CT_SIZE, .ss_size = HQC256_SS_SIZE,
};

static const pq_algorithm_metadata_t *hqc256_metadata(void) { return &hqc256_meta; }
static int hqc256_keygen(uint8_t *pk, uint8_t *sk) { return oqs_kem_keygen("HQC-256", pk, sk); }
static int hqc256_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss) { return oqs_kem_encaps("HQC-256", pk, ct, ss); }
static int hqc256_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss) { return oqs_kem_decaps("HQC-256", sk, ct, ss); }
static bool hqc256_is_available(void) { return oqs_kem_check("HQC-256"); }
static void hqc256_cleanup(void) { }

static const pq_kem_provider_t hqc256_provider = {
    .name = hqc256_name, .metadata = hqc256_metadata,
    .keygen = hqc256_keygen, .encapsulate = hqc256_encapsulate,
    .decapsulate = hqc256_decapsulate, .is_available = hqc256_is_available,
    .cleanup = hqc256_cleanup,
};

const pq_kem_provider_t *pq_kem_provider_hqc256(void) { return &hqc256_provider; }

/* ========================================================================
 * Plugin Entry Point (for dynamic loading)
 *
 * When compiled as a shared library, this function is called by the
 * registry's plugin loader.
 * ======================================================================== */

static const pq_kem_provider_t *hqc_kem_list[] = {
    &hqc128_provider,
    &hqc192_provider,
    &hqc256_provider,
    NULL,
};

static const pq_plugin_descriptor_t hqc_plugin_desc = {
    .api_version    = PQ_PLUGIN_API_VERSION,
    .plugin_name    = "hqc-provider",
    .plugin_version = "1.0.0",
    .kem_providers  = hqc_kem_list,
    .kem_count      = 3,
    .sig_providers  = NULL,
    .sig_count      = 0,
};

const pq_plugin_descriptor_t *pq_plugin_init(void)
{
    return &hqc_plugin_desc;
}
