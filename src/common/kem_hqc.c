/**
 * @file kem_hqc.c
 * @brief HQC KEM Provider using liboqs
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Implements pq_kem_provider_t for the three HQC security levels.
 * Uses liboqs OQS_KEM API directly (same library as ML-KEM).
 *
 * liboqs naming / sizing (why nothing is hard-coded here):
 *   - liboqs <= 0.15 exposes "HQC-128" / "HQC-192" / "HQC-256"
 *     (OQS_KEM_alg_hqc_128 ...); liboqs >= 0.16 exposes the renamed
 *     "HQC-1" / "HQC-3" / "HQC-5" (OQS_KEM_alg_hqc_1 ...).  The liboqs name
 *     is selected at compile time from whichever macro the headers define.
 *   - Key, ciphertext and shared-secret sizes changed between HQC versions
 *     (e.g. the shared secret went from 64 to 32 bytes).  All sizes are
 *     therefore read at runtime from OQS_KEM_new()->length_* (once, under
 *     pthread_once) and published through metadata(), so buffers allocated
 *     from the metadata always match what liboqs writes.
 *   - HQC is often not compiled into liboqs (e.g. the vendored minimal
 *     build).  Then OQS_KEM_new() returns NULL, is_available() returns
 *     false, all sizes in metadata() are 0 and every operation returns
 *     PQ_ERR_ALGORITHM_NOT_AVAILABLE without touching caller buffers.
 *
 * The registry-visible provider names stay "HQC-128" / "HQC-192" /
 * "HQC-256" for API/config stability, whatever the liboqs name is.
 *
 * Can be compiled as either:
 *   - Built-in: linked directly into the server
 *   - Plugin: compiled as a .so and loaded at runtime via the registry
 *     (only liboqs + libc/pthread are required, hence OQS_MEM_cleanse)
 */

#include "kem_hqc.h"
#include "pq_errors.h"

#include <oqs/oqs.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>

/* ========================================================================
 * liboqs algorithm name resolution
 * ======================================================================== */

#if defined(OQS_KEM_alg_hqc_1)
#  define HQC_L1_OQS_NAME OQS_KEM_alg_hqc_1
#elif defined(OQS_KEM_alg_hqc_128)
#  define HQC_L1_OQS_NAME OQS_KEM_alg_hqc_128
#else
#  define HQC_L1_OQS_NAME NULL
#endif

#if defined(OQS_KEM_alg_hqc_3)
#  define HQC_L3_OQS_NAME OQS_KEM_alg_hqc_3
#elif defined(OQS_KEM_alg_hqc_192)
#  define HQC_L3_OQS_NAME OQS_KEM_alg_hqc_192
#else
#  define HQC_L3_OQS_NAME NULL
#endif

#if defined(OQS_KEM_alg_hqc_5)
#  define HQC_L5_OQS_NAME OQS_KEM_alg_hqc_5
#elif defined(OQS_KEM_alg_hqc_256)
#  define HQC_L5_OQS_NAME OQS_KEM_alg_hqc_256
#else
#  define HQC_L5_OQS_NAME NULL
#endif

/* ========================================================================
 * Per-level state (sizes filled once from liboqs)
 * ======================================================================== */

typedef struct {
    const char *oqs_name;          /* liboqs algorithm name, or NULL if unknown */
    bool available;                /* OQS_KEM_new() succeeded */
    pq_algorithm_metadata_t meta;  /* sizes are 0 until/unless available */
} hqc_state_t;

#define HQC_META(NAME, LEVEL)                   \
    {                                           \
        .name       = NAME,                     \
        .oid        = NULL, /* not yet assigned */ \
        .tls_group  = NULL, /* no TLS group */  \
        .family     = PQ_ALG_FAMILY_CODE,       \
        .status     = PQ_ALG_STATUS_CANDIDATE,  \
        .nist_level = LEVEL,                    \
        .pk_size = 0, .sk_size = 0, .ct_size = 0, .ss_size = 0, \
    }

static hqc_state_t hqc128_state = { HQC_L1_OQS_NAME, false, HQC_META("HQC-128", 1) };
static hqc_state_t hqc192_state = { HQC_L3_OQS_NAME, false, HQC_META("HQC-192", 3) };
static hqc_state_t hqc256_state = { HQC_L5_OQS_NAME, false, HQC_META("HQC-256", 5) };

static pthread_once_t hqc128_once = PTHREAD_ONCE_INIT;
static pthread_once_t hqc192_once = PTHREAD_ONCE_INIT;
static pthread_once_t hqc256_once = PTHREAD_ONCE_INIT;

static void hqc_probe(hqc_state_t *st)
{
    if (!st->oqs_name) return;
    OQS_KEM *kem = OQS_KEM_new(st->oqs_name);
    if (!kem) return;   /* HQC not enabled in this liboqs build */

    st->meta.pk_size = kem->length_public_key;
    st->meta.sk_size = kem->length_secret_key;
    st->meta.ct_size = kem->length_ciphertext;
    st->meta.ss_size = kem->length_shared_secret;
    st->available = st->meta.pk_size && st->meta.sk_size &&
                    st->meta.ct_size && st->meta.ss_size;
    OQS_KEM_free(kem);
}

static void hqc128_probe(void) { hqc_probe(&hqc128_state); }
static void hqc192_probe(void) { hqc_probe(&hqc192_state); }
static void hqc256_probe(void) { hqc_probe(&hqc256_state); }

/* ========================================================================
 * Helper: generic liboqs KEM operations (after the state is initialised)
 * ======================================================================== */

/* OQS_KEM_new() plus a defensive check that sizes still match the metadata */
static OQS_KEM *hqc_new(const hqc_state_t *st)
{
    if (!st->available) return NULL;
    OQS_KEM *kem = OQS_KEM_new(st->oqs_name);
    if (!kem) return NULL;
    if (kem->length_public_key != st->meta.pk_size ||
        kem->length_secret_key != st->meta.sk_size ||
        kem->length_ciphertext != st->meta.ct_size ||
        kem->length_shared_secret != st->meta.ss_size) {
        OQS_KEM_free(kem);
        return NULL;
    }
    return kem;
}

static int hqc_keygen(const hqc_state_t *st, uint8_t *pk, uint8_t *sk)
{
    if (!pk || !sk) return PQ_ERR_NULL_POINTER;
    OQS_KEM *kem = hqc_new(st);
    if (!kem) return PQ_ERR_ALGORITHM_NOT_AVAILABLE;

    OQS_STATUS status = OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_free(kem);
    if (status != OQS_SUCCESS) {
        OQS_MEM_cleanse(sk, st->meta.sk_size);
        return PQ_ERR_KEY_GENERATION_FAILED;
    }
    return PQ_SUCCESS;
}

static int hqc_encaps(const hqc_state_t *st, const uint8_t *pk, uint8_t *ct, uint8_t *ss)
{
    if (!pk || !ct || !ss) return PQ_ERR_NULL_POINTER;
    OQS_KEM *kem = hqc_new(st);
    if (!kem) return PQ_ERR_ALGORITHM_NOT_AVAILABLE;

    OQS_STATUS status = OQS_KEM_encaps(kem, ct, ss, pk);
    OQS_KEM_free(kem);
    if (status != OQS_SUCCESS) {
        OQS_MEM_cleanse(ss, st->meta.ss_size);
        return PQ_ERR_ENCRYPTION_FAILED;
    }
    return PQ_SUCCESS;
}

static int hqc_decaps(const hqc_state_t *st, const uint8_t *sk, const uint8_t *ct, uint8_t *ss)
{
    if (!sk || !ct || !ss) return PQ_ERR_NULL_POINTER;
    OQS_KEM *kem = hqc_new(st);
    if (!kem) return PQ_ERR_ALGORITHM_NOT_AVAILABLE;

    OQS_STATUS status = OQS_KEM_decaps(kem, ss, ct, sk);
    OQS_KEM_free(kem);
    if (status != OQS_SUCCESS) {
        OQS_MEM_cleanse(ss, st->meta.ss_size);
        return PQ_ERR_DECRYPTION_FAILED;
    }
    return PQ_SUCCESS;
}

/* ========================================================================
 * Provider vtables
 * ======================================================================== */

#define DEFINE_HQC_PROVIDER(tag)                                                      \
    static const hqc_state_t *tag##_get(void)                                         \
    {                                                                                 \
        pthread_once(&tag##_once, tag##_probe);                                       \
        return &tag##_state;                                                          \
    }                                                                                 \
    static const char *tag##_name(void) { return tag##_state.meta.name; }             \
    static const pq_algorithm_metadata_t *tag##_metadata(void) { return &tag##_get()->meta; } \
    static int tag##_keygen(uint8_t *pk, uint8_t *sk)                                 \
    { return hqc_keygen(tag##_get(), pk, sk); }                                       \
    static int tag##_encapsulate(const uint8_t *pk, uint8_t *ct, uint8_t *ss)         \
    { return hqc_encaps(tag##_get(), pk, ct, ss); }                                   \
    static int tag##_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss)   \
    { return hqc_decaps(tag##_get(), sk, ct, ss); }                                   \
    static bool tag##_is_available(void) { return tag##_get()->available; }           \
    static void tag##_cleanup(void) { }                                               \
    static const pq_kem_provider_t tag##_provider = {                                 \
        .name = tag##_name, .metadata = tag##_metadata,                               \
        .keygen = tag##_keygen, .encapsulate = tag##_encapsulate,                     \
        .decapsulate = tag##_decapsulate, .is_available = tag##_is_available,         \
        .cleanup = tag##_cleanup,                                                     \
    }

/* HQC-128 (NIST Level 1) - liboqs "HQC-128" or "HQC-1" */
DEFINE_HQC_PROVIDER(hqc128);
const pq_kem_provider_t *pq_kem_provider_hqc128(void) { return &hqc128_provider; }

/* HQC-192 (NIST Level 3) - liboqs "HQC-192" or "HQC-3" */
DEFINE_HQC_PROVIDER(hqc192);
const pq_kem_provider_t *pq_kem_provider_hqc192(void) { return &hqc192_provider; }

/* HQC-256 (NIST Level 5) - liboqs "HQC-256" or "HQC-5" */
DEFINE_HQC_PROVIDER(hqc256);
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
    .plugin_version = "1.1.0",
    .kem_providers  = hqc_kem_list,
    .kem_count      = 3,
    .sig_providers  = NULL,
    .sig_count      = 0,
};

const pq_plugin_descriptor_t *pq_plugin_init(void)
{
    return &hqc_plugin_desc;
}
