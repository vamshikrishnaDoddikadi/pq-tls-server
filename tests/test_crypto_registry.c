/**
 * @file test_crypto_registry.c
 * @brief Unit tests for the Crypto-Agility Registry and Provider Interface
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 */

#include "../src/common/crypto_registry.h"
#include "../src/common/kem_mlkem.h"
#include "../src/common/kem_classical.h"
#include "../src/common/kem_hqc.h"
#include "../src/common/sig_providers.h"
#include "../src/common/hybrid_combiner.h"
#include "../src/common/pq_errors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %-50s", #name "..."); test_##name(); printf("PASS\n"); } while(0)

/* ========================================================================
 * Provider Interface Tests
 * ======================================================================== */

TEST(mlkem_provider_metadata)
{
    const pq_kem_provider_t *p = pq_kem_provider_mlkem768();
    assert(p != NULL);
    assert(strcmp(p->name(), "ML-KEM-768") == 0);

    const pq_algorithm_metadata_t *m = p->metadata();
    assert(m != NULL);
    assert(m->nist_level == 3);
    assert(m->family == PQ_ALG_FAMILY_LATTICE);
    assert(m->status == PQ_ALG_STATUS_STANDARD);
    assert(m->pk_size == 1184);
    assert(m->sk_size == 2400);
    assert(m->ct_size == 1088);
    assert(m->ss_size == 32);
}

TEST(mlkem512_roundtrip)
{
    const pq_kem_provider_t *p = pq_kem_provider_mlkem512();
    if (!p->is_available()) { printf("SKIP (not available) "); return; }

    const pq_algorithm_metadata_t *m = p->metadata();
    uint8_t pk[800], sk[1632], ct[768], ss1[32], ss2[32];

    assert(p->keygen(pk, sk) == PQ_SUCCESS);
    assert(p->encapsulate(pk, ct, ss1) == PQ_SUCCESS);
    assert(p->decapsulate(sk, ct, ss2) == PQ_SUCCESS);
    assert(memcmp(ss1, ss2, m->ss_size) == 0);
}

TEST(mlkem768_roundtrip)
{
    const pq_kem_provider_t *p = pq_kem_provider_mlkem768();
    if (!p->is_available()) { printf("SKIP (not available) "); return; }

    uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
    assert(p->keygen(pk, sk) == PQ_SUCCESS);
    assert(p->encapsulate(pk, ct, ss1) == PQ_SUCCESS);
    assert(p->decapsulate(sk, ct, ss2) == PQ_SUCCESS);
    assert(memcmp(ss1, ss2, 32) == 0);
}

TEST(mlkem1024_roundtrip)
{
    const pq_kem_provider_t *p = pq_kem_provider_mlkem1024();
    if (!p->is_available()) { printf("SKIP (not available) "); return; }

    uint8_t pk[1568], sk[3168], ct[1568], ss1[32], ss2[32];
    assert(p->keygen(pk, sk) == PQ_SUCCESS);
    assert(p->encapsulate(pk, ct, ss1) == PQ_SUCCESS);
    assert(p->decapsulate(sk, ct, ss2) == PQ_SUCCESS);
    assert(memcmp(ss1, ss2, 32) == 0);
}

TEST(x25519_roundtrip)
{
    const pq_kem_provider_t *p = pq_kem_provider_x25519();
    if (!p->is_available()) { printf("SKIP (not available) "); return; }

    assert(strcmp(p->name(), "X25519") == 0);
    const pq_algorithm_metadata_t *m = p->metadata();
    assert(m->family == PQ_ALG_FAMILY_CLASSICAL);

    uint8_t pk[32], sk[32], ct[32], ss1[32], ss2[32];
    assert(p->keygen(pk, sk) == PQ_SUCCESS);
    assert(p->encapsulate(pk, ct, ss1) == PQ_SUCCESS);
    assert(p->decapsulate(sk, ct, ss2) == PQ_SUCCESS);
    assert(memcmp(ss1, ss2, 32) == 0);
}

TEST(hqc128_metadata)
{
    const pq_kem_provider_t *p = pq_kem_provider_hqc128();
    assert(p != NULL);
    assert(strcmp(p->name(), "HQC-128") == 0);

    const pq_algorithm_metadata_t *m = p->metadata();
    assert(m->family == PQ_ALG_FAMILY_CODE);
    assert(m->status == PQ_ALG_STATUS_CANDIDATE);
    assert(m->nist_level == 1);
}

TEST(hqc128_roundtrip)
{
    const pq_kem_provider_t *p = pq_kem_provider_hqc128();
    if (!p->is_available()) { printf("SKIP (HQC not compiled in liboqs) "); return; }

    uint8_t *pk = malloc(p->metadata()->pk_size);
    uint8_t *sk = malloc(p->metadata()->sk_size);
    uint8_t *ct = malloc(p->metadata()->ct_size);
    uint8_t *ss1 = malloc(p->metadata()->ss_size);
    uint8_t *ss2 = malloc(p->metadata()->ss_size);

    assert(p->keygen(pk, sk) == PQ_SUCCESS);
    assert(p->encapsulate(pk, ct, ss1) == PQ_SUCCESS);
    assert(p->decapsulate(sk, ct, ss2) == PQ_SUCCESS);
    assert(memcmp(ss1, ss2, p->metadata()->ss_size) == 0);

    free(pk); free(sk); free(ct); free(ss1); free(ss2);
}

/* ========================================================================
 * Signature Provider Tests
 * ======================================================================== */

TEST(mldsa65_roundtrip)
{
    const pq_sig_provider_t *p = pq_sig_provider_mldsa65();
    if (!p->is_available()) { printf("SKIP (not available) "); return; }

    assert(strcmp(p->name(), "ML-DSA-65") == 0);
    const pq_algorithm_metadata_t *m = p->metadata();
    assert(m->nist_level == 3);

    uint8_t *pk = malloc(m->pk_size);
    uint8_t *sk = malloc(m->sk_size);
    uint8_t *sig = malloc(m->ct_size);
    size_t sig_len = 0;

    const uint8_t msg[] = "Post-quantum TLS is the future";

    assert(p->keygen(pk, sk) == PQ_SUCCESS);
    assert(p->sign(sk, msg, sizeof(msg) - 1, sig, &sig_len) == PQ_SUCCESS);
    assert(sig_len > 0);
    assert(p->verify(pk, msg, sizeof(msg) - 1, sig, sig_len) == PQ_SUCCESS);

    /* Tamper with signature → should fail */
    sig[0] ^= 0xFF;
    assert(p->verify(pk, msg, sizeof(msg) - 1, sig, sig_len) != PQ_SUCCESS);

    free(pk); free(sk); free(sig);
}

TEST(ed25519_roundtrip)
{
    const pq_sig_provider_t *p = pq_sig_provider_ed25519();
    if (!p->is_available()) { printf("SKIP (not available) "); return; }

    assert(strcmp(p->name(), "Ed25519") == 0);
    assert(p->metadata()->family == PQ_ALG_FAMILY_CLASSICAL);

    uint8_t pk[32], sk[32], sig[64];
    size_t sig_len = 0;
    const uint8_t msg[] = "test message";

    assert(p->keygen(pk, sk) == PQ_SUCCESS);
    assert(p->sign(sk, msg, sizeof(msg) - 1, sig, &sig_len) == PQ_SUCCESS);
    assert(p->verify(pk, msg, sizeof(msg) - 1, sig, sig_len) == PQ_SUCCESS);
}

/* ========================================================================
 * Hybrid Combiner Tests
 * ======================================================================== */

TEST(kdf_concat_combiner)
{
    const pq_hybrid_combiner_t *c = pq_combiner_kdf_concat();
    assert(c != NULL);
    assert(c->method == PQ_COMBINER_KDF_CONCAT);

    uint8_t classical_ss[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                 17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    uint8_t pq_ss[32] = {32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,
                           16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
    uint8_t out[32];
    size_t out_len = sizeof(out);

    assert(c->combine(classical_ss, 32, pq_ss, 32, out, &out_len, NULL, 0) == PQ_SUCCESS);
    assert(out_len == 32);

    /* Deterministic: same inputs → same output */
    uint8_t out2[32];
    size_t out2_len = sizeof(out2);
    assert(c->combine(classical_ss, 32, pq_ss, 32, out2, &out2_len, NULL, 0) == PQ_SUCCESS);
    assert(memcmp(out, out2, 32) == 0);

    /* Different context → different output */
    uint8_t out3[32];
    size_t out3_len = sizeof(out3);
    assert(c->combine(classical_ss, 32, pq_ss, 32, out3, &out3_len,
                       (const uint8_t *)"different", 9) == PQ_SUCCESS);
    assert(memcmp(out, out3, 32) != 0);
}

TEST(xor_combiner)
{
    const pq_hybrid_combiner_t *c = pq_combiner_xor();
    assert(c != NULL);
    assert(c->method == PQ_COMBINER_XOR);

    uint8_t a[32], b[32], out[32];
    memset(a, 0xAA, 32);
    memset(b, 0x55, 32);
    size_t out_len = sizeof(out);

    assert(c->combine(a, 32, b, 32, out, &out_len, NULL, 0) == PQ_SUCCESS);
    assert(out_len == 32);

    /* 0xAA XOR 0x55 = 0xFF */
    for (size_t i = 0; i < 32; i++)
        assert(out[i] == 0xFF);
}

/* ========================================================================
 * Registry Tests
 * ======================================================================== */

TEST(registry_create_destroy)
{
    pq_registry_t *reg = pq_registry_create();
    assert(reg != NULL);
    assert(pq_registry_kem_count(reg) == 0);
    assert(pq_registry_sig_count(reg) == 0);
    pq_registry_destroy(reg);
}

TEST(registry_register_builtins)
{
    pq_registry_t *reg = pq_registry_create();
    assert(pq_registry_register_builtins(reg) == PQ_SUCCESS);

    /* Should have 5 KEM providers: ML-KEM-512/768/1024, X25519, P-256 */
    assert(pq_registry_kem_count(reg) == 5);

    /* Should have 4 SIG providers: ML-DSA-44/65/87, Ed25519 */
    assert(pq_registry_sig_count(reg) == 4);

    pq_registry_destroy(reg);
}

TEST(registry_find_kem)
{
    pq_registry_t *reg = pq_registry_create();
    pq_registry_register_builtins(reg);

    const pq_kem_provider_t *p = pq_registry_find_kem(reg, "ML-KEM-768");
    assert(p != NULL);
    assert(strcmp(p->name(), "ML-KEM-768") == 0);

    assert(pq_registry_find_kem(reg, "NONEXISTENT") == NULL);

    pq_registry_destroy(reg);
}

TEST(registry_find_hybrid)
{
    pq_registry_t *reg = pq_registry_create();
    pq_registry_register_builtins(reg);

    const pq_hybrid_kem_t *h = pq_registry_find_hybrid(reg, "X25519MLKEM768");
    assert(h != NULL);
    assert(h->nist_level == 3);
    assert(h->classical != NULL);
    assert(h->pq != NULL);
    assert(h->combiner != NULL);

    /* Classical-only entry */
    h = pq_registry_find_hybrid(reg, "X25519");
    assert(h != NULL);
    assert(h->pq == NULL);
    assert(h->combiner == NULL);

    pq_registry_destroy(reg);
}

TEST(registry_filter_by_level)
{
    pq_registry_t *reg = pq_registry_create();
    pq_registry_register_builtins(reg);

    const pq_kem_provider_t *results[32];
    size_t n = pq_registry_filter_kems_by_level(reg, 3, results, 32);
    assert(n >= 2); /* At least ML-KEM-768 and ML-KEM-1024 */

    for (size_t i = 0; i < n; i++)
        assert(results[i]->metadata()->nist_level >= 3);

    pq_registry_destroy(reg);
}

TEST(registry_filter_by_family)
{
    pq_registry_t *reg = pq_registry_create();
    pq_registry_register_builtins(reg);

    const pq_kem_provider_t *results[32];
    size_t n = pq_registry_filter_kems_by_family(reg, PQ_ALG_FAMILY_LATTICE, results, 32);
    assert(n == 3); /* ML-KEM-512, 768, 1024 */

    n = pq_registry_filter_kems_by_family(reg, PQ_ALG_FAMILY_CLASSICAL, results, 32);
    assert(n == 2); /* X25519, P-256 */

    pq_registry_destroy(reg);
}

TEST(registry_generate_groups_string)
{
    pq_registry_t *reg = pq_registry_create();
    pq_registry_register_builtins(reg);

    char buf[512];
    int len = pq_registry_generate_groups_string(reg, buf, sizeof(buf));
    assert(len > 0);

    /* Should contain the hybrid entries */
    assert(strstr(buf, "X25519MLKEM768") != NULL);
    assert(strstr(buf, "X25519") != NULL);

    pq_registry_destroy(reg);
}

TEST(registry_preference_ordering)
{
    pq_registry_t *reg = pq_registry_create();
    pq_registry_register_builtins(reg);

    const char *prefs[] = {
        "X25519MLKEM1024",
        "X25519MLKEM768",
        "X25519",
        NULL
    };
    assert(pq_registry_set_kem_preference(reg, prefs) == PQ_SUCCESS);

    char buf[512];
    int len = pq_registry_generate_groups_string(reg, buf, sizeof(buf));
    assert(len > 0);

    /* Verify ordering: 1024 should come before 768 */
    char *pos1024 = strstr(buf, "X25519MLKEM1024");
    char *pos768  = strstr(buf, "X25519MLKEM768");
    assert(pos1024 != NULL && pos768 != NULL);
    assert(pos1024 < pos768);

    pq_registry_destroy(reg);
}

TEST(registry_policy)
{
    pq_registry_t *reg = pq_registry_create();
    pq_registry_register_builtins(reg);

    pq_crypto_policy_t policy = {
        .allow_classical_only = false,
        .min_nist_level = 3,
        .log_negotiation = true,
        .prefer_hybrid = true,
    };
    assert(pq_registry_set_policy(reg, &policy) == PQ_SUCCESS);

    const pq_crypto_policy_t *p = pq_registry_get_policy(reg);
    assert(p->allow_classical_only == false);
    assert(p->min_nist_level == 3);

    /* With min_level=3 and no classical, groups should exclude level 1 */
    char buf[512];
    int len = pq_registry_generate_groups_string(reg, buf, sizeof(buf));
    assert(len > 0);
    assert(strstr(buf, "X25519MLKEM512") == NULL); /* Level 1, excluded */
    assert(strstr(buf, "X25519MLKEM768") != NULL);  /* Level 3, included */

    pq_registry_destroy(reg);
}

TEST(registry_negotiation_log)
{
    pq_registry_t *reg = pq_registry_create();

    pq_negotiation_log_entry_t entry = {
        .selected_name = "X25519MLKEM768",
        .nist_level = 3,
        .is_hybrid = true,
        .is_fallback = false,
        .client_groups = "X25519MLKEM768:X25519",
        .reason = "highest preference mutual match",
    };
    assert(pq_registry_log_negotiation(reg, &entry) == PQ_SUCCESS);

    pq_negotiation_log_entry_t out[10];
    size_t n = pq_registry_get_negotiation_log(reg, out, 10);
    assert(n == 1);
    assert(strcmp(out[0].selected_name, "X25519MLKEM768") == 0);
    assert(out[0].timestamp_us > 0);

    pq_registry_destroy(reg);
}

TEST(registry_to_json)
{
    pq_registry_t *reg = pq_registry_create();
    pq_registry_register_builtins(reg);

    char buf[8192];
    int len = pq_registry_to_json(reg, buf, sizeof(buf));
    assert(len > 0);

    /* Verify JSON structure */
    assert(strstr(buf, "\"kem_providers\"") != NULL);
    assert(strstr(buf, "\"sig_providers\"") != NULL);
    assert(strstr(buf, "\"hybrid_kems\"") != NULL);
    assert(strstr(buf, "\"ML-KEM-768\"") != NULL);
    assert(strstr(buf, "\"ML-DSA-65\"") != NULL);

    pq_registry_destroy(reg);
}

TEST(registry_duplicate_registration)
{
    pq_registry_t *reg = pq_registry_create();
    assert(pq_registry_register_kem(reg, pq_kem_provider_mlkem768()) == PQ_SUCCESS);
    assert(pq_registry_register_kem(reg, pq_kem_provider_mlkem768()) == PQ_ERR_INVALID_PARAMETER);
    assert(pq_registry_kem_count(reg) == 1);
    pq_registry_destroy(reg);
}

TEST(hqc_plugin_descriptor)
{
    /* Validate the plugin entry point works as expected */
    extern const pq_plugin_descriptor_t *pq_plugin_init(void);
    const pq_plugin_descriptor_t *desc = pq_plugin_init();

    assert(desc != NULL);
    assert(desc->api_version == PQ_PLUGIN_API_VERSION);
    assert(strcmp(desc->plugin_name, "hqc-provider") == 0);
    assert(desc->kem_count == 3);
    assert(desc->sig_count == 0);

    /* Register HQC providers via plugin descriptor */
    pq_registry_t *reg = pq_registry_create();
    for (size_t i = 0; i < desc->kem_count; i++) {
        assert(pq_registry_register_kem(reg, desc->kem_providers[i]) == PQ_SUCCESS);
    }
    assert(pq_registry_kem_count(reg) == 3);

    assert(pq_registry_find_kem(reg, "HQC-128") != NULL);
    assert(pq_registry_find_kem(reg, "HQC-192") != NULL);
    assert(pq_registry_find_kem(reg, "HQC-256") != NULL);

    pq_registry_destroy(reg);
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void)
{
    printf("\n=== Crypto-Agility Registry Tests ===\n\n");

    printf("[Provider Interface]\n");
    RUN(mlkem_provider_metadata);
    RUN(mlkem512_roundtrip);
    RUN(mlkem768_roundtrip);
    RUN(mlkem1024_roundtrip);
    RUN(x25519_roundtrip);
    RUN(hqc128_metadata);
    RUN(hqc128_roundtrip);

    printf("\n[Signature Providers]\n");
    RUN(mldsa65_roundtrip);
    RUN(ed25519_roundtrip);

    printf("\n[Hybrid Combiners]\n");
    RUN(kdf_concat_combiner);
    RUN(xor_combiner);

    printf("\n[Registry]\n");
    RUN(registry_create_destroy);
    RUN(registry_register_builtins);
    RUN(registry_find_kem);
    RUN(registry_find_hybrid);
    RUN(registry_filter_by_level);
    RUN(registry_filter_by_family);
    RUN(registry_generate_groups_string);
    RUN(registry_preference_ordering);
    RUN(registry_policy);
    RUN(registry_negotiation_log);
    RUN(registry_to_json);
    RUN(registry_duplicate_registration);
    RUN(hqc_plugin_descriptor);

    printf("\n=== All tests passed ===\n\n");
    return 0;
}
