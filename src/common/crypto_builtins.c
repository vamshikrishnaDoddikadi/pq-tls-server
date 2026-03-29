/**
 * @file crypto_builtins.c
 * @brief Registers all built-in crypto providers with the registry
 * @author Vamshi Krishna Doddikadi
 * @date 2026
 *
 * Called by pq_registry_register_builtins() to populate the registry
 * with all compiled-in KEM, SIG, and combiner providers plus the
 * standard hybrid KEM pair definitions.
 */

#include "crypto_registry.h"
#include "kem_mlkem.h"
#include "kem_classical.h"
#include "sig_providers.h"
#include "hybrid_combiner.h"
#include "pq_errors.h"

#include <stdio.h>

int pq_registry_register_builtins(pq_registry_t *reg)
{
    if (!reg) return PQ_ERR_INVALID_PARAMETER;

    int rc;

    /* ---- KEM Providers ---- */

    /* Post-quantum (lattice-based) */
    rc = pq_registry_register_kem(reg, pq_kem_provider_mlkem512());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] ML-KEM-512 registration: %s\n", pq_error_string(rc));

    rc = pq_registry_register_kem(reg, pq_kem_provider_mlkem768());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] ML-KEM-768 registration: %s\n", pq_error_string(rc));

    rc = pq_registry_register_kem(reg, pq_kem_provider_mlkem1024());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] ML-KEM-1024 registration: %s\n", pq_error_string(rc));

    /* Classical */
    rc = pq_registry_register_kem(reg, pq_kem_provider_x25519());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] X25519 registration: %s\n", pq_error_string(rc));

    rc = pq_registry_register_kem(reg, pq_kem_provider_p256());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] P-256 registration: %s\n", pq_error_string(rc));

    /* ---- Signature Providers ---- */

    rc = pq_registry_register_sig(reg, pq_sig_provider_mldsa44());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] ML-DSA-44 registration: %s\n", pq_error_string(rc));

    rc = pq_registry_register_sig(reg, pq_sig_provider_mldsa65());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] ML-DSA-65 registration: %s\n", pq_error_string(rc));

    rc = pq_registry_register_sig(reg, pq_sig_provider_mldsa87());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] ML-DSA-87 registration: %s\n", pq_error_string(rc));

    rc = pq_registry_register_sig(reg, pq_sig_provider_ed25519());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] Ed25519 registration: %s\n", pq_error_string(rc));

    /* ---- Combiners ---- */

    rc = pq_registry_register_combiner(reg, pq_combiner_kdf_concat());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] KDF-Concat combiner: %s\n", pq_error_string(rc));

    rc = pq_registry_register_combiner(reg, pq_combiner_xor());
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] XOR combiner: %s\n", pq_error_string(rc));

    /* ---- Hybrid KEM Pairs ---- */

    /* X25519 + ML-KEM-768 (the current default) */
    pq_hybrid_kem_t h_x25519_mlkem768 = {
        .label      = "X25519 + ML-KEM-768",
        .tls_group  = "X25519MLKEM768",
        .classical  = pq_kem_provider_x25519(),
        .pq         = pq_kem_provider_mlkem768(),
        .combiner   = pq_combiner_kdf_concat(),
        .nist_level = 3,
    };
    rc = pq_registry_register_hybrid(reg, &h_x25519_mlkem768);
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] X25519+ML-KEM-768 hybrid: %s\n", pq_error_string(rc));

    /* X25519 + ML-KEM-512 (not validated with oqs-provider 0.7.0) */
    pq_hybrid_kem_t h_x25519_mlkem512 = {
        .label      = "X25519 + ML-KEM-512",
        .tls_group  = "",
        .classical  = pq_kem_provider_x25519(),
        .pq         = pq_kem_provider_mlkem512(),
        .combiner   = pq_combiner_kdf_concat(),
        .nist_level = 1,
    };
    rc = pq_registry_register_hybrid(reg, &h_x25519_mlkem512);
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] X25519+ML-KEM-512 hybrid: %s\n", pq_error_string(rc));

    /* X25519 + ML-KEM-1024 (not validated with oqs-provider 0.7.0) */
    pq_hybrid_kem_t h_x25519_mlkem1024 = {
        .label      = "X25519 + ML-KEM-1024",
        .tls_group  = "",
        .classical  = pq_kem_provider_x25519(),
        .pq         = pq_kem_provider_mlkem1024(),
        .combiner   = pq_combiner_kdf_concat(),
        .nist_level = 5,
    };
    rc = pq_registry_register_hybrid(reg, &h_x25519_mlkem1024);
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] X25519+ML-KEM-1024 hybrid: %s\n", pq_error_string(rc));

    /* P-256 + ML-KEM-768 (not validated with oqs-provider 0.7.0) */
    pq_hybrid_kem_t h_p256_mlkem768 = {
        .label      = "P-256 + ML-KEM-768",
        .tls_group  = "",
        .classical  = pq_kem_provider_p256(),
        .pq         = pq_kem_provider_mlkem768(),
        .combiner   = pq_combiner_kdf_concat(),
        .nist_level = 3,
    };
    rc = pq_registry_register_hybrid(reg, &h_p256_mlkem768);
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] P256+ML-KEM-768 hybrid: %s\n", pq_error_string(rc));

    /* Classical-only fallback entries */
    pq_hybrid_kem_t h_x25519_only = {
        .label      = "X25519 (classical)",
        .tls_group  = "X25519",
        .classical  = pq_kem_provider_x25519(),
        .pq         = NULL,
        .combiner   = NULL,
        .nist_level = 1,
    };
    rc = pq_registry_register_hybrid(reg, &h_x25519_only);
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] X25519 hybrid entry: %s\n", pq_error_string(rc));

    pq_hybrid_kem_t h_p256_only = {
        .label      = "P-256 (classical)",
        .tls_group  = "prime256v1",
        .classical  = pq_kem_provider_p256(),
        .pq         = NULL,
        .combiner   = NULL,
        .nist_level = 1,
    };
    rc = pq_registry_register_hybrid(reg, &h_p256_only);
    if (rc != PQ_SUCCESS)
        fprintf(stderr, "[builtins] P-256 hybrid entry: %s\n", pq_error_string(rc));

    return PQ_SUCCESS;
}
