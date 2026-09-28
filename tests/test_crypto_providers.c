/*
 * test_crypto_providers.c - Tests for the crypto library fixes in src/common
 *
 *  - pq_sig: sign/verify for every algorithm with the "*sig_len = capacity"
 *    contract (a zero/short capacity is rejected instead of overflowing or
 *    silently failing inside OpenSSL); tampered signatures fail.
 *  - Signature providers: sign() works with *sig_len = 0 (output-only per
 *    crypto_provider.h) - the Ed25519 benchmark bug.
 *  - ML-KEM providers: metadata sizes equal liboqs's runtime sizes.
 *  - HQC providers: either cleanly unavailable (sizes 0, operations return
 *    PQ_ERR_ALGORITHM_NOT_AVAILABLE) or sizes come from liboqs and a round
 *    trip with metadata-sized buffers works.
 *  - Classical KEM providers (X25519, P-256 incl. decapsulation and invalid
 *    point rejection).
 *  - hybrid_kex CONCAT (now a KDF, 32 bytes) and the combiners.
 *  - pq_utils hex helpers and thread-safe logging.
 *
 * Uses explicit CHECK()s (not assert) so the tests also run under NDEBUG.
 */

#include "../src/common/hybrid_combiner.h"
#include "../src/common/hybrid_kex.h"
#include "../src/common/kem_classical.h"
#include "../src/common/kem_hqc.h"
#include "../src/common/kem_mlkem.h"
#include "../src/common/pq_errors.h"
#include "../src/common/pq_kem.h"
#include "../src/common/pq_sig.h"
#include "../src/common/pq_utils.h"
#include "../src/common/sig_providers.h"

#include <oqs/oqs.h>
#include <openssl/evp.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        g_failures++; \
    } \
} while (0)

#define PASS(name) printf("PASS: %s\n", name)

/* ------------------------------------------------------------------------ */
/* pq_sig                                                                   */
/* ------------------------------------------------------------------------ */

static void test_pq_sig_all(void) {
    static const struct { int alg; const char *name; } algs[] = {
        { PQ_SIG_MLDSA44, "ML-DSA-44" }, { PQ_SIG_MLDSA65, "ML-DSA-65" },
        { PQ_SIG_MLDSA87, "ML-DSA-87" }, { PQ_SIG_ED25519, "Ed25519" },
        { PQ_SIG_ECDSA_P256, "ECDSA-P256" }, { PQ_SIG_RSA2048, "RSA-2048" },
    };
    const uint8_t msg[] = "pq-tls signature test";
    int before = g_failures;

    for (size_t i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
        int alg = algs[i].alg;
        size_t pk_n = pq_sig_publickey_bytes(alg), sk_n = pq_sig_secretkey_bytes(alg);
        size_t sig_n = pq_sig_signature_bytes(alg);
        uint8_t *pk = malloc(pk_n), *sk = malloc(sk_n), *sig = malloc(sig_n);
        CHECK(pk && sk && sig);
        if (!pk || !sk || !sig) { free(pk); free(sk); free(sig); continue; }

        CHECK(pq_sig_keypair(alg, pk, sk) == PQ_SUCCESS);

        /* capacity 0 (the old benchmark bug) and capacity - 1 are rejected */
        size_t sig_len = 0;
        CHECK(pq_sig_sign(alg, sig, &sig_len, msg, sizeof(msg), sk) == PQ_ERR_BUFFER_TOO_SMALL);
        sig_len = sig_n - 1;
        CHECK(pq_sig_sign(alg, sig, &sig_len, msg, sizeof(msg), sk) == PQ_ERR_BUFFER_TOO_SMALL);
        CHECK(sig_len == 0);

        sig_len = sig_n;
        int rc = pq_sig_sign(alg, sig, &sig_len, msg, sizeof(msg), sk);
        CHECK(rc == PQ_SUCCESS);
        if (rc != PQ_SUCCESS) fprintf(stderr, "  %s sign rc=%d\n", algs[i].name, rc);
        CHECK(sig_len > 0 && sig_len <= sig_n);
        if (alg == PQ_SIG_ED25519) CHECK(sig_len == 64);
        CHECK(pq_sig_verify(alg, msg, sizeof(msg), sig, sig_len, pk) == PQ_SUCCESS);

        sig[sig_len / 2] ^= 0x04;
        CHECK(pq_sig_verify(alg, msg, sizeof(msg), sig, sig_len, pk) != PQ_SUCCESS);
        sig[sig_len / 2] ^= 0x04;
        CHECK(pq_sig_verify(alg, msg, sizeof(msg) - 1, sig, sig_len, pk) != PQ_SUCCESS);

        CHECK(pq_sig_self_test(alg) == PQ_SUCCESS);
        free(pk); free(sk); free(sig);
    }

    /* ECDSA: off-curve public key must be rejected */
    {
        uint8_t pk[65], sk[32], sig[72];
        size_t sig_len = sizeof(sig);
        CHECK(pq_sig_keypair(PQ_SIG_ECDSA_P256, pk, sk) == PQ_SUCCESS);
        CHECK(pq_sig_sign(PQ_SIG_ECDSA_P256, sig, &sig_len, msg, sizeof(msg), sk) == PQ_SUCCESS);
        pk[64] ^= 0x01;
        CHECK(pq_sig_verify(PQ_SIG_ECDSA_P256, msg, sizeof(msg), sig, sig_len, pk) != PQ_SUCCESS);
    }

    if (g_failures == before) PASS("pq_sig sign/verify, capacity contract (6 algorithms)");
}

static void test_sig_providers(void) {
    const pq_sig_provider_t *provs[] = {
        pq_sig_provider_mldsa44(), pq_sig_provider_mldsa65(),
        pq_sig_provider_mldsa87(), pq_sig_provider_ed25519(),
    };
    const uint8_t msg[] = "provider message";
    int before = g_failures;

    for (size_t i = 0; i < sizeof(provs) / sizeof(provs[0]); i++) {
        const pq_sig_provider_t *p = provs[i];
        const pq_algorithm_metadata_t *m = p->metadata();
        CHECK(p->is_available());
        CHECK(p->is_available());   /* cached path */
        uint8_t *pk = malloc(m->pk_size), *sk = malloc(m->sk_size), *sig = malloc(m->ct_size);
        CHECK(pk && sk && sig);
        if (pk && sk && sig) {
            size_t sig_len = 0;   /* output-only per crypto_provider.h */
            CHECK(p->keygen(pk, sk) == PQ_SUCCESS);
            CHECK(p->sign(sk, msg, sizeof(msg) - 1, sig, &sig_len) == PQ_SUCCESS);
            CHECK(sig_len > 0 && sig_len <= m->ct_size);
            CHECK(p->verify(pk, msg, sizeof(msg) - 1, sig, sig_len) == PQ_SUCCESS);
        }
        free(pk); free(sk); free(sig);
    }
    if (g_failures == before) PASS("signature providers (Ed25519 sign with sig_len=0 input)");
}

/* ------------------------------------------------------------------------ */
/* KEM providers                                                            */
/* ------------------------------------------------------------------------ */

static void kem_roundtrip(const pq_kem_provider_t *p) {
    const pq_algorithm_metadata_t *m = p->metadata();
    uint8_t *pk = malloc(m->pk_size), *sk = malloc(m->sk_size), *ct = malloc(m->ct_size);
    uint8_t *s1 = malloc(m->ss_size), *s2 = malloc(m->ss_size);
    CHECK(pk && sk && ct && s1 && s2);
    if (pk && sk && ct && s1 && s2) {
        CHECK(p->keygen(pk, sk) == PQ_SUCCESS);
        CHECK(p->encapsulate(pk, ct, s1) == PQ_SUCCESS);
        CHECK(p->decapsulate(sk, ct, s2) == PQ_SUCCESS);
        CHECK(memcmp(s1, s2, m->ss_size) == 0);
    }
    free(pk); free(sk); free(ct); free(s1); free(s2);
}

static void test_mlkem_providers(void) {
    const pq_kem_provider_t *provs[] = {
        pq_kem_provider_mlkem512(), pq_kem_provider_mlkem768(), pq_kem_provider_mlkem1024(),
    };
    int before = g_failures;
    for (size_t i = 0; i < 3; i++) {
        const pq_kem_provider_t *p = provs[i];
        const pq_algorithm_metadata_t *m = p->metadata();
        CHECK(p->is_available());
        OQS_KEM *k = OQS_KEM_new(m->name);
        CHECK(k != NULL);
        if (k) {
            CHECK(k->length_public_key == m->pk_size);
            CHECK(k->length_secret_key == m->sk_size);
            CHECK(k->length_ciphertext == m->ct_size);
            CHECK(k->length_shared_secret == m->ss_size);
            OQS_KEM_free(k);
        }
        kem_roundtrip(p);
    }
    if (g_failures == before) PASS("ML-KEM providers: metadata sizes == liboqs runtime sizes");
}

static void test_hqc_providers(void) {
    const pq_kem_provider_t *provs[] = {
        pq_kem_provider_hqc128(), pq_kem_provider_hqc192(), pq_kem_provider_hqc256(),
    };
    static const char *names[] = { "HQC-128", "HQC-192", "HQC-256" };
#if defined(OQS_KEM_alg_hqc_1)
    static const char *oqs_names[] = { OQS_KEM_alg_hqc_1, OQS_KEM_alg_hqc_3, OQS_KEM_alg_hqc_5 };
#else
    static const char *oqs_names[] = { OQS_KEM_alg_hqc_128, OQS_KEM_alg_hqc_192, OQS_KEM_alg_hqc_256 };
#endif
    int before = g_failures;
    int available = 0;

    for (size_t i = 0; i < 3; i++) {
        const pq_kem_provider_t *p = provs[i];
        const pq_algorithm_metadata_t *m = p->metadata();
        CHECK(strcmp(p->name(), names[i]) == 0);
        CHECK(m->family == PQ_ALG_FAMILY_CODE);
        OQS_KEM *k = OQS_KEM_new(oqs_names[i]);
        CHECK(p->is_available() == (k != NULL));
        if (!p->is_available()) {
            uint8_t dummy[1] = { 0 };
            CHECK(m->pk_size == 0 && m->sk_size == 0 && m->ct_size == 0 && m->ss_size == 0);
            CHECK(p->keygen(dummy, dummy) == PQ_ERR_ALGORITHM_NOT_AVAILABLE);
            CHECK(p->encapsulate(dummy, dummy, dummy) == PQ_ERR_ALGORITHM_NOT_AVAILABLE);
            CHECK(p->decapsulate(dummy, dummy, dummy) == PQ_ERR_ALGORITHM_NOT_AVAILABLE);
        } else {
            available++;
            CHECK(k->length_public_key == m->pk_size);
            CHECK(k->length_secret_key == m->sk_size);
            CHECK(k->length_ciphertext == m->ct_size);
            CHECK(k->length_shared_secret == m->ss_size);
            kem_roundtrip(p);
        }
        OQS_KEM_free(k);
    }
    if (g_failures == before) {
        printf("PASS: HQC providers (%s)\n",
               available ? "available: sizes from liboqs, round trip ok"
                         : "not compiled into liboqs: reported unavailable cleanly");
    }
}

static void test_classical_kems(void) {
    int before = g_failures;
    kem_roundtrip(pq_kem_provider_x25519());
    kem_roundtrip(pq_kem_provider_p256());   /* decapsulate used to be unsupported */

    /* P-256: invalid / off-curve ephemeral key is rejected */
    {
        const pq_kem_provider_t *p = pq_kem_provider_p256();
        uint8_t pk[65], sk[32], ct[65], ss[32];
        CHECK(p->keygen(pk, sk) == PQ_SUCCESS);
        CHECK(p->encapsulate(pk, ct, ss) == PQ_SUCCESS);
        ct[40] ^= 0x01;
        CHECK(p->decapsulate(sk, ct, ss) != PQ_SUCCESS);
        ct[40] ^= 0x01;
        ct[0] = 0x02;   /* compressed encoding not accepted */
        CHECK(p->decapsulate(sk, ct, ss) != PQ_SUCCESS);
        pk[64] ^= 0x01;
        CHECK(p->encapsulate(pk, ct, ss) != PQ_SUCCESS);
    }
    /* P-256 raw helpers: out-of-range scalars */
    {
        uint8_t zero[32] = { 0 }, ff[32], pk[65];
        memset(ff, 0xFF, sizeof(ff));
        CHECK(pq_p256_public_from_private(zero, pk) != PQ_SUCCESS);
        CHECK(pq_p256_public_from_private(ff, pk) != PQ_SUCCESS);
    }
    /* X25519: all-zero (low-order) peer key is rejected */
    {
        const pq_kem_provider_t *p = pq_kem_provider_x25519();
        uint8_t pk[32], sk[32], zero[32] = { 0 }, ss[32], ct[32];
        CHECK(p->keygen(pk, sk) == PQ_SUCCESS);
        CHECK(p->decapsulate(sk, zero, ss) != PQ_SUCCESS);
        CHECK(p->encapsulate(zero, ct, ss) != PQ_SUCCESS);
    }
    if (g_failures == before) PASS("classical KEM providers (X25519, P-256 incl. decaps + validation)");
}

/* ------------------------------------------------------------------------ */
/* hybrid_kex                                                               */
/* ------------------------------------------------------------------------ */

static void test_hybrid_kex(void) {
    int before = g_failures;
    static const int classical[] = { HYBRID_CLASSICAL_X25519, HYBRID_CLASSICAL_P256 };
    static const int pqs[] = { PQ_KEM_MLKEM512, PQ_KEM_MLKEM768, PQ_KEM_MLKEM1024 };

    for (size_t c = 0; c < 2; c++) {
        for (size_t q = 0; q < 3; q++) {
            pq_hybrid_kex_t *kex = pq_hybrid_kex_init(classical[c], pqs[q], HYBRID_MODE_CONCAT);
            CHECK(kex != NULL);
            if (!kex) continue;
            size_t pk_cap = pq_hybrid_kex_publickey_bytes(kex);
            size_t sk_cap = pq_hybrid_kex_secretkey_bytes(kex);
            size_t ct_cap = pq_hybrid_kex_ciphertext_bytes(kex);
            CHECK(pq_hybrid_kex_sharedsecret_bytes(kex) == 32);
            uint8_t *pk = malloc(pk_cap), *sk = malloc(sk_cap), *ct = malloc(ct_cap);
            uint8_t s1[32], s2[32];
            size_t pk_len = 0, sk_len = 0, ct_len = 0, s1_len = 0, s2_len = 0;
            CHECK(pk && sk && ct);
            if (pk && sk && ct) {
                CHECK(pq_hybrid_kex_keypair(kex, pk, &pk_len, sk, &sk_len) == PQ_SUCCESS);
                CHECK(pk_len == pk_cap && sk_len == sk_cap);
                CHECK(pq_hybrid_kex_encapsulate(kex, ct, &ct_len, s1, &s1_len, pk, pk_len)
                      == PQ_SUCCESS);
                CHECK(ct_len == ct_cap && s1_len == 32);
                CHECK(pq_hybrid_kex_decapsulate(kex, s2, &s2_len, ct, ct_len, sk, sk_len)
                      == PQ_SUCCESS);
                CHECK(s2_len == 32 && memcmp(s1, s2, 32) == 0);

                /* Tampering with the PQ ciphertext changes the secret */
                ct[ct_len - 1] ^= 0x01;
                CHECK(pq_hybrid_kex_decapsulate(kex, s2, &s2_len, ct, ct_len, sk, sk_len)
                      == PQ_SUCCESS);
                CHECK(memcmp(s1, s2, 32) != 0);
                ct[ct_len - 1] ^= 0x01;
                /* Tampering with the classical ciphertext changes or rejects */
                ct[2] ^= 0x01;
                int rc = pq_hybrid_kex_decapsulate(kex, s2, &s2_len, ct, ct_len, sk, sk_len);
                CHECK(rc != PQ_SUCCESS || memcmp(s1, s2, 32) != 0);
                ct[2] ^= 0x01;
                /* Exact length checks */
                CHECK(pq_hybrid_kex_encapsulate(kex, ct, &ct_len, s1, &s1_len, pk, pk_len - 1)
                      == PQ_ERR_INVALID_PARAMETER);
                CHECK(pq_hybrid_kex_decapsulate(kex, s2, &s2_len, ct, ct_len - 1, sk, sk_len)
                      == PQ_ERR_INVALID_PARAMETER);
            }
            free(pk); free(sk); free(ct);
            pq_hybrid_kex_free(kex);
        }
    }

    /* Deprecated XOR mode still round-trips (compatibility) */
    {
        pq_hybrid_kex_t *kex = pq_hybrid_kex_init(HYBRID_CLASSICAL_X25519, PQ_KEM_MLKEM768,
                                                  HYBRID_MODE_XOR);
        uint8_t pk[32 + 1184], sk[32 + 2400], ct[32 + 1088], s1[32], s2[32];
        size_t pl, sl, cl, l1, l2;
        CHECK(kex != NULL);
        CHECK(pq_hybrid_kex_keypair(kex, pk, &pl, sk, &sl) == PQ_SUCCESS);
        CHECK(pq_hybrid_kex_encapsulate(kex, ct, &cl, s1, &l1, pk, pl) == PQ_SUCCESS);
        CHECK(pq_hybrid_kex_decapsulate(kex, s2, &l2, ct, cl, sk, sl) == PQ_SUCCESS);
        CHECK(l1 == 32 && l2 == 32 && memcmp(s1, s2, 32) == 0);
        pq_hybrid_kex_free(kex);
    }

    if (g_failures == before) PASS("hybrid_kex CONCAT via SHA3-256 KDF (2 classical x 3 ML-KEM)");
}

/* ------------------------------------------------------------------------ */
/* Combiners                                                                */
/* ------------------------------------------------------------------------ */

static void test_combiners(void) {
    int before = g_failures;
    const pq_hybrid_combiner_t *kdf = pq_combiner_kdf_concat();
    uint8_t a[32], b[32], o1[32], o2[32], o3[32];
    size_t l1 = sizeof(o1), l2 = sizeof(o2), l3 = sizeof(o3);
    memset(a, 0x11, sizeof(a));
    memset(b, 0x22, sizeof(b));

    uint8_t t1[32], t2[32];
    uint8_t ct_c[32], ct_pq[64], pk_c[32], pk_pq[64];
    memset(ct_c, 1, sizeof(ct_c)); memset(ct_pq, 2, sizeof(ct_pq));
    memset(pk_c, 3, sizeof(pk_c)); memset(pk_pq, 4, sizeof(pk_pq));
    CHECK(pq_combiner_transcript_hash(ct_c, 32, ct_pq, 64, pk_c, 32, pk_pq, 64, t1) == PQ_SUCCESS);
    ct_pq[10] ^= 1;
    CHECK(pq_combiner_transcript_hash(ct_c, 32, ct_pq, 64, pk_c, 32, pk_pq, 64, t2) == PQ_SUCCESS);
    CHECK(memcmp(t1, t2, 32) != 0);
    /* length framing: moving a byte between fields changes the digest */
    CHECK(pq_combiner_transcript_hash(ct_c, 31, ct_pq, 64, pk_c, 32, pk_pq, 64, t2) == PQ_SUCCESS);
    CHECK(memcmp(t1, t2, 32) != 0);

    CHECK(kdf->combine(a, 32, b, 32, o1, &l1, t1, 32) == PQ_SUCCESS);
    CHECK(kdf->combine(a, 32, b, 32, o2, &l2, t1, 32) == PQ_SUCCESS);
    CHECK(kdf->combine(a, 32, b, 32, o3, &l3, t2, 32) == PQ_SUCCESS);
    CHECK(l1 == 32 && memcmp(o1, o2, 32) == 0);     /* deterministic */
    CHECK(memcmp(o1, o3, 32) != 0);                 /* bound to the transcript */
    {
        /* Length-framed IKM: moving the split point between the two secrets
         * (same concatenated bytes) must change the output. */
        uint8_t ab[64], x1[32], x2[32];
        size_t xl1 = sizeof(x1), xl2 = sizeof(x2);
        memcpy(ab, a, 32);
        memcpy(ab + 32, b, 32);
        CHECK(kdf->combine(ab, 32, ab + 32, 32, x1, &xl1, t1, 32) == PQ_SUCCESS);
        CHECK(kdf->combine(ab, 31, ab + 31, 33, x2, &xl2, t1, 32) == PQ_SUCCESS);
        CHECK(memcmp(x1, o1, 32) == 0);
        CHECK(memcmp(x1, x2, 32) != 0);
    }
    l3 = 16;
    CHECK(kdf->combine(a, 32, b, 32, o3, &l3, NULL, 0) == PQ_ERR_BUFFER_TOO_SMALL);

    /* XOR combiner is flagged as deprecated/insecure */
    CHECK(strstr(pq_combiner_xor()->name, "insecure") != NULL);

    /* X-Wing-style combiner == independent SHA3-256 */
    {
        uint8_t out[32], expect[32];
        unsigned int md_len = 0;
        const uint8_t label[] = PQ_XWING_LABEL;
        CHECK(pq_combiner_xwing_style(a, 32, b, 32, ct_c, 32, pk_c, 32,
                                      label, PQ_XWING_LABEL_BYTES, out) == PQ_SUCCESS);
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        CHECK(md && EVP_DigestInit_ex(md, EVP_sha3_256(), NULL) == 1 &&
              EVP_DigestUpdate(md, a, 32) == 1 && EVP_DigestUpdate(md, b, 32) == 1 &&
              EVP_DigestUpdate(md, ct_c, 32) == 1 && EVP_DigestUpdate(md, pk_c, 32) == 1 &&
              EVP_DigestUpdate(md, "\x5c\x2e\x2f\x2f\x5e\x5c", 6) == 1 &&
              EVP_DigestFinal_ex(md, expect, &md_len) == 1);
        EVP_MD_CTX_free(md);
        CHECK(memcmp(out, expect, 32) == 0);
        CHECK(pq_combiner_xwing_style(NULL, 32, b, 32, ct_c, 32, pk_c, 32,
                                      label, PQ_XWING_LABEL_BYTES, out) != PQ_SUCCESS);
    }

    if (g_failures == before) PASS("combiners (KDF-Concat transcript binding, X-Wing-style, XOR flagged)");
}

/* ------------------------------------------------------------------------ */
/* pq_utils                                                                 */
/* ------------------------------------------------------------------------ */

static void *log_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 200; i++)
        pq_log(LOG_INFO, "thread log line %d", i);
    return NULL;
}

static void test_utils(void) {
    int before = g_failures;
    const uint8_t bytes[] = { 0x00, 0x01, 0x7f, 0x80, 0xab, 0xff };
    char hex[2 * sizeof(bytes) + 1];
    uint8_t back[8];

    pq_bytes_to_hex(bytes, sizeof(bytes), hex);
    CHECK(strcmp(hex, "00017f80abff") == 0);
    CHECK(pq_hex_to_bytes("00017f80abff", back, sizeof(back)) == (int)sizeof(bytes));
    CHECK(memcmp(back, bytes, sizeof(bytes)) == 0);
    CHECK(pq_hex_to_bytes("00017F80ABFF", back, sizeof(back)) == (int)sizeof(bytes));
    CHECK(pq_hex_to_bytes("abc", back, sizeof(back)) == -1);        /* odd length */
    CHECK(pq_hex_to_bytes("zz", back, sizeof(back)) == -1);         /* invalid char */
    CHECK(pq_hex_to_bytes("0011223344556677ff", back, 8) == -1);    /* too long */

    /* Concurrent logging (localtime_r + mutex); output goes to /dev/null */
    pq_log_init("/dev/null", LOG_DEBUG);
    pthread_t th[4];
    for (int i = 0; i < 4; i++) CHECK(pthread_create(&th[i], NULL, log_worker, NULL) == 0);
    for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
    pq_log_cleanup();

    if (g_failures == before) PASS("pq_utils hex (lookup table, strict decode), threaded pq_log");
}

int run_crypto_provider_tests(void) {
    g_failures = 0;
    test_pq_sig_all();
    test_sig_providers();
    test_mlkem_providers();
    test_hqc_providers();
    test_classical_kems();
    test_hybrid_kex();
    test_combiners();
    test_utils();
    return g_failures == 0 ? 0 : 1;
}
