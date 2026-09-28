/*
 * test_crypto_hpke.c - Tests for the RFC 9180 HPKE module (src/common/hpke.c)
 *
 *  - Known-answer tests against RFC 9180 Appendix A.1 (DHKEM(X25519,
 *    HKDF-SHA256), HKDF-SHA256, AES-128-GCM, mode_base) and A.2 (same with
 *    ChaCha20Poly1305): DeriveKeyPair, enc, KEM shared_secret, the
 *    ciphertexts at sequence numbers 0/1/2/4/255/256 and the exported
 *    values.  (Vector values copied from RFC 9180 Appendix A.)
 *  - The X-Wing-style hybrid KEM secret is recomputed independently
 *    (X25519 + ML-KEM-768 + SHA3-256 with the X-Wing label) to prove that
 *    both components contribute.
 *  - Round trips for every KEM x AEAD, and negative tests (tampered
 *    ciphertext / enc, wrong key, wrong info/AAD, bad lengths, misuse).
 *
 * Uses explicit CHECK()s (not assert) so the tests also run under NDEBUG.
 */

#include "../src/common/hpke.h"
#include "../src/common/pq_errors.h"
#include "../src/common/pq_kem.h"

#include <openssl/evp.h>

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
/* helpers                                                                  */
/* ------------------------------------------------------------------------ */

static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex) / 2;
    if (n > cap) {
        fprintf(stderr, "unhex: buffer too small\n");
        exit(2);
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
            fprintf(stderr, "unhex: bad hex\n");
            exit(2);
        }
        out[i] = (uint8_t)v;
    }
    return n;
}

static int hex_eq(const uint8_t *buf, size_t len, const char *hex) {
    uint8_t tmp[512];
    size_t n = unhex(hex, tmp, sizeof(tmp));
    return n == len && memcmp(buf, tmp, len) == 0;
}

/* ------------------------------------------------------------------------ */
/* RFC 9180 Appendix A vectors                                              */
/* ------------------------------------------------------------------------ */

typedef struct {
    int seq;
    const char *ct;
} kat_enc_t;

typedef struct {
    const char *exporter_context;
    const char *value;   /* L = 32 */
} kat_exp_t;

typedef struct {
    const char *name;
    int aead;
    const char *info, *ikmE, *pkEm, *skEm, *ikmR, *pkRm, *skRm, *enc, *shared_secret;
    kat_enc_t encs[6];
    kat_exp_t exps[3];
} hpke_kat_t;

#define KAT_PT "4265617574792069732074727574682c20747275746820626561757479"

static const hpke_kat_t kats[] = {
    {
        /* RFC 9180 A.1.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Base */
        "RFC 9180 A.1 (AES-128-GCM)", HPKE_AEAD_AES128GCM,
        "4f6465206f6e2061204772656369616e2055726e",
        "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
        {
            { 0,   "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a" },
            { 1,   "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84" },
            { 2,   "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180" },
            { 4,   "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d" },
            { 255, "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a" },
            { 256, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2" },
        },
        {
            { "",                       "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee" },
            { "00",                     "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5" },
            { "54657374436f6e74657874", "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931" },
        },
    },
    {
        /* RFC 9180 A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305, Base */
        "RFC 9180 A.2 (ChaCha20Poly1305)", HPKE_AEAD_CHACHAPOLY,
        "4f6465206f6e2061204772656369616e2055726e",
        "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
        "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
        "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
        {
            { 0,   "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28" },
            { 1,   "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c" },
            { 2,   "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b" },
            { 4,   "63357a2aa291f5a4e5f27db6baa2af8cf77427c7c1a909e0b37214dd47db122bb153495ff0b02e9e54a50dbe16" },
            { 255, "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c" },
            { 256, "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b" },
        },
        {
            { "",                       "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e" },
            { "00",                     "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69" },
            { "54657374436f6e74657874", "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53" },
        },
    },
};

static void run_kat(const hpke_kat_t *v) {
    uint8_t info[64], ikmE[64], ikmR[64], pkRm[32], skRm[32];
    size_t info_len = unhex(v->info, info, sizeof(info));
    size_t ikmE_len = unhex(v->ikmE, ikmE, sizeof(ikmE));
    size_t ikmR_len = unhex(v->ikmR, ikmR, sizeof(ikmR));
    unhex(v->pkRm, pkRm, sizeof(pkRm));
    unhex(v->skRm, skRm, sizeof(skRm));

    pq_hpke_t *s = pq_hpke_init(HPKE_KEM_X25519, v->aead);
    pq_hpke_t *r = pq_hpke_init(HPKE_KEM_X25519, v->aead);
    CHECK(s != NULL && r != NULL);
    if (!s || !r) { pq_hpke_free(s); pq_hpke_free(r); return; }

    /* DeriveKeyPair (RFC 9180 7.1.3) */
    uint8_t pk[32], sk[32];
    CHECK(pq_hpke_derive_keypair(s, ikmR, ikmR_len, pk, sizeof(pk), sk, sizeof(sk)) == PQ_SUCCESS);
    CHECK(hex_eq(pk, 32, v->pkRm));
    CHECK(hex_eq(sk, 32, v->skRm));
    CHECK(pq_hpke_derive_keypair(s, ikmE, ikmE_len, pk, sizeof(pk), sk, sizeof(sk)) == PQ_SUCCESS);
    CHECK(hex_eq(pk, 32, v->pkEm));
    CHECK(hex_eq(sk, 32, v->skEm));

    /* SetupBaseS with the vector's ephemeral key */
    uint8_t enc[32];
    size_t enc_len = 0;
    CHECK(pq_hpke_setup_base_sender_derand(s, ikmE, ikmE_len, enc, sizeof(enc), &enc_len,
                                           pkRm, sizeof(pkRm), info, info_len) == PQ_SUCCESS);
    CHECK(enc_len == 32 && hex_eq(enc, enc_len, v->enc));

    /* Raw KEM Decap must give the vector's shared_secret (ExtractAndExpand) */
    uint8_t ss[32];
    CHECK(pq_hpke_decapsulate(r, ss, sizeof(ss), enc, enc_len, skRm, sizeof(skRm)) == PQ_SUCCESS);
    CHECK(hex_eq(ss, 32, v->shared_secret));

    CHECK(pq_hpke_setup_base_recipient(r, enc, enc_len, skRm, sizeof(skRm), info, info_len)
          == PQ_SUCCESS);

    /* Sequence numbers 0..256; compare against the vectors where given */
    uint8_t pt[64], ct[128], out[128];
    size_t pt_len = unhex(KAT_PT, pt, sizeof(pt));
    size_t next = 0;
    for (int seq = 0; seq <= 256; seq++) {
        char aad[32];
        int aad_len = snprintf(aad, sizeof(aad), "Count-%d", seq);
        size_t ct_len = 0, out_len = 0;
        CHECK(pq_hpke_seal(s, ct, sizeof(ct), &ct_len, pt, pt_len,
                           (const uint8_t *)aad, (size_t)aad_len) == PQ_SUCCESS);
        CHECK(ct_len == pt_len + HPKE_AEAD_TAG_BYTES);
        if (next < 6 && v->encs[next].seq == seq) {
            CHECK(hex_eq(ct, ct_len, v->encs[next].ct));
            next++;
        }
        CHECK(pq_hpke_open(r, out, sizeof(out), &out_len, ct, ct_len,
                           (const uint8_t *)aad, (size_t)aad_len) == PQ_SUCCESS);
        CHECK(out_len == pt_len && memcmp(out, pt, pt_len) == 0);
    }
    CHECK(next == 6);

    /* Secret export from both sides */
    for (int i = 0; i < 3; i++) {
        uint8_t ec[32], e1[32], e2[32];
        size_t ec_len = unhex(v->exps[i].exporter_context, ec, sizeof(ec));
        CHECK(pq_hpke_export(s, ec_len ? ec : NULL, ec_len, e1, sizeof(e1)) == PQ_SUCCESS);
        CHECK(pq_hpke_export(r, ec_len ? ec : NULL, ec_len, e2, sizeof(e2)) == PQ_SUCCESS);
        CHECK(hex_eq(e1, 32, v->exps[i].value));
        CHECK(hex_eq(e2, 32, v->exps[i].value));
    }

    pq_hpke_free(s);
    pq_hpke_free(r);
}

static void test_rfc9180_vectors(void) {
    for (size_t i = 0; i < sizeof(kats) / sizeof(kats[0]); i++) {
        int before = g_failures;
        run_kat(&kats[i]);
        if (g_failures == before) PASS(kats[i].name);
    }
}

/* ------------------------------------------------------------------------ */
/* Round trips                                                              */
/* ------------------------------------------------------------------------ */

typedef struct {
    pq_hpke_t *s, *r;
    uint8_t *pk, *sk, *enc;
    size_t pk_len, sk_len, enc_len;
} pair_t;

static void pair_free(pair_t *p) {
    pq_hpke_free(p->s);
    pq_hpke_free(p->r);
    free(p->pk); free(p->sk); free(p->enc);
    memset(p, 0, sizeof(*p));
}

/* keygen + SetupBaseS + SetupBaseR (recipient info may differ) */
static int pair_setup(pair_t *p, int kem, int aead,
                      const char *info_s, const char *info_r) {
    memset(p, 0, sizeof(*p));
    p->pk_len = pq_hpke_publickey_bytes(kem);
    p->sk_len = pq_hpke_secretkey_bytes(kem);
    size_t enc_cap = pq_hpke_encapsulated_bytes(kem);
    p->s = pq_hpke_init(kem, aead);
    p->r = pq_hpke_init(kem, aead);
    p->pk = malloc(p->pk_len);
    p->sk = malloc(p->sk_len);
    p->enc = malloc(enc_cap);
    if (!p->s || !p->r || !p->pk || !p->sk || !p->enc) return -1;
    if (pq_hpke_keygen(p->r, p->pk, p->pk_len, p->sk, p->sk_len) != PQ_SUCCESS) return -1;
    if (pq_hpke_setup_base_sender(p->s, p->enc, enc_cap, &p->enc_len, p->pk, p->pk_len,
                                  (const uint8_t *)info_s, strlen(info_s)) != PQ_SUCCESS)
        return -1;
    if (p->enc_len != enc_cap) return -1;
    return pq_hpke_setup_base_recipient(p->r, p->enc, p->enc_len, p->sk, p->sk_len,
                                        (const uint8_t *)info_r, strlen(info_r));
}

static void test_roundtrips(void) {
    static const int kems[] = { HPKE_KEM_X25519, HPKE_KEM_MLKEM768,
                                HPKE_KEM_X25519_MLKEM768_CONCAT };
    static const int aeads[] = { HPKE_AEAD_AES128GCM, HPKE_AEAD_AES256GCM,
                                 HPKE_AEAD_CHACHAPOLY };
    int before = g_failures;

    for (size_t k = 0; k < 3; k++) {
        for (size_t a = 0; a < 3; a++) {
            pair_t p;
            CHECK(pair_setup(&p, kems[k], aeads[a], "app info", "app info") == PQ_SUCCESS);
            for (int m = 0; m < 5 && p.s; m++) {
                uint8_t pt[100], ct[128], out[128];
                size_t pt_len = (size_t)(m * 20), ct_len = 0, out_len = 0;
                memset(pt, 0xA0 + m, sizeof(pt));
                const uint8_t aad[] = "header";
                CHECK(pq_hpke_seal(p.s, ct, sizeof(ct), &ct_len, pt_len ? pt : NULL, pt_len,
                                   m % 2 ? aad : NULL, m % 2 ? sizeof(aad) : 0) == PQ_SUCCESS);
                CHECK(ct_len == pt_len + HPKE_AEAD_TAG_BYTES);
                CHECK(pq_hpke_open(p.r, out, sizeof(out), &out_len, ct, ct_len,
                                   m % 2 ? aad : NULL, m % 2 ? sizeof(aad) : 0) == PQ_SUCCESS);
                CHECK(out_len == pt_len && memcmp(out, pt, pt_len) == 0);
            }
            uint8_t e1[48], e2[48];
            CHECK(pq_hpke_export(p.s, (const uint8_t *)"ctx", 3, e1, sizeof(e1)) == PQ_SUCCESS);
            CHECK(pq_hpke_export(p.r, (const uint8_t *)"ctx", 3, e2, sizeof(e2)) == PQ_SUCCESS);
            CHECK(memcmp(e1, e2, sizeof(e1)) == 0);
            pair_free(&p);
        }
    }
    if (g_failures == before) PASS("hpke round trips (3 KEMs x 3 AEADs)");
}

/* Same message twice must give different ciphertexts (nonce = base_nonce ^ seq) */
static void test_nonce_sequence(void) {
    int before = g_failures;
    pair_t p;
    CHECK(pair_setup(&p, HPKE_KEM_X25519, HPKE_AEAD_AES256GCM, "i", "i") == PQ_SUCCESS);
    if (p.s) {
        uint8_t pt[16] = { 0 }, c1[64], c2[64], out[64];
        size_t l1 = 0, l2 = 0, ol = 0;
        CHECK(pq_hpke_seal(p.s, c1, sizeof(c1), &l1, pt, sizeof(pt), NULL, 0) == PQ_SUCCESS);
        CHECK(pq_hpke_seal(p.s, c2, sizeof(c2), &l2, pt, sizeof(pt), NULL, 0) == PQ_SUCCESS);
        CHECK(l1 == l2 && memcmp(c1, c2, l1) != 0);
        /* Out-of-order open fails (seq 1 ciphertext at seq 0) */
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &ol, c2, l2, NULL, 0) == PQ_ERR_VERIFICATION_FAILED);
        /* ...and the failure did not advance the recipient's sequence number */
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &ol, c1, l1, NULL, 0) == PQ_SUCCESS);
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &ol, c2, l2, NULL, 0) == PQ_SUCCESS);
    }
    pair_free(&p);
    if (g_failures == before) PASS("hpke nonce = base_nonce XOR seq");
}

/* ------------------------------------------------------------------------ */
/* Hybrid KEM: both components contribute (regression for key = ss[0..32]) */
/* ------------------------------------------------------------------------ */

static int x25519_raw(const uint8_t *sk, const uint8_t *peer, uint8_t out[32], uint8_t pk_out[32]) {
    EVP_PKEY *self = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
    EVP_PKEY *other = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
    EVP_PKEY_CTX *ctx = self ? EVP_PKEY_CTX_new(self, NULL) : NULL;
    size_t len = 32, pk_len = 32;
    int ok = ctx && other && EVP_PKEY_derive_init(ctx) == 1 &&
             EVP_PKEY_derive_set_peer(ctx, other) == 1 &&
             EVP_PKEY_derive(ctx, out, &len) == 1 && len == 32 &&
             EVP_PKEY_get_raw_public_key(self, pk_out, &pk_len) == 1;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(self);
    EVP_PKEY_free(other);
    return ok;
}

static void test_hybrid_construction(void) {
    int before = g_failures;
    const int kem = HPKE_KEM_X25519_MLKEM768_CONCAT;
    pq_hpke_t *h = pq_hpke_init(kem, HPKE_AEAD_AES256GCM);
    uint8_t pk[HPKE_HYBRID_PUBLICKEY_BYTES], sk[HPKE_HYBRID_SECRETKEY_BYTES];
    uint8_t enc[HPKE_HYBRID_ENCAPSULATED_BYTES];
    uint8_t ss_enc[32], ss_dec[32], ss_x[32], ss_m[32], pk_x[32], expect[32];
    size_t enc_len = 0;

    CHECK(h != NULL);
    CHECK(pq_hpke_sharedsecret_bytes(kem) == 32);
    CHECK(pq_hpke_keygen(h, pk, sizeof(pk), sk, sizeof(sk)) == PQ_SUCCESS);
    CHECK(pq_hpke_encapsulate(h, enc, sizeof(enc), &enc_len, ss_enc, sizeof(ss_enc),
                              pk, sizeof(pk)) == PQ_SUCCESS);
    CHECK(enc_len == sizeof(enc));
    CHECK(pq_hpke_decapsulate(h, ss_dec, sizeof(ss_dec), enc, enc_len, sk, sizeof(sk)) == PQ_SUCCESS);
    CHECK(memcmp(ss_enc, ss_dec, 32) == 0);

    /* Independent recomputation:
     *   SHA3-256(ss_M || ss_X || ct_X || pk_X || "\.//^\") */
    CHECK(x25519_raw(sk, enc, ss_x, pk_x));
    CHECK(memcmp(pk_x, pk, 32) == 0);
    CHECK(pq_kem_decapsulate(PQ_KEM_MLKEM768, ss_m, enc + 32, sk + 32) == PQ_SUCCESS);
    static const uint8_t label[6] = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };
    unsigned int md_len = 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    CHECK(md && EVP_DigestInit_ex(md, EVP_sha3_256(), NULL) == 1 &&
          EVP_DigestUpdate(md, ss_m, 32) == 1 &&
          EVP_DigestUpdate(md, ss_x, 32) == 1 &&
          EVP_DigestUpdate(md, enc, 32) == 1 &&
          EVP_DigestUpdate(md, pk_x, 32) == 1 &&
          EVP_DigestUpdate(md, label, sizeof(label)) == 1 &&
          EVP_DigestFinal_ex(md, expect, &md_len) == 1 && md_len == 32);
    EVP_MD_CTX_free(md);
    CHECK(memcmp(expect, ss_enc, 32) == 0);
    /* The combined secret is neither component on its own */
    CHECK(memcmp(ss_enc, ss_x, 32) != 0);
    CHECK(memcmp(ss_enc, ss_m, 32) != 0);

    /* Tampering with ONLY the ML-KEM part (X25519 part unchanged) must change
     * the secret: ML-KEM implicit rejection yields a different ss_M. */
    enc[32 + 100] ^= 0x01;
    CHECK(pq_hpke_decapsulate(h, ss_dec, sizeof(ss_dec), enc, enc_len, sk, sizeof(sk)) == PQ_SUCCESS);
    CHECK(memcmp(ss_enc, ss_dec, 32) != 0);
    enc[32 + 100] ^= 0x01;

    /* Tampering with ONLY the X25519 part must change (or reject) the secret */
    enc[5] ^= 0x01;
    int rc = pq_hpke_decapsulate(h, ss_dec, sizeof(ss_dec), enc, enc_len, sk, sizeof(sk));
    CHECK(rc != PQ_SUCCESS || memcmp(ss_enc, ss_dec, 32) != 0);
    enc[5] ^= 0x01;

    pq_hpke_free(h);
    if (g_failures == before) PASS("hpke X-Wing-style hybrid: SHA3-256 combiner, both components bound");
}

/* ------------------------------------------------------------------------ */
/* Negative tests                                                           */
/* ------------------------------------------------------------------------ */

static void test_negative(void) {
    int before = g_failures;
    static const int kems[] = { HPKE_KEM_X25519, HPKE_KEM_MLKEM768,
                                HPKE_KEM_X25519_MLKEM768_CONCAT };

    for (size_t k = 0; k < 3; k++) {
        const int kem = kems[k];
        pair_t p;
        uint8_t pt[40], ct[64], out[64];
        size_t ct_len = 0, out_len = 0;
        memset(pt, 0x42, sizeof(pt));

        /* Tampered ciphertext / tag / wrong AAD / truncation */
        CHECK(pair_setup(&p, kem, HPKE_AEAD_AES256GCM, "info", "info") == PQ_SUCCESS);
        CHECK(pq_hpke_seal(p.s, ct, sizeof(ct), &ct_len, pt, sizeof(pt),
                           (const uint8_t *)"aad", 3) == PQ_SUCCESS);
        ct[3] ^= 0x80;
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &out_len, ct, ct_len,
                           (const uint8_t *)"aad", 3) == PQ_ERR_VERIFICATION_FAILED);
        ct[3] ^= 0x80;
        ct[ct_len - 1] ^= 0x01;   /* tag */
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &out_len, ct, ct_len,
                           (const uint8_t *)"aad", 3) == PQ_ERR_VERIFICATION_FAILED);
        ct[ct_len - 1] ^= 0x01;
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &out_len, ct, ct_len,
                           (const uint8_t *)"aaX", 3) == PQ_ERR_VERIFICATION_FAILED);
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &out_len, ct, ct_len - 1,
                           (const uint8_t *)"aad", 3) != PQ_SUCCESS);
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &out_len, ct, HPKE_AEAD_TAG_BYTES - 1,
                           (const uint8_t *)"aad", 3) == PQ_ERR_INVALID_FORMAT);
        /* Output capacity checks */
        CHECK(pq_hpke_open(p.r, out, sizeof(pt) - 1, &out_len, ct, ct_len,
                           (const uint8_t *)"aad", 3) == PQ_ERR_BUFFER_TOO_SMALL);
        /* Untampered still opens (failures did not advance seq) */
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &out_len, ct, ct_len,
                           (const uint8_t *)"aad", 3) == PQ_SUCCESS);
        CHECK(out_len == sizeof(pt) && memcmp(out, pt, sizeof(pt)) == 0);
        CHECK(pq_hpke_seal(p.s, ct, sizeof(pt) + HPKE_AEAD_TAG_BYTES - 1, &ct_len, pt, sizeof(pt),
                           NULL, 0) == PQ_ERR_BUFFER_TOO_SMALL);
        /* Role misuse */
        CHECK(pq_hpke_open(p.s, out, sizeof(out), &out_len, ct, ct_len, NULL, 0) != PQ_SUCCESS);
        CHECK(pq_hpke_seal(p.r, ct, sizeof(ct), &ct_len, pt, sizeof(pt), NULL, 0) != PQ_SUCCESS);
        /* Setting up an already set-up context is refused */
        size_t enc_len2 = 0;
        CHECK(pq_hpke_setup_base_sender(p.s, p.enc, p.enc_len, &enc_len2, p.pk, p.pk_len,
                                        NULL, 0) != PQ_SUCCESS);
        pair_free(&p);

        /* Different info on the two sides -> different keys -> open fails */
        CHECK(pair_setup(&p, kem, HPKE_AEAD_CHACHAPOLY, "info-A", "info-B") == PQ_SUCCESS);
        CHECK(pq_hpke_seal(p.s, ct, sizeof(ct), &ct_len, pt, sizeof(pt), NULL, 0) == PQ_SUCCESS);
        CHECK(pq_hpke_open(p.r, out, sizeof(out), &out_len, ct, ct_len, NULL, 0)
              == PQ_ERR_VERIFICATION_FAILED);
        pair_free(&p);

        /* Wrong recipient key -> open fails (or decap fails for the hybrid) */
        CHECK(pair_setup(&p, kem, HPKE_AEAD_AES128GCM, "i", "i") == PQ_SUCCESS);
        {
            pq_hpke_t *other = pq_hpke_init(kem, HPKE_AEAD_AES128GCM);
            uint8_t *pk2 = malloc(p.pk_len), *sk2 = malloc(p.sk_len);
            CHECK(other && pk2 && sk2);
            if (other && pk2 && sk2) {
                CHECK(pq_hpke_keygen(other, pk2, p.pk_len, sk2, p.sk_len) == PQ_SUCCESS);
                CHECK(pq_hpke_seal(p.s, ct, sizeof(ct), &ct_len, pt, sizeof(pt), NULL, 0)
                      == PQ_SUCCESS);
                int rc = pq_hpke_setup_base_recipient(other, p.enc, p.enc_len, sk2, p.sk_len,
                                                      (const uint8_t *)"i", 1);
                if (rc == PQ_SUCCESS)
                    CHECK(pq_hpke_open(other, out, sizeof(out), &out_len, ct, ct_len, NULL, 0)
                          == PQ_ERR_VERIFICATION_FAILED);
            }
            pq_hpke_free(other);
            free(pk2); free(sk2);
        }

        /* Exact-length checks on pk / enc / sk */
        {
            size_t enc_cap = pq_hpke_encapsulated_bytes(kem);
            uint8_t *big = calloc(1, p.sk_len + enc_cap + 8);
            uint8_t ss[32];
            size_t el = 0;
            pq_hpke_t *t = pq_hpke_init(kem, HPKE_AEAD_AES128GCM);
            CHECK(big && t);
            if (big && t) {
                CHECK(pq_hpke_encapsulate(t, big, enc_cap, &el, ss, sizeof(ss), p.pk, p.pk_len - 1)
                      == PQ_ERR_INVALID_PARAMETER);
                CHECK(pq_hpke_encapsulate(t, big, enc_cap, &el, ss, sizeof(ss), p.pk, p.pk_len + 1)
                      == PQ_ERR_INVALID_PARAMETER);
                CHECK(pq_hpke_encapsulate(t, big, enc_cap - 1, &el, ss, sizeof(ss), p.pk, p.pk_len)
                      == PQ_ERR_BUFFER_TOO_SMALL);
                CHECK(pq_hpke_decapsulate(t, ss, sizeof(ss), p.enc, p.enc_len + 1, p.sk, p.sk_len)
                      == PQ_ERR_INVALID_PARAMETER);
                CHECK(pq_hpke_decapsulate(t, ss, sizeof(ss), p.enc, p.enc_len - 1, p.sk, p.sk_len)
                      == PQ_ERR_INVALID_PARAMETER);
                CHECK(pq_hpke_decapsulate(t, ss, sizeof(ss), p.enc, p.enc_len, p.sk, p.sk_len + 1)
                      == PQ_ERR_INVALID_PARAMETER);
                CHECK(pq_hpke_setup_base_recipient(t, p.enc, p.enc_len, p.sk, p.sk_len - 1, NULL, 0)
                      == PQ_ERR_INVALID_PARAMETER);
            }
            pq_hpke_free(t);
            free(big);
        }
        pair_free(&p);
    }

    /* Unsupported / misuse */
    CHECK(pq_hpke_init(0x9999, HPKE_AEAD_AES128GCM) == NULL);
    CHECK(pq_hpke_init(HPKE_KEM_X25519, 0x0099) == NULL);
    {
        pq_hpke_t *h = pq_hpke_init(HPKE_KEM_MLKEM768, HPKE_AEAD_AES128GCM);
        uint8_t ikm[32] = { 1 }, pk[HPKE_MLKEM768_PUBLICKEY_BYTES], enc[HPKE_MLKEM768_ENCAPSULATED_BYTES];
        uint8_t out[32];
        size_t enc_len = 0;
        memset(pk, 0, sizeof(pk));
        CHECK(pq_hpke_setup_base_sender_derand(h, ikm, sizeof(ikm), enc, sizeof(enc), &enc_len,
                                               pk, sizeof(pk), NULL, 0) == PQ_ERR_UNSUPPORTED_ALGORITHM);
        CHECK(pq_hpke_export(h, NULL, 0, out, sizeof(out)) != PQ_SUCCESS);  /* not set up */
        pq_hpke_free(h);
    }
    /* X25519 low-order point as enc is rejected (all-zero DH, RFC 9180 7.1.4) */
    {
        pq_hpke_t *h = pq_hpke_init(HPKE_KEM_X25519, HPKE_AEAD_AES128GCM);
        uint8_t pk[32], sk[32], zero[32] = { 0 };
        CHECK(pq_hpke_keygen(h, pk, sizeof(pk), sk, sizeof(sk)) == PQ_SUCCESS);
        CHECK(pq_hpke_setup_base_recipient(h, zero, sizeof(zero), sk, sizeof(sk), NULL, 0)
              != PQ_SUCCESS);
        pq_hpke_free(h);
    }

    if (g_failures == before) PASS("hpke negative tests (tamper, wrong key/info/aad, lengths, misuse)");
}

int run_crypto_hpke_tests(void) {
    g_failures = 0;
    test_rfc9180_vectors();
    test_roundtrips();
    test_nonce_sequence();
    test_hybrid_construction();
    test_negative();
    return g_failures == 0 ? 0 : 1;
}
