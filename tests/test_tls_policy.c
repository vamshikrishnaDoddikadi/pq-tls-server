/*
 * test_tls_policy.c - Tests for TLS group resolution and PQ detection
 *
 * The test binary loads only OpenSSL's built-in providers, so assertions are
 * written to hold both on OpenSSL 3.0-3.4 (no native ML-KEM) and on 3.5+
 * (native X25519MLKEM768).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

#include "../src/core/tls_policy.h"

#define TEST(name) static void name(void)
#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)
#define PASS(name) printf("PASS: %s\n", name)

static int list_has(const char *list, const char *name) {
    size_t n = strlen(name);
    for (const char *p = list; p && *p; ) {
        const char *e = strchr(p, ':');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len == n && strncmp(p, name, n) == 0) return 1;
        p = e ? e + 1 : NULL;
    }
    return 0;
}

static int list_count(const char *list) {
    if (!list[0]) return 0;
    int n = 1;
    for (const char *p = list; *p; p++) if (*p == ':') n++;
    return n;
}

TEST(test_group_is_pq) {
    ASSERT(pq_tls_group_is_pq("X25519MLKEM768"));
    ASSERT(pq_tls_group_is_pq("SecP256r1MLKEM768"));
    ASSERT(pq_tls_group_is_pq("mlkem1024"));
    ASSERT(pq_tls_group_is_pq("x25519_kyber768"));
    ASSERT(pq_tls_group_is_pq("p256_frodo640aes"));
    ASSERT(pq_tls_group_is_pq("hqc192"));
    ASSERT(!pq_tls_group_is_pq("X25519"));
    ASSERT(!pq_tls_group_is_pq("secp384r1"));
    ASSERT(!pq_tls_group_is_pq("P-256"));
    ASSERT(!pq_tls_group_is_pq(""));
    ASSERT(!pq_tls_group_is_pq(NULL));

    ASSERT(pq_tls_groups_have_pq("X25519:?X25519MLKEM768"));
    ASSERT(pq_tls_groups_have_pq("*X25519MLKEM768/X25519:P-256"));
    ASSERT(!pq_tls_groups_have_pq("X25519:P-256"));
    PASS("test_group_is_pq");
}

TEST(test_resolve_drops_unknown_and_aliases) {
    char out[512], dropped[512];
    /* This exact list (from the crypto registry) used to be rejected as a
     * whole by OpenSSL because P-256 == prime256v1, silently disabling PQ. */
    int n = pq_tls_resolve_groups("X25519MLKEM768:X25519:prime256v1:P-256:bogus-group",
                                  0, out, sizeof(out), dropped, sizeof(dropped));
    ASSERT(n >= 2);
    ASSERT(n == list_count(out));
    ASSERT(list_has(out, "X25519"));
    ASSERT(list_has(out, "prime256v1"));
    ASSERT(!list_has(out, "P-256"));          /* alias of prime256v1 */
    ASSERT(!list_has(out, "bogus-group"));
    ASSERT(list_has(dropped, "bogus-group"));
    ASSERT(list_has(dropped, "P-256"));

    /* whatever was kept must be accepted by OpenSSL as a whole */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    ASSERT(ctx);
    ASSERT(SSL_CTX_set1_groups_list(ctx, out) == 1);
    SSL_CTX_free(ctx);
    PASS("test_resolve_drops_unknown_and_aliases");
}

TEST(test_resolve_verbatim_when_valid) {
    char out[256];
    int n = pq_tls_resolve_groups("X25519:P-256:secp384r1", 0, out, sizeof(out), NULL, 0);
    ASSERT(n == 3);
    ASSERT(strcmp(out, "X25519:P-256:secp384r1") == 0);
    /* aliases are removed even where OpenSSL itself would accept them */
    n = pq_tls_resolve_groups("secp256r1:X25519:P-256", 0, out, sizeof(out), NULL, 0);
    ASSERT(n == 2);
    ASSERT(strcmp(out, "secp256r1:X25519") == 0);
    PASS("test_resolve_verbatim_when_valid");
}

TEST(test_resolve_pq_only) {
    char out[256], dropped[256];
    int n = pq_tls_resolve_groups("X25519MLKEM768:X25519:P-256", 1, out, sizeof(out),
                                  dropped, sizeof(dropped));
    ASSERT(n >= 0);
    ASSERT(!list_has(out, "X25519"));
    ASSERT(!list_has(out, "P-256"));
    ASSERT(list_has(dropped, "X25519"));
    if (n > 0) ASSERT(pq_tls_groups_have_pq(out));
    PASS("test_resolve_pq_only");
}

TEST(test_resolve_empty_and_errors) {
    char out[64];
    ASSERT(pq_tls_resolve_groups("", 0, out, sizeof(out), NULL, 0) == 0);
    ASSERT(out[0] == '\0');
    ASSERT(pq_tls_resolve_groups("nope:also-nope", 0, out, sizeof(out), NULL, 0) == 0);
    ASSERT(pq_tls_resolve_groups(NULL, 0, out, sizeof(out), NULL, 0) == -1);
    ASSERT(pq_tls_resolve_groups("X25519", 0, NULL, 0, NULL, 0) == -1);
    PASS("test_resolve_empty_and_errors");
}

TEST(test_alpn_select) {
    const unsigned char *sel = NULL;
    unsigned char sel_len = 0;
    static const unsigned char both[] = "\x02h2\x08http/1.1";
    static const unsigned char h2_only[] = "\x02h2";

    ASSERT(pq_tls_alpn_select_http1(NULL, &sel, &sel_len, both, sizeof(both) - 1, NULL)
           == SSL_TLSEXT_ERR_OK);
    ASSERT(sel_len == 8 && memcmp(sel, "http/1.1", 8) == 0);
    ASSERT(pq_tls_alpn_select_http1(NULL, &sel, &sel_len, h2_only, sizeof(h2_only) - 1, NULL)
           == SSL_TLSEXT_ERR_ALERT_FATAL);
    ASSERT(pq_tls_alpn_select_http1(NULL, &sel, &sel_len, both, 0, NULL)
           == SSL_TLSEXT_ERR_NOACK);
    PASS("test_alpn_select");
}

int run_tls_policy_tests(void) {
    test_group_is_pq();
    test_resolve_drops_unknown_and_aliases();
    test_resolve_verbatim_when_valid();
    test_resolve_pq_only();
    test_resolve_empty_and_errors();
    test_alpn_select();
    return 0;
}
