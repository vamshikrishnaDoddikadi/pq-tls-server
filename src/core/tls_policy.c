/**
 * @file tls_policy.c
 * @brief TLS key-exchange group policy: probing, filtering and PQ detection
 * @author Vamshi Krishna Doddikadi
 */

#include "tls_policy.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Substrings (lower-case) that identify post-quantum KEM groups as named by
 * OpenSSL >= 3.5 and by oqs-provider. */
static const char *const pq_markers[] = {
    "mlkem", "kyber", "frodo", "bike", "hqc", "mceliece", NULL
};

static int contains_ci(const char *haystack, const char *needle) {
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        if (strncasecmp(p, needle, nlen) == 0) return 1;
    }
    return 0;
}

int pq_tls_group_is_pq(const char *group_name) {
    if (!group_name || !group_name[0]) return 0;
    for (int i = 0; pq_markers[i]; i++) {
        if (contains_ci(group_name, pq_markers[i])) return 1;
    }
    return 0;
}

/* Copy the next group token from *p into tok, advancing *p past it.
 * Tokens are separated by ':' (and '/' for OpenSSL 3.5 tuples); leading
 * '?' (optional) and '*' (key-share) markers are stripped.
 * Returns 0 when the list is exhausted. */
static int next_token(const char **p, char *tok, size_t tok_len) {
    const char *s = *p;
    while (*s == ':' || *s == '/' || isspace((unsigned char)*s)) s++;
    if (!*s) { *p = s; return 0; }

    const char *start = s;
    while (*s && *s != ':' && *s != '/') s++;
    const char *end = s;
    while (end > start && isspace((unsigned char)end[-1])) end--;
    while (start < end && (*start == '?' || *start == '*')) start++;

    size_t len = (size_t)(end - start);
    if (len >= tok_len) len = tok_len - 1;
    memcpy(tok, start, len);
    tok[len] = '\0';
    *p = s;
    return 1;
}

int pq_tls_groups_have_pq(const char *groups) {
    if (!groups) return 0;
    char tok[128];
    const char *p = groups;
    while (next_token(&p, tok, sizeof(tok))) {
        if (pq_tls_group_is_pq(tok)) return 1;
    }
    return 0;
}

/* OpenSSL accepts several names for the NIST curves. Map them to one
 * canonical spelling so aliases compare equal on every OpenSSL version
 * (3.0 rejects a list containing an alias twice, 3.5+ silently drops it).
 * Hybrid/PQ group names have no aliases; names compare case-insensitively. */
static const char *canonical_group(const char *name) {
    static const char *const aliases[][2] = {
        { "prime256v1", "secp256r1" }, { "P-256", "secp256r1" },
        { "P-384", "secp384r1" },      { "P-521", "secp521r1" },
        { "prime192v1", "secp192r1" }, { "P-192", "secp192r1" },
        { "P-224", "secp224r1" },
    };
    for (size_t i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++) {
        if (strcasecmp(name, aliases[i][0]) == 0) return aliases[i][1];
    }
    return name;
}

#define MAX_TRACKED_GROUPS 64

static int group_seen(char seen[][128], int n, const char *name) {
    const char *c = canonical_group(name);
    for (int i = 0; i < n; i++) {
        if (strcasecmp(seen[i], c) == 0) return 1;
    }
    return 0;
}

static void group_remember(char seen[][128], int *n, const char *name) {
    if (*n >= MAX_TRACKED_GROUPS) return;
    snprintf(seen[*n], 128, "%s", canonical_group(name));
    (*n)++;
}

/* 1 if the list names the same group twice. */
static int has_duplicate_groups(const char *list) {
    char seen[MAX_TRACKED_GROUPS][128];
    int n = 0;
    char tok[128];
    const char *p = list;
    while (next_token(&p, tok, sizeof(tok))) {
        if (group_seen(seen, n, tok)) return 1;
        group_remember(seen, &n, tok);
    }
    return 0;
}

static void append_list(char *buf, size_t len, const char *item) {
    if (!buf || len == 0) return;
    size_t used = strlen(buf);
    if (used + (used ? 1 : 0) + strlen(item) >= len) return;
    if (used) buf[used++] = ':';
    memcpy(buf + used, item, strlen(item) + 1);
}

int pq_tls_resolve_groups(const char *requested, int pq_only,
                          char *out, size_t out_len,
                          char *dropped, size_t dropped_len) {
    if (!requested || !out || out_len == 0) return -1;
    out[0] = '\0';
    if (dropped && dropped_len) dropped[0] = '\0';

    SSL_CTX *probe = SSL_CTX_new(TLS_server_method());
    if (!probe) { ERR_clear_error(); return -1; }

    int count = 0;
    char tok[128];
    const char *p;

    /* Fast path: the whole list is valid and nothing needs filtering. */
    if (!pq_only && requested[0] && strlen(requested) < out_len &&
        SSL_CTX_set1_groups_list(probe, requested) == 1 &&
        !has_duplicate_groups(requested)) {
        memcpy(out, requested, strlen(requested) + 1);
        p = requested;
        while (next_token(&p, tok, sizeof(tok))) count++;
        SSL_CTX_free(probe);
        ERR_clear_error();
        return count;
    }

    char *candidate = malloc(out_len);
    if (!candidate) { SSL_CTX_free(probe); return -1; }

    char kept[MAX_TRACKED_GROUPS][128];
    int nkept = 0;
    p = requested;
    while (next_token(&p, tok, sizeof(tok))) {
        if (!tok[0]) continue;

        if (pq_only && !pq_tls_group_is_pq(tok)) {
            append_list(dropped, dropped_len, tok);
            continue;
        }
        /* Unsupported by the loaded providers (or unknown name), or an
         * alias of a group already in the list. */
        if (SSL_CTX_set1_groups_list(probe, tok) != 1 || group_seen(kept, nkept, tok) ||
            nkept >= MAX_TRACKED_GROUPS) {
            append_list(dropped, dropped_len, tok);
            continue;
        }
        /* The combined list must remain acceptable to OpenSSL. */
        int n = snprintf(candidate, out_len, "%s%s%s",
                         out, out[0] ? ":" : "", tok);
        if (n < 0 || (size_t)n >= out_len ||
            SSL_CTX_set1_groups_list(probe, candidate) != 1) {
            append_list(dropped, dropped_len, tok);
            continue;
        }
        memcpy(out, candidate, (size_t)n + 1);
        group_remember(kept, &nkept, tok);
        count++;
    }

    free(candidate);
    SSL_CTX_free(probe);
    /* Probing failures leave entries on this thread's error queue. */
    ERR_clear_error();
    return count;
}

const char *pq_tls_negotiated_group(SSL *ssl) {
    if (!ssl) return "unknown";
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    const char *name = SSL_get0_group_name(ssl);
    if (name) return name;
#endif
    int gid = SSL_get_negotiated_group(ssl);
    if (gid == 0 || gid == NID_undef) return "unknown";
    const char *n = SSL_group_to_name(ssl, gid);
    return n ? n : "unknown";
}

int pq_tls_alpn_select_http1(SSL *ssl, const unsigned char **out,
                             unsigned char *outlen, const unsigned char *in,
                             unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    static const unsigned char server_protos[] = "\x08http/1.1\x08http/1.0";
    unsigned char *sel = NULL;
    unsigned char sel_len = 0;

    if (!in || inlen == 0) return SSL_TLSEXT_ERR_NOACK;
    if (SSL_select_next_proto(&sel, &sel_len, server_protos,
                              sizeof(server_protos) - 1, in, inlen)
            != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    *out = sel;
    *outlen = sel_len;
    return SSL_TLSEXT_ERR_OK;
}
