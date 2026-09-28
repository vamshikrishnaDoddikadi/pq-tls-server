/**
 * @file tls_policy.h
 * @brief TLS key-exchange group policy: probing, filtering and PQ detection
 *
 * The configured group list is resolved against what the loaded OpenSSL
 * providers actually support *before* it is applied to an SSL_CTX, so a
 * single unknown or duplicate name can no longer make OpenSSL reject the
 * whole list and silently fall back to its (classical-only) defaults.
 *
 * @author Vamshi Krishna Doddikadi
 */

#ifndef PQ_TLS_POLICY_H
#define PQ_TLS_POLICY_H

#include <openssl/ssl.h>
#include <stddef.h>

/**
 * Return 1 if @p group_name denotes a post-quantum or hybrid PQ key
 * exchange (ML-KEM, Kyber, FrodoKEM, BIKE, HQC, Classic McEliece), else 0.
 * Matching is case-insensitive, so "X25519MLKEM768", "SecP256r1MLKEM768",
 * "mlkem768" and "p256_frodo640aes" are all recognised.
 */
int pq_tls_group_is_pq(const char *group_name);

/**
 * Return 1 if the colon-separated group list contains at least one PQ group.
 */
int pq_tls_groups_have_pq(const char *groups);

/**
 * Resolve a colon-separated TLS group list against the currently loaded
 * OpenSSL providers.
 *
 *  - Groups the providers do not support are dropped.
 *  - Aliases of a group already in the list (e.g. "P-256" after
 *    "prime256v1") are dropped.
 *  - With @p pq_only set, classical groups are dropped as well.
 *
 * OpenSSL >= 3.5 tuple syntax ("a/b:c") and "?"/"*" prefixes are accepted;
 * when the list is valid as-is and @p pq_only is not set it is kept
 * verbatim so the operator's key-share preferences are preserved.
 *
 * @param requested   group list to resolve (may be empty)
 * @param pq_only     1 = keep only post-quantum groups
 * @param out         receives the resolved list ("" if nothing usable)
 * @param out_len     size of @p out
 * @param dropped     optional; receives the groups that were removed
 * @param dropped_len size of @p dropped (0 if @p dropped is NULL)
 * @return number of groups in @p out, or -1 on internal error.
 */
int pq_tls_resolve_groups(const char *requested, int pq_only,
                          char *out, size_t out_len,
                          char *dropped, size_t dropped_len);

/**
 * Name of the key-exchange group negotiated on an established connection.
 * Never returns NULL ("unknown" if it cannot be determined).
 */
const char *pq_tls_negotiated_group(SSL *ssl);

/**
 * ALPN selection callback for HTTP/1.x proxying (RFC 7301).
 * Selects "http/1.1" (or "http/1.0"). A client that offers ALPN but none of
 * those protocols is rejected with no_application_protocol, which prevents
 * cross-protocol attacks such as ALPACA.
 */
int pq_tls_alpn_select_http1(SSL *ssl, const unsigned char **out,
                             unsigned char *outlen, const unsigned char *in,
                             unsigned int inlen, void *arg);

#endif /* PQ_TLS_POLICY_H */
