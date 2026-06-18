/**
 * @file mgmt_auth.h
 * @brief Management API authentication — PBKDF2 passwords + session tokens
 */

#ifndef PQ_MGMT_AUTH_H
#define PQ_MGMT_AUTH_H

#include "../core/server_config.h"

#define MGMT_MAX_SESSIONS    16
#define MGMT_TOKEN_BYTES     32
#define MGMT_TOKEN_HEX_LEN   64   /* 32 bytes * 2 hex chars */
#define MGMT_SESSION_TTL_SEC 1800  /* 30 minutes */

/* TOTP 2FA (RFC 6238) */
#define MGMT_TOTP_SECRET_BYTES 20   /* HMAC-SHA1 key size */
#define MGMT_TOTP_BASE32_LEN   32   /* ceil(20*8/5) = 32 */
#define MGMT_TOTP_PERIOD       30   /* 30-second time step */
#define MGMT_TOTP_DIGITS       6    /* 6-digit code */
#define MGMT_TOTP_WINDOW        1    /* ±1 step tolerance for clock skew */

/**
 * Initialize the auth subsystem.
 */
void mgmt_auth_init(void);

/**
 * Hash a password using PBKDF2-SHA256 (via OpenSSL).
 * Returns hex-encoded hash in out (must be >= 128 bytes).
 * @return 0 on success, -1 on error.
 */
int mgmt_auth_hash_password(const char *password, char *out, size_t out_size);

/**
 * Verify a password against a stored PBKDF2 hash.
 * @return 1 if matches, 0 if not.
 */
int mgmt_auth_verify_password(const char *password, const char *stored_hash);

/**
 * Create a new session, returning a hex token.
 * @return 0 on success (token written to out), -1 on error.
 */
int mgmt_auth_create_session(const char *username, char *token_out);

/**
 * Validate a session token. Extends the session expiry on success.
 * @return 1 if valid, 0 if invalid/expired.
 */
int mgmt_auth_validate_session(const char *token);

/**
 * Destroy a session by token.
 */
void mgmt_auth_destroy_session(const char *token);

/**
 * Check if initial setup is needed (no admin credentials configured).
 */
int mgmt_auth_needs_setup(const pq_server_config_t *cfg);

/**
 * Generate a new TOTP secret (20 random bytes → base32 string).
 * The caller should display this to the admin for entry into their
 * authenticator app (Google Authenticator, Authy, etc.).
 * @param out  Buffer of at least MGMT_TOTP_BASE32_LEN + 1 bytes.
 * @return 0 on success, -1 on error.
 */
int mgmt_auth_totp_generate_secret(char *out, size_t out_size);

/**
 * Verify a TOTP code against a stored base32 secret.
 * Implements RFC 6238 with HMAC-SHA1, 6-digit codes, 30-second steps.
 * Accepts codes from ±1 time window to tolerate minor clock skew.
 * @param code        6-digit code as null-terminated string
 * @param secret_b32  Base32-encoded secret
 * @return 1 if valid, 0 if invalid.
 */
int mgmt_auth_totp_verify(const char *code, const char *secret_b32);

/**
 * Check if TOTP 2FA is configured.
 */
int mgmt_auth_is_totp_enabled(const pq_server_config_t *cfg);

/**
 * Clean up all sessions.
 */
void mgmt_auth_cleanup(void);
/* ── Login rate limiter (C-1 fix) ────────────────────────────────── */
#define MGMT_LOGIN_MAX_ATTEMPTS   5    /* max failures before lockout */
#define MGMT_LOGIN_WINDOW_SEC    60    /* tracking window */
#define MGMT_LOGIN_LOCKOUT_SEC  300    /* lockout duration */
#define MGMT_LOGIN_ESCALATED_SEC 900   /* escalated lockout after 10 failures */

/**
 * Check if a login attempt from this IP should be allowed.
 * Also records the attempt for rate limiting.
 * @param ip       Client IP address
 * @param success  1 if login succeeded, 0 if failed
 * @return 1 if allowed, 0 if rate-limited
 */
int mgmt_auth_login_rate_check(const char *ip, int success);

/* ── TOTP replay protection (H-6 fix) ───────────────────────────── */

/**
 * Check TOTP code with replay protection.
 * Same as mgmt_auth_totp_verify but rejects replayed codes.
 */
int mgmt_auth_totp_verify_nr(const char *code, const char *secret_b32);

/* ── Audit logging (M-13 fix) ───────────────────────────────────── */

/**
 * Log an authentication event.
 * @param ip        Client IP
 * @param username  Attempted username
 * @param event     "LOGIN_SUCCESS", "LOGIN_FAIL", "LOGIN_BLOCKED", "TOTP_FAIL"
 */
void mgmt_auth_audit_log(const char *ip, const char *username, const char *event);

#endif /* PQ_MGMT_AUTH_H */
