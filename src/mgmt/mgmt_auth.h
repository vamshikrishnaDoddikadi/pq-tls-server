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
 * Clean up all sessions.
 */
void mgmt_auth_cleanup(void);

#endif /* PQ_MGMT_AUTH_H */
