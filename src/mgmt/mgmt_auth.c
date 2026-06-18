/**
 * @file mgmt_auth.c
 * @brief PBKDF2-SHA256 password hashing and session token management
 */

#include "mgmt_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#define PBKDF2_ITERATIONS  600000
#define PBKDF2_SALT_LEN    16
#define PBKDF2_KEY_LEN     32

typedef struct {
    char     token[MGMT_TOKEN_HEX_LEN + 1];
    char     username[64];
    time_t   created_at;
    time_t   last_active;
} mgmt_session_t;

static struct {
    mgmt_session_t sessions[MGMT_MAX_SESSIONS];
    pthread_mutex_t mutex;
    int             initialized;
} auth;

static void hex_encode(const unsigned char *in, size_t in_len, char *out) {
    for (size_t i = 0; i < in_len; i++) {
        sprintf(out + i * 2, "%02x", in[i]);
    }
    out[in_len * 2] = '\0';
}

static int hex_decode(const char *in, unsigned char *out, size_t out_max) {
    /* SECURITY: Validate input parameters and hex character format explicitly */
    if (!in || !out || out_max == 0) return -1;

    size_t in_len = strlen(in);
    if (in_len == 0 || in_len % 2 != 0 || in_len / 2 > out_max) return -1;

    /* Validate each character is valid hex before attempting decode */
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return -1;
        }
    }

    /* Decode hex string to bytes */
    for (size_t i = 0; i < in_len / 2; i++) {
        unsigned int byte;
        if (sscanf(in + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return (int)(in_len / 2);
}

void mgmt_auth_init(void) {
    memset(&auth, 0, sizeof(auth));
    pthread_mutex_init(&auth.mutex, NULL);
    auth.initialized = 1;
}

int mgmt_auth_hash_password(const char *password, char *out, size_t out_size) {
    if (!password || !out || out_size < 128) return -1;

    unsigned char salt[PBKDF2_SALT_LEN];
    if (RAND_bytes(salt, PBKDF2_SALT_LEN) != 1) return -1;

    unsigned char derived[PBKDF2_KEY_LEN];
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           salt, PBKDF2_SALT_LEN,
                           PBKDF2_ITERATIONS, EVP_sha256(),
                           PBKDF2_KEY_LEN, derived) != 1) {
        return -1;
    }

    /* Format: iterations$salt_hex$key_hex */
    char salt_hex[PBKDF2_SALT_LEN * 2 + 1];
    char key_hex[PBKDF2_KEY_LEN * 2 + 1];
    hex_encode(salt, PBKDF2_SALT_LEN, salt_hex);
    hex_encode(derived, PBKDF2_KEY_LEN, key_hex);

    snprintf(out, out_size, "%d$%s$%s", PBKDF2_ITERATIONS, salt_hex, key_hex);
    return 0;
}

int mgmt_auth_verify_password(const char *password, const char *stored_hash) {
    if (!password || !stored_hash) return 0;

    /* Parse: iterations$salt_hex$key_hex */
    int iterations = 0;
    char salt_hex[64] = {0}, key_hex[128] = {0};

    /* Find first $ */
    const char *p1 = strchr(stored_hash, '$');
    if (!p1) return 0;
    {
        char *endptr = NULL;
        long itmp = strtol(stored_hash, &endptr, 10);
        if (*endptr != '\0' || itmp <= 0) return 0;
        iterations = (int)itmp;
    }

    const char *p2 = strchr(p1 + 1, '$');
    if (!p2) return 0;

    size_t salt_hex_len = (size_t)(p2 - p1 - 1);
    if (salt_hex_len >= sizeof(salt_hex)) return 0;
    memcpy(salt_hex, p1 + 1, salt_hex_len);
    salt_hex[salt_hex_len] = '\0';

    size_t key_hex_len = strlen(p2 + 1);
    if (key_hex_len >= sizeof(key_hex)) return 0;
    memcpy(key_hex, p2 + 1, key_hex_len);
    key_hex[key_hex_len] = '\0';

    /* Decode salt */
    unsigned char salt[PBKDF2_SALT_LEN];
    int salt_len = hex_decode(salt_hex, salt, sizeof(salt));
    if (salt_len <= 0) return 0;

    /* Decode stored key */
    unsigned char stored_key[PBKDF2_KEY_LEN];
    int key_len = hex_decode(key_hex, stored_key, sizeof(stored_key));
    if (key_len <= 0) return 0;

    /* Derive key from password with same salt */
    unsigned char derived[PBKDF2_KEY_LEN];
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           salt, salt_len,
                           iterations, EVP_sha256(),
                           key_len, derived) != 1) {
        return 0;
    }

    /* Constant-time comparison */
    return CRYPTO_memcmp(derived, stored_key, (size_t)key_len) == 0 ? 1 : 0;
}

int mgmt_auth_create_session(const char *username, char *token_out) {
    if (!auth.initialized || !username || !token_out) return -1;

    unsigned char token_bytes[MGMT_TOKEN_BYTES];
    if (RAND_bytes(token_bytes, MGMT_TOKEN_BYTES) != 1) return -1;

    char token_hex[MGMT_TOKEN_HEX_LEN + 1];
    hex_encode(token_bytes, MGMT_TOKEN_BYTES, token_hex);

    pthread_mutex_lock(&auth.mutex);

    /* Find empty or oldest slot */
    int slot = -1;
    time_t oldest = 0;
    int oldest_idx = 0;
    int found_oldest = 0;

    for (int i = 0; i < MGMT_MAX_SESSIONS; i++) {
        if (auth.sessions[i].token[0] == '\0') {
            slot = i;
            break;
        }
        if (!found_oldest || auth.sessions[i].last_active < oldest) {
            oldest = auth.sessions[i].last_active;
            oldest_idx = i;
            found_oldest = 1;
        }
    }

    if (slot < 0) slot = oldest_idx; /* Evict oldest */

    mgmt_session_t *s = &auth.sessions[slot];
    memcpy(s->token, token_hex, MGMT_TOKEN_HEX_LEN + 1);
    snprintf(s->username, sizeof(s->username), "%s", username);
    s->username[sizeof(s->username) - 1] = '\0';
    s->created_at = time(NULL);
    s->last_active = s->created_at;

    pthread_mutex_unlock(&auth.mutex);

    memcpy(token_out, token_hex, MGMT_TOKEN_HEX_LEN + 1);
    return 0;
}

int mgmt_auth_validate_session(const char *token) {
    if (!auth.initialized || !token || strlen(token) != MGMT_TOKEN_HEX_LEN)
        return 0;

    pthread_mutex_lock(&auth.mutex);
    time_t now = time(NULL);
    int valid = 0;

    for (int i = 0; i < MGMT_MAX_SESSIONS; i++) {
        mgmt_session_t *s = &auth.sessions[i];
        if (s->token[0] == '\0') continue;

        /* Check expiry */
        if (now - s->last_active > MGMT_SESSION_TTL_SEC) {
            memset(s, 0, sizeof(*s));
            continue;
        }

        if (CRYPTO_memcmp(s->token, token, MGMT_TOKEN_HEX_LEN) == 0) {
            s->last_active = now; /* Sliding expiry */
            valid = 1;
            break;
        }
    }

    pthread_mutex_unlock(&auth.mutex);
    return valid;
}

void mgmt_auth_destroy_session(const char *token) {
    if (!auth.initialized || !token) return;

    pthread_mutex_lock(&auth.mutex);
    for (int i = 0; i < MGMT_MAX_SESSIONS; i++) {
        if (auth.sessions[i].token[0] &&
            CRYPTO_memcmp(auth.sessions[i].token, token, MGMT_TOKEN_HEX_LEN) == 0) {
            memset(&auth.sessions[i], 0, sizeof(auth.sessions[i]));
            break;
        }
    }
    pthread_mutex_unlock(&auth.mutex);
}

int mgmt_auth_needs_setup(const pq_server_config_t *cfg) {
    return (cfg->mgmt_admin_user[0] == '\0' || cfg->mgmt_admin_pass_hash[0] == '\0');
}

/* ========================================================================
 * TOTP 2FA — RFC 6238 (HMAC-SHA1, 6-digit, 30-second time step)
 * ======================================================================== */

static const char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int base32_decode(const char *in, unsigned char *out, size_t out_max) {
    size_t in_len = strlen(in);
    size_t bitbuf = 0;
    int bitcount = 0;
    size_t out_pos = 0;

    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '=') break; /* padding */
        const char *p = strchr(BASE32_ALPHABET, c);
        if (!p) return -1;
        bitbuf = (bitbuf << 5) | (unsigned int)(p - BASE32_ALPHABET);
        bitcount += 5;
        if (bitcount >= 8) {
            bitcount -= 8;
            if (out_pos >= out_max) return -1;
            out[out_pos++] = (unsigned char)(bitbuf >> bitcount);
        }
    }
    return (int)out_pos;
}

static void base32_encode(const unsigned char *in, size_t in_len, char *out) {
    size_t bitbuf = 0;
    int bitcount = 0;
    size_t out_pos = 0;
    for (size_t i = 0; i < in_len; i++) {
        bitbuf = (bitbuf << 8) | in[i];
        bitcount += 8;
        while (bitcount >= 5) {
            bitcount -= 5;
            out[out_pos++] = BASE32_ALPHABET[(bitbuf >> bitcount) & 0x1F];
        }
    }
    if (bitcount > 0) {
        out[out_pos++] = BASE32_ALPHABET[(bitbuf << (5 - bitcount)) & 0x1F];
    }
    out[out_pos] = '\0';
}

int mgmt_auth_totp_generate_secret(char *out, size_t out_size) {
    if (!out || out_size < MGMT_TOTP_BASE32_LEN + 1) return -1;
    unsigned char secret[MGMT_TOTP_SECRET_BYTES];
    if (RAND_bytes(secret, MGMT_TOTP_SECRET_BYTES) != 1) return -1;
    base32_encode(secret, MGMT_TOTP_SECRET_BYTES, out);
    return 0;
}

int mgmt_auth_totp_verify(const char *code, const char *secret_b32) {
    if (!code || !secret_b32 || strlen(code) != MGMT_TOTP_DIGITS) return 0;

    /* Decode base32 secret */
    unsigned char key[MGMT_TOTP_SECRET_BYTES];
    int key_len = base32_decode(secret_b32, key, sizeof(key));
    if (key_len <= 0) return 0;

    /* Parse code as integer */
    long code_val = strtol(code, NULL, 10);
    if (code_val < 0 || code_val > 999999) return 0;

    /* Compute current time step (RFC 6238 §4.1) */
    uint64_t counter = (uint64_t)time(NULL) / MGMT_TOTP_PERIOD;

    /* Try ±window steps to tolerate clock skew */
    for (int offset = -MGMT_TOTP_WINDOW; offset <= MGMT_TOTP_WINDOW; offset++) {
        uint64_t step = counter + (int64_t)offset;
        /* Convert counter to big-endian 8 bytes */
        unsigned char msg[8];
        for (int i = 7; i >= 0; i--) {
            msg[i] = (unsigned char)(step & 0xFF);
            step >>= 8;
        }

        /* HMAC-SHA1(key, msg) */
        unsigned char hmac[20]; /* SHA1 digest = 20 bytes */
        size_t hmac_len = sizeof(hmac);
        int ok = 0;

        EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (mac) {
            EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 "SHA1", 0),
                OSSL_PARAM_END
            };
            if (EVP_MAC_init(mctx, key, (size_t)key_len, params)
                && EVP_MAC_update(mctx, msg, sizeof(msg))
                && EVP_MAC_final(mctx, hmac, &hmac_len, sizeof(hmac))) {
                ok = 1;
            }
            EVP_MAC_CTX_free(mctx);
            EVP_MAC_free(mac);
        }

        if (!ok) continue;

        /* Dynamic truncation (RFC 4226 §5.3) */
        int offset_dt = hmac[hmac_len - 1] & 0x0F;
        unsigned int binary =
            ((unsigned int)(hmac[offset_dt] & 0x7F) << 24) |
            ((unsigned int)(hmac[offset_dt + 1]) << 16) |
            ((unsigned int)(hmac[offset_dt + 2]) << 8) |
            ((unsigned int)(hmac[offset_dt + 3]));

        unsigned int totp = binary % 1000000;
        if ((unsigned long)code_val == totp) return 1;
    }
    return 0;
}

int mgmt_auth_is_totp_enabled(const pq_server_config_t *cfg) {
    return (cfg && cfg->mgmt_totp_secret[0] != '\0');
}

void mgmt_auth_cleanup(void) {
    if (!auth.initialized) return;
    auth.initialized = 0; /* Prevent new callers from entering */
    pthread_mutex_lock(&auth.mutex);
    memset(auth.sessions, 0, sizeof(auth.sessions));
    pthread_mutex_unlock(&auth.mutex);
    pthread_mutex_destroy(&auth.mutex);
}
