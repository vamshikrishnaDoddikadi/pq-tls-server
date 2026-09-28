/**
 * @file acl.c
 * @brief IP-based access control with CIDR support (IPv4 and IPv6)
 * @author Vamshi Krishna Doddikadi
 */

#include "acl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pthread.h>

/*
 * Every entry is stored as a 128-bit IPv6 network plus prefix length.
 * IPv4 addresses are stored IPv4-mapped (::ffff:a.b.c.d, prefix 96 + n),
 * which makes "10.0.0.0/8" match both "10.1.2.3" and "::ffff:10.1.2.3".
 */
typedef struct {
    uint8_t net[16];    /* Network address, host bits cleared */
    uint8_t prefix;     /* 0..128 */
} acl_entry_t;

static struct {
    acl_entry_t     entries[PQ_ACL_MAX_ENTRIES];
    int             count;
    pq_acl_mode_t   mode;
    int             initialized;
} acl;

/* Initialized once, never destroyed: safe against concurrent checks */
static pthread_mutex_t acl_lock = PTHREAD_MUTEX_INITIALIZER;

static const uint8_t v4mapped_prefix[12] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
};

/* Parse an address (IPv4 or IPv6, no prefix) into 16 bytes.
 * Returns the implied maximum prefix (32 for IPv4, 128 for IPv6), or -1. */
static int parse_addr(const char *s, uint8_t out[16])
{
    struct in_addr a4;
    struct in6_addr a6;

    if (inet_pton(AF_INET, s, &a4) == 1) {
        memcpy(out, v4mapped_prefix, sizeof(v4mapped_prefix));
        memcpy(out + 12, &a4.s_addr, 4);    /* network byte order */
        return 32;
    }
    if (inet_pton(AF_INET6, s, &a6) == 1) {
        memcpy(out, a6.s6_addr, 16);
        return 128;
    }
    return -1;
}

static void apply_prefix(uint8_t addr[16], int prefix)
{
    for (int i = 0; i < 16; i++) {
        int bits = prefix - i * 8;
        if (bits >= 8)
            continue;
        if (bits <= 0)
            addr[i] = 0;
        else
            addr[i] &= (uint8_t)(0xFFu << (8 - bits));
    }
}

static int prefix_match(const uint8_t addr[16], const acl_entry_t *e)
{
    int full = e->prefix / 8;
    int rem = e->prefix % 8;

    if (full > 0 && memcmp(addr, e->net, (size_t)full) != 0)
        return 0;
    if (rem) {
        uint8_t mask = (uint8_t)(0xFFu << (8 - rem));
        if ((addr[full] & mask) != e->net[full])
            return 0;
    }
    return 1;
}

/*
 * Parse "addr" or "addr/prefix" into an entry. The prefix must be 1-3
 * decimal digits within range for the address family (0-32 for IPv4,
 * 0-128 for IPv6). Returns 0 on success, -1 if invalid.
 */
static int parse_entry(const char *ip_or_cidr, acl_entry_t *out)
{
    if (!ip_or_cidr)
        return -1;

    char ip_buf[64];
    size_t len = strnlen(ip_or_cidr, sizeof(ip_buf));
    if (len == 0 || len >= sizeof(ip_buf))
        return -1;                      /* empty or would be truncated */
    memcpy(ip_buf, ip_or_cidr, len + 1);

    int prefix_len = -1;
    char *slash = strchr(ip_buf, '/');
    if (slash) {
        *slash = '\0';
        const char *p = slash + 1;
        size_t digits = strlen(p);
        if (digits == 0 || digits > 3)
            return -1;
        prefix_len = 0;
        for (; *p; p++) {
            if (*p < '0' || *p > '9')
                return -1;
            prefix_len = prefix_len * 10 + (*p - '0');
        }
    }

    uint8_t addr[16];
    int max_prefix = parse_addr(ip_buf, addr);
    if (max_prefix < 0)
        return -1;

    if (prefix_len < 0)
        prefix_len = max_prefix;
    if (prefix_len > max_prefix)
        return -1;

    /* IPv4 prefixes apply to the low 32 bits of the mapped address */
    int prefix = (max_prefix == 32) ? 96 + prefix_len : prefix_len;

    apply_prefix(addr, prefix);
    memcpy(out->net, addr, 16);
    out->prefix = (uint8_t)prefix;
    return 0;
}

void pq_acl_init(pq_acl_mode_t mode) {
    pthread_mutex_lock(&acl_lock);
    acl.count = 0;
    acl.mode = mode;
    acl.initialized = 1;
    pthread_mutex_unlock(&acl_lock);
}

int pq_acl_add(const char *ip_or_cidr) {
    acl_entry_t e;
    if (parse_entry(ip_or_cidr, &e) < 0) {
        fprintf(stderr, "acl: invalid entry '%s', skipping\n",
                ip_or_cidr ? ip_or_cidr : "(null)");
        return -1;
    }

    pthread_mutex_lock(&acl_lock);
    if (!acl.initialized || acl.count >= PQ_ACL_MAX_ENTRIES) {
        pthread_mutex_unlock(&acl_lock);
        return -1;
    }
    acl.entries[acl.count++] = e;
    pthread_mutex_unlock(&acl_lock);
    return 0;
}

int pq_acl_replace(pq_acl_mode_t mode, const char entries[][64], int count) {
    if (count < 0 || count > PQ_ACL_MAX_ENTRIES || (count > 0 && !entries))
        return -1;

    acl_entry_t *tmp = NULL;
    if (count > 0) {
        tmp = malloc((size_t)count * sizeof(*tmp));
        if (!tmp)
            return -1;
    }

    for (int i = 0; i < count; i++) {
        /* entries[i] is a char[64]; require termination within it */
        if (memchr(entries[i], '\0', 64) == NULL ||
            parse_entry(entries[i], &tmp[i]) < 0) {
            fprintf(stderr, "acl: invalid entry #%d, ACL not changed\n", i);
            free(tmp);
            return -1;
        }
    }

    pthread_mutex_lock(&acl_lock);
    if (count > 0)
        memcpy(acl.entries, tmp, (size_t)count * sizeof(*tmp));
    acl.count = count;
    acl.mode = mode;
    acl.initialized = 1;
    pthread_mutex_unlock(&acl_lock);

    free(tmp);
    return 0;
}

int pq_acl_check(const char *client_ip) {
    uint8_t addr[16];
    int parsed = client_ip ? parse_addr(client_ip, addr) : -1;

    pthread_mutex_lock(&acl_lock);

    pq_acl_mode_t mode = acl.initialized ? acl.mode : PQ_ACL_MODE_DISABLED;
    if (mode != PQ_ACL_MODE_ALLOWLIST && mode != PQ_ACL_MODE_BLOCKLIST) {
        pthread_mutex_unlock(&acl_lock);
        return 1;
    }

    if (parsed < 0) {
        pthread_mutex_unlock(&acl_lock);
        /* Unparseable: fail closed for allowlists, cannot match a blocklist */
        return mode == PQ_ACL_MODE_BLOCKLIST;
    }

    int matched = 0;
    for (int i = 0; i < acl.count; i++) {
        if (prefix_match(addr, &acl.entries[i])) {
            matched = 1;
            break;
        }
    }

    pthread_mutex_unlock(&acl_lock);

    return (mode == PQ_ACL_MODE_ALLOWLIST) ? matched : !matched;
}

void pq_acl_destroy(void) {
    pthread_mutex_lock(&acl_lock);
    acl.count = 0;
    acl.mode = PQ_ACL_MODE_DISABLED;
    acl.initialized = 0;
    pthread_mutex_unlock(&acl_lock);
}

void pq_acl_clear(void) {
    pthread_mutex_lock(&acl_lock);
    acl.count = 0;
    pthread_mutex_unlock(&acl_lock);
}

void pq_acl_reinit(pq_acl_mode_t mode) {
    pq_acl_init(mode);
}
