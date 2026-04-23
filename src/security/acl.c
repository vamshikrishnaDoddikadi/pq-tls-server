/**
 * @file acl.c
 * @brief IP-based access control with CIDR support
 * @author Vamshi Krishna Doddikadi
 */

#include "acl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MAX_ACL_ENTRIES 1024

typedef struct {
    uint32_t network;   /* Network address in host byte order */
    uint32_t mask;      /* Subnet mask in host byte order */
} acl_entry_t;

static struct {
    acl_entry_t    entries[MAX_ACL_ENTRIES];
    int            count;
    pq_acl_mode_t  mode;
    pthread_mutex_t mutex;
    int            initialized;
} acl;

void pq_acl_init(pq_acl_mode_t mode) {
    memset(&acl, 0, sizeof(acl));
    pthread_mutex_init(&acl.mutex, NULL);
    acl.mode = mode;
    acl.initialized = 1;
}

int pq_acl_add(const char *ip_or_cidr) {
    if (!acl.initialized || !ip_or_cidr) return -1;

    pthread_mutex_lock(&acl.mutex);
    if (acl.count >= MAX_ACL_ENTRIES) {
        pthread_mutex_unlock(&acl.mutex);
        return -1;
    }

    /* Parse CIDR notation */
    char ip_buf[64];
    strncpy(ip_buf, ip_or_cidr, sizeof(ip_buf) - 1);
    ip_buf[sizeof(ip_buf) - 1] = '\0';

    int prefix_len = 32;
    char *slash = strchr(ip_buf, '/');
    if (slash) {
        *slash = '\0';
        char *endptr = NULL;
        prefix_len = (int)strtol(slash + 1, &endptr, 10);
        /* Validate: no non-numeric chars, and within valid range [0,32] */
        if (!endptr || *endptr != '\0' || prefix_len < 0 || prefix_len > 32) {
            fprintf(stderr, "acl: invalid CIDR prefix /%s in '%s', skipping\n",
                    slash + 1, ip_or_cidr);
            pthread_mutex_unlock(&acl.mutex);
            return -1;
        }
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_buf, &addr) != 1) {
        pthread_mutex_unlock(&acl.mutex);
        return -1;
    }

    uint32_t mask;
    /* SECURITY: Explicit mask calculation handles all prefix_len edge cases */
    if (prefix_len == 0) {
        mask = 0;
    } else if (prefix_len == 32) {
        mask = 0xFFFFFFFF;
    } else {
        /* Left shift of 32-bit value by (32 - prefix_len) where result is in [1,31] */
        mask = 0xFFFFFFFFu << (32 - prefix_len);
    }
    uint32_t network = ntohl(addr.s_addr) & mask;

    acl_entry_t *e = &acl.entries[acl.count++];
    e->network = network;
    e->mask = mask;

    pthread_mutex_unlock(&acl.mutex);
    return 0;
}

int pq_acl_check(const char *client_ip) {
    if (!acl.initialized || acl.mode == PQ_ACL_MODE_DISABLED) return 1;
    if (!client_ip) return 0;

    struct in_addr addr;
    if (inet_pton(AF_INET, client_ip, &addr) != 1) return 0;
    uint32_t ip = ntohl(addr.s_addr);

    pthread_mutex_lock(&acl.mutex);

    int matched = 0;
    pq_acl_mode_t mode = acl.mode;
    for (int i = 0; i < acl.count; i++) {
        if ((ip & acl.entries[i].mask) == acl.entries[i].network) {
            matched = 1;
            break;
        }
    }

    pthread_mutex_unlock(&acl.mutex);

    if (mode == PQ_ACL_MODE_ALLOWLIST) return matched;
    if (mode == PQ_ACL_MODE_BLOCKLIST) return !matched;
    return 1;
}

void pq_acl_destroy(void) {
    if (!acl.initialized) return;
    pthread_mutex_destroy(&acl.mutex);
    acl.initialized = 0;
}

void pq_acl_clear(void) {
    if (!acl.initialized) return;
    pthread_mutex_lock(&acl.mutex);
    acl.count = 0;
    pthread_mutex_unlock(&acl.mutex);
}

void pq_acl_reinit(pq_acl_mode_t mode) {
    pq_acl_destroy();
    pq_acl_init(mode);
}
