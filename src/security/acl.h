/**
 * @file acl.h
 * @brief IP-based access control lists (allowlist / blocklist)
 * @author Vamshi Krishna Doddikadi
 */

#ifndef PQ_ACL_H
#define PQ_ACL_H

/* pq_acl_mode_t may already be defined by server_config.h */
#ifndef PQ_SERVER_CONFIG_H
typedef enum {
    PQ_ACL_MODE_DISABLED,   /* No ACL — all IPs allowed */
    PQ_ACL_MODE_ALLOWLIST,  /* Only listed IPs allowed */
    PQ_ACL_MODE_BLOCKLIST   /* Listed IPs blocked, others allowed */
} pq_acl_mode_t;
#endif

/**
 * Initialize the ACL system.
 */
void pq_acl_init(pq_acl_mode_t mode);

/**
 * Add an IP or CIDR range to the ACL.
 * Supports: "192.168.1.1", "10.0.0.0/8", "0.0.0.0/0"
 *
 * @return 0 on success, -1 on error.
 */
int pq_acl_add(const char *ip_or_cidr);

/**
 * Check if a client IP is allowed to connect.
 * @return 1 if allowed, 0 if denied.
 */
int pq_acl_check(const char *client_ip);

/**
 * Free all ACL entries.
 */
void pq_acl_destroy(void);

/**
 * Clear all ACL entries without destroying the mutex.
 */
void pq_acl_clear(void);

/**
 * Reinitialize the ACL with a new mode, clearing all entries.
 */
void pq_acl_reinit(pq_acl_mode_t mode);

#endif /* PQ_ACL_H */
