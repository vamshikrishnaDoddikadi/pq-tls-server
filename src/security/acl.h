/**
 * @file acl.h
 * @brief IP-based access control lists (allowlist / blocklist)
 * @author Vamshi Krishna Doddikadi
 *
 * Entries are IPv4 or IPv6 addresses or CIDR ranges ("10.0.0.0/8",
 * "2001:db8::/32", "192.0.2.7", "::1"). IPv4-mapped IPv6 client addresses
 * ("::ffff:192.0.2.7", as reported by dual-stack sockets) are matched as
 * the IPv4 address, so an IPv4 rule applies no matter how the client
 * connected. "0.0.0.0/0" matches every IPv4 client; "::/0" matches every
 * client.
 *
 * A client address that cannot be parsed (NULL, "unknown", garbage) is
 * denied in allowlist mode (fail closed) and allowed in blocklist mode
 * (it cannot match any listed range).
 *
 * Thread safety: the table is protected by a statically initialized lock
 * that is never destroyed, so pq_acl_check() may run concurrently with any
 * other call. For runtime reconfiguration use pq_acl_replace(), which swaps
 * mode and entries atomically; destroy+init+add sequences leave windows in
 * which a concurrent check sees an empty or disabled ACL.
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

/** Maximum number of entries in the table. */
#define PQ_ACL_MAX_ENTRIES 1024

/**
 * Initialize the ACL system (empty table, given mode).
 */
void pq_acl_init(pq_acl_mode_t mode);

/**
 * Add an IP or CIDR range to the ACL.
 * Supports: "192.168.1.1", "10.0.0.0/8", "0.0.0.0/0", "2001:db8::/32"
 *
 * @return 0 on success, -1 on error.
 */
int pq_acl_add(const char *ip_or_cidr);

/**
 * Atomically replace the whole ACL (mode and entries).
 *
 * All entries are parsed into a temporary table first; only if every entry
 * is valid are mode, entries and count swapped in under the lock, so a
 * concurrent pq_acl_check() sees either the old or the new ACL, never a
 * partial one. entries may be NULL when count is 0.
 *
 * @return 0 on success; -1 if any entry is invalid, count is negative or
 *         exceeds PQ_ACL_MAX_ENTRIES (the current ACL is left untouched).
 */
int pq_acl_replace(pq_acl_mode_t mode, const char entries[][64], int count);

/**
 * Check if a client IP is allowed to connect.
 * @return 1 if allowed, 0 if denied.
 */
int pq_acl_check(const char *client_ip);

/**
 * Free all ACL entries and disable the ACL (all clients allowed).
 * Safe to call while other threads use the ACL; the lock is not destroyed.
 */
void pq_acl_destroy(void);

/**
 * Clear all ACL entries without changing the mode.
 */
void pq_acl_clear(void);

/**
 * Reinitialize the ACL with a new mode, clearing all entries.
 */
void pq_acl_reinit(pq_acl_mode_t mode);

#endif /* PQ_ACL_H */
