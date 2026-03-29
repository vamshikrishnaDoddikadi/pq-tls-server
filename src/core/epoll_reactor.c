/*
 * epoll_reactor.c - High-performance epoll-based event loop reactor implementation
 *
 * Provides a thread-safe event reactor with support for I/O multiplexing,
 * timers, and callbacks. Uses epoll for scalable event notification.
 */

#include "epoll_reactor.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

/* ============================================================================
 * Constants and Limits
 * ============================================================================ */

#define DEFAULT_MAX_EVENTS 256
#define FD_HASH_BUCKETS 1024
#define FD_HASH_MASK (FD_HASH_BUCKETS - 1)

/* ============================================================================
 * Internal Data Structures
 * ============================================================================ */

/*
 * Event source entry in the hash table.
 * Maps a file descriptor to its callback, user data, and event interests.
 */
typedef struct fd_entry {
    int fd;                    /* File descriptor (-1 if unused) */
    uint32_t events;           /* Registered event bitmask */
    pq_event_cb callback;      /* User callback */
    void *userdata;            /* User context */
    struct fd_entry *next;     /* Hash collision chain */
} fd_entry_t;

/*
 * Main reactor structure.
 * Contains the epoll fd, event source hash table, and internal state.
 */
typedef struct pq_reactor {
    int epoll_fd;              /* epoll file descriptor */
    int max_events;            /* Max events per epoll_wait batch */
    struct epoll_event *events_array;  /* Buffer for epoll_wait results */

    fd_entry_t **fd_table;     /* Hash table: [FD_HASH_BUCKETS] */
    pthread_mutex_t table_lock; /* Protects fd_table access */

    int num_sources;           /* Number of registered fds */
} pq_reactor_t;

/* ============================================================================
 * Hash Table Operations (Protected by table_lock)
 * ============================================================================ */

/*
 * fd_hash - Compute hash bucket for a file descriptor.
 * Uses FNV-1a hash for better distribution with non-sequential FDs.
 */
static inline int fd_hash(int fd) {
    /* FNV-1a hash: better distribution than simple modulo */
    unsigned int h = 2166136261U;
    unsigned int v = (unsigned int)fd;
    h ^= v & 0xFF;
    h *= 16777619U;
    h ^= (v >> 8) & 0xFF;
    h *= 16777619U;
    h ^= (v >> 16) & 0xFF;
    h *= 16777619U;
    h ^= (v >> 24);
    h *= 16777619U;
    return h & FD_HASH_MASK;
}

/*
 * fd_table_find - Find an fd entry in the hash table.
 * Caller must hold table_lock.
 */
static fd_entry_t *fd_table_find(pq_reactor_t *r, int fd) {
    int bucket = fd_hash(fd);
    fd_entry_t *entry = r->fd_table[bucket];

    while (entry != NULL) {
        if (entry->fd == fd) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

/*
 * fd_table_insert - Insert a new fd entry into the hash table.
 * Caller must hold table_lock. Returns NULL if entry already exists.
 */
static fd_entry_t *fd_table_insert(pq_reactor_t *r, int fd,
                                    pq_event_cb cb, void *userdata) {
    int bucket = fd_hash(fd);

    /* Check if fd already registered */
    fd_entry_t *entry = r->fd_table[bucket];
    while (entry != NULL) {
        if (entry->fd == fd) {
            return NULL;  /* Already exists */
        }
        entry = entry->next;
    }

    /* Allocate new entry */
    entry = (fd_entry_t *)malloc(sizeof(fd_entry_t));
    if (entry == NULL) {
        return NULL;
    }

    entry->fd = fd;
    entry->events = 0;
    entry->callback = cb;
    entry->userdata = userdata;

    /* Insert at head of bucket chain */
    entry->next = r->fd_table[bucket];
    r->fd_table[bucket] = entry;

    r->num_sources++;
    return entry;
}

/*
 * fd_table_remove - Remove and free an fd entry from the hash table.
 * Caller must hold table_lock. Returns the entry if found, NULL otherwise.
 */
static fd_entry_t *fd_table_remove(pq_reactor_t *r, int fd) {
    int bucket = fd_hash(fd);
    fd_entry_t *entry = r->fd_table[bucket];
    fd_entry_t *prev = NULL;

    while (entry != NULL) {
        if (entry->fd == fd) {
            if (prev == NULL) {
                r->fd_table[bucket] = entry->next;
            } else {
                prev->next = entry->next;
            }
            r->num_sources--;
            return entry;  /* Caller must free */
        }
        prev = entry;
        entry = entry->next;
    }

    return NULL;
}

/* ============================================================================
 * Event Dispatch Helper
 * ============================================================================ */

/*
 * epoll_flags_to_pq_events - Convert epoll flags to pq_event_type_t bitmask.
 */
static uint32_t epoll_flags_to_pq_events(uint32_t epoll_flags) {
    uint32_t events = 0;

    if (epoll_flags & EPOLLIN) {
        events |= PQ_EV_READ;
    }
    if (epoll_flags & EPOLLOUT) {
        events |= PQ_EV_WRITE;
    }
    if (epoll_flags & EPOLLERR) {
        events |= PQ_EV_ERROR;
    }
    if (epoll_flags & EPOLLHUP) {
        events |= PQ_EV_HANGUP;
    }

    return events;
}

/*
 * pq_events_to_epoll_flags - Convert pq_event_type_t bitmask to epoll flags.
 * Note: PQ_EV_TIMER is internal and not converted to epoll flags.
 */
static uint32_t pq_events_to_epoll_flags(uint32_t pq_events) {
    uint32_t flags = 0;

    if (pq_events & PQ_EV_READ) {
        flags |= EPOLLIN;
    }
    if (pq_events & PQ_EV_WRITE) {
        flags |= EPOLLOUT;
    }

    /* Errors are always monitored */
    flags |= EPOLLERR;

    return flags;
}

/* ============================================================================
 * Public API: Reactor Lifecycle
 * ============================================================================ */

pq_reactor_t *pq_reactor_create(int max_events) {
    pq_reactor_t *r = (pq_reactor_t *)malloc(sizeof(pq_reactor_t));
    if (r == NULL) {
        return NULL;
    }

    /* Set max_events, with default fallback */
    if (max_events <= 0) {
        max_events = DEFAULT_MAX_EVENTS;
    }
    r->max_events = max_events;

    /* Create epoll fd */
    r->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (r->epoll_fd < 0) {
        free(r);
        return NULL;
    }

    /* Allocate events buffer */
    r->events_array = (struct epoll_event *)malloc(
        max_events * sizeof(struct epoll_event)
    );
    if (r->events_array == NULL) {
        close(r->epoll_fd);
        free(r);
        return NULL;
    }

    /* Allocate hash table */
    r->fd_table = (fd_entry_t **)calloc(FD_HASH_BUCKETS, sizeof(fd_entry_t *));
    if (r->fd_table == NULL) {
        free(r->events_array);
        close(r->epoll_fd);
        free(r);
        return NULL;
    }

    /* Initialize mutex */
    if (pthread_mutex_init(&r->table_lock, NULL) != 0) {
        free(r->fd_table);
        free(r->events_array);
        close(r->epoll_fd);
        free(r);
        return NULL;
    }

    r->num_sources = 0;

    return r;
}

void pq_reactor_destroy(pq_reactor_t *r) {
    if (r == NULL) {
        return;
    }

    /* Close epoll fd */
    if (r->epoll_fd >= 0) {
        close(r->epoll_fd);
    }

    /* Close all registered timer fds and free hash table */
    pthread_mutex_lock(&r->table_lock);
    for (int i = 0; i < FD_HASH_BUCKETS; i++) {
        fd_entry_t *entry = r->fd_table[i];
        while (entry != NULL) {
            fd_entry_t *next = entry->next;
            /* Close timerfd if it's a timer (registered with PQ_EV_TIMER) */
            if ((entry->events & PQ_EV_TIMER) && entry->fd >= 0) {
                close(entry->fd);
            }
            free(entry);
            entry = next;
        }
    }
    pthread_mutex_unlock(&r->table_lock);

    /* Clean up resources */
    free(r->fd_table);
    free(r->events_array);
    pthread_mutex_destroy(&r->table_lock);
    free(r);
}

/* ============================================================================
 * Public API: File Descriptor Registration
 * ============================================================================ */

int pq_reactor_add(pq_reactor_t *r, int fd, uint32_t events,
                   pq_event_cb cb, void *userdata) {
    if (r == NULL || fd < 0 || cb == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Remove PQ_EV_TIMER from user events (internal only) */
    uint32_t user_events = events & ~PQ_EV_TIMER;
    uint32_t epoll_flags = pq_events_to_epoll_flags(user_events);

    /* Prepare epoll_event structure */
    struct epoll_event ee;
    memset(&ee, 0, sizeof(ee));
    ee.events = epoll_flags;
    ee.data.fd = fd;

    /* Add to epoll */
    if (epoll_ctl(r->epoll_fd, EPOLL_CTL_ADD, fd, &ee) < 0) {
        return -1;
    }

    /* Add to hash table */
    pthread_mutex_lock(&r->table_lock);
    fd_entry_t *entry = fd_table_insert(r, fd, cb, userdata);
    if (entry == NULL) {
        pthread_mutex_unlock(&r->table_lock);
        epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        errno = EEXIST;
        return -1;
    }
    entry->events = user_events;
    pthread_mutex_unlock(&r->table_lock);

    return 0;
}

int pq_reactor_mod(pq_reactor_t *r, int fd, uint32_t events) {
    if (r == NULL || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    /* Remove PQ_EV_TIMER from user events */
    uint32_t user_events = events & ~PQ_EV_TIMER;
    uint32_t epoll_flags = pq_events_to_epoll_flags(user_events);

    /* Prepare epoll_event structure */
    struct epoll_event ee;
    memset(&ee, 0, sizeof(ee));
    ee.events = epoll_flags;
    ee.data.fd = fd;

    /* Modify in epoll */
    if (epoll_ctl(r->epoll_fd, EPOLL_CTL_MOD, fd, &ee) < 0) {
        return -1;
    }

    /* Update hash table */
    pthread_mutex_lock(&r->table_lock);
    fd_entry_t *entry = fd_table_find(r, fd);
    if (entry == NULL) {
        pthread_mutex_unlock(&r->table_lock);
        epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        errno = ENOENT;
        return -1;
    }
    entry->events = user_events;
    pthread_mutex_unlock(&r->table_lock);

    return 0;
}

int pq_reactor_del(pq_reactor_t *r, int fd) {
    if (r == NULL || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    /* Remove from epoll */
    if (epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        return -1;
    }

    /* Remove from hash table and close if timer */
    pthread_mutex_lock(&r->table_lock);
    fd_entry_t *entry = fd_table_remove(r, fd);
    if (entry == NULL) {
        pthread_mutex_unlock(&r->table_lock);
        errno = ENOENT;
        return -1;
    }

    /* Close timerfd if applicable */
    if ((entry->events & PQ_EV_TIMER) && fd >= 0) {
        close(fd);
    }

    free(entry);
    pthread_mutex_unlock(&r->table_lock);

    return 0;
}

/* ============================================================================
 * Public API: Timer Registration
 * ============================================================================ */

int pq_reactor_add_timer(pq_reactor_t *r, int interval_ms,
                         pq_event_cb cb, void *userdata) {
    if (r == NULL || interval_ms <= 0 || cb == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Create timerfd */
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0) {
        return -1;
    }

    /* Set timer interval */
    struct itimerspec spec;
    memset(&spec, 0, sizeof(spec));

    /* Convert milliseconds to seconds and nanoseconds */
    spec.it_value.tv_sec = interval_ms / 1000;
    spec.it_value.tv_nsec = (interval_ms % 1000) * 1000000;
    spec.it_interval = spec.it_value;

    if (timerfd_settime(timer_fd, 0, &spec, NULL) < 0) {
        close(timer_fd);
        return -1;
    }

    /* Register with reactor as edge-triggered */
    struct epoll_event ee;
    memset(&ee, 0, sizeof(ee));
    ee.events = EPOLLIN | EPOLLET;  /* Edge-triggered for timers */
    ee.data.fd = timer_fd;

    if (epoll_ctl(r->epoll_fd, EPOLL_CTL_ADD, timer_fd, &ee) < 0) {
        close(timer_fd);
        return -1;
    }

    /* Add to hash table with PQ_EV_TIMER marker */
    pthread_mutex_lock(&r->table_lock);
    fd_entry_t *entry = fd_table_insert(r, timer_fd, cb, userdata);
    if (entry == NULL) {
        pthread_mutex_unlock(&r->table_lock);
        epoll_ctl(r->epoll_fd, EPOLL_CTL_DEL, timer_fd, NULL);
        close(timer_fd);
        errno = EEXIST;
        return -1;
    }
    entry->events = PQ_EV_TIMER;
    pthread_mutex_unlock(&r->table_lock);

    return timer_fd;
}

/* ============================================================================
 * Public API: Event Loop
 * ============================================================================ */

__attribute__((hot))
int pq_reactor_run(pq_reactor_t *r, int timeout_ms) {
    if (__builtin_expect(r == NULL, 0)) {
        errno = EINVAL;
        return -1;
    }

    /* Call epoll_wait with retry on EINTR */
    int num_events;
    while (1) {
        num_events = epoll_wait(r->epoll_fd, r->events_array,
                                r->max_events, timeout_ms);
        if (__builtin_expect(num_events >= 0 || errno != EINTR, 1)) {
            break;
        }
        /* EINTR: retry */
    }

    if (__builtin_expect(num_events < 0, 0)) {
        return -1;
    }

    /* Dispatch callbacks for each event */
    for (int i = 0; i < num_events; i++) {
        int fd = r->events_array[i].data.fd;
        uint32_t epoll_events = r->events_array[i].events;

        /* Convert epoll flags to pq_event_type_t */
        uint32_t pq_events = epoll_flags_to_pq_events(epoll_events);

        /* Look up the event source */
        pthread_mutex_lock(&r->table_lock);
        fd_entry_t *entry = fd_table_find(r, fd);
        if (__builtin_expect(entry == NULL, 0)) {
            pthread_mutex_unlock(&r->table_lock);
            continue;  /* Stale event, skip */
        }

        /* Make copies to avoid lock issues during callback */
        pq_event_cb callback = entry->callback;
        void *userdata = entry->userdata;
        uint32_t registered_events = entry->events;

        pthread_mutex_unlock(&r->table_lock);

        /* For timers, set the PQ_EV_TIMER flag */
        if (__builtin_expect(registered_events & PQ_EV_TIMER, 0)) {
            pq_events = PQ_EV_TIMER;
        }

        /* Invoke callback */
        if (__builtin_expect(callback != NULL, 1)) {
            callback(r, fd, pq_events, userdata);
        }
    }

    return num_events;
}

__attribute__((hot))
int pq_reactor_loop(pq_reactor_t *r, volatile int *running) {
    if (__builtin_expect(r == NULL || running == NULL, 0)) {
        errno = EINVAL;
        return -1;
    }

    while (*running != 0) {
        int ret = pq_reactor_run(r, -1);  /* Block indefinitely */
        if (__builtin_expect(ret < 0, 0)) {
            return -1;
        }
    }

    return 0;
}
