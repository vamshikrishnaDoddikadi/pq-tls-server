/*
 * epoll_reactor.h - High-performance epoll-based event loop reactor
 *
 * A thread-safe, non-blocking event reactor for the Post-Quantum TLS
 * termination reverse proxy. Supports I/O multiplexing and periodic timers.
 */

#ifndef EPOLL_REACTOR_H
#define EPOLL_REACTOR_H

#include <stdint.h>
#include <sys/epoll.h>

/* Event type bitmasks */
typedef enum {
    PQ_EV_READ   = 0x01,      /* File descriptor is readable */
    PQ_EV_WRITE  = 0x02,      /* File descriptor is writable */
    PQ_EV_ERROR  = 0x04,      /* Error condition (EPOLLERR) */
    PQ_EV_HANGUP = 0x08,      /* Remote hangup (EPOLLHUP) */
    PQ_EV_TIMER  = 0x10       /* Timer event */
} pq_event_type_t;

/* Opaque reactor structure */
typedef struct pq_reactor pq_reactor_t;

/*
 * Event callback signature.
 *
 * Called when events occur on registered file descriptors or timers.
 * The events parameter is a bitmask of pq_event_type_t values.
 * The callback is responsible for non-blocking I/O operations.
 *
 * Parameters:
 *   reactor - The reactor instance
 *   fd      - File descriptor that triggered the event (-1 for timers)
 *   events  - Bitmask of events that occurred
 *   userdata - User-provided context
 */
typedef void (*pq_event_cb)(pq_reactor_t *reactor, int fd, uint32_t events, void *userdata);

/*
 * Event source descriptor (for informational purposes).
 * Users don't allocate these; they're returned by query functions.
 */
typedef struct {
    int fd;                    /* File descriptor (-1 for timers) */
    uint32_t events;           /* Bitmask of registered events */
    pq_event_cb callback;      /* User callback function */
    void *userdata;            /* User-provided context */
} pq_event_source_t;

/*
 * pq_reactor_create - Create a new event reactor.
 *
 * Initializes an epoll-based event reactor with internal data structures.
 * The reactor uses a hash table to map file descriptors to event sources.
 *
 * Parameters:
 *   max_events - Maximum number of events to process per epoll_wait call.
 *                Recommended: 256-1024. If <= 0, defaults to 256.
 *
 * Returns:
 *   Pointer to new reactor on success, NULL on failure (errno set).
 *
 * Thread-safety: Not thread-safe to call from multiple threads simultaneously
 *   (use once during initialization).
 */
pq_reactor_t *pq_reactor_create(int max_events);

/*
 * pq_reactor_destroy - Destroy a reactor and release all resources.
 *
 * Closes the internal epoll fd and all registered timer file descriptors.
 * Does NOT close application file descriptors passed to pq_reactor_add().
 *
 * Parameters:
 *   r - Reactor instance (may be NULL).
 *
 * Thread-safety: Not safe if reactor is currently running in another thread.
 */
void pq_reactor_destroy(pq_reactor_t *r);

/*
 * pq_reactor_add - Register a file descriptor with the reactor.
 *
 * Adds a file descriptor to the reactor with specified event interests.
 * If the fd is already registered, returns error.
 *
 * Parameters:
 *   r        - Reactor instance
 *   fd       - Non-negative file descriptor to monitor
 *   events   - Bitmask of pq_event_type_t values (PQ_EV_READ, PQ_EV_WRITE, etc.)
 *   cb       - Callback function to invoke on events (must not be NULL)
 *   userdata - User context pointer passed to callback (may be NULL)
 *
 * Returns:
 *   0 on success, -1 on failure (errno set).
 *   EINVAL: Invalid fd or events
 *   EEXIST: fd already registered
 *   ENOBUFS: epoll subsystem out of memory
 *
 * Thread-safety: Protected by internal mutex. Safe to call from any thread.
 *
 * Note: For listener sockets, use edge-triggered mode via pq_reactor_mod_trigger().
 *       For client connections, level-triggered (default) is recommended.
 */
int pq_reactor_add(pq_reactor_t *r, int fd, uint32_t events, pq_event_cb cb, void *userdata);

/*
 * pq_reactor_mod - Modify event interests for a registered file descriptor.
 *
 * Changes the set of events being monitored for an already-registered fd.
 *
 * Parameters:
 *   r      - Reactor instance
 *   fd     - Registered file descriptor
 *   events - New event bitmask (PQ_EV_READ | PQ_EV_WRITE | etc.)
 *
 * Returns:
 *   0 on success, -1 on failure (errno set).
 *   ENOENT: fd not registered
 *   EINVAL: Invalid events mask
 *
 * Thread-safety: Protected by internal mutex. Safe to call from any thread.
 */
int pq_reactor_mod(pq_reactor_t *r, int fd, uint32_t events);

/*
 * pq_reactor_del - Unregister a file descriptor.
 *
 * Removes a file descriptor from the reactor. The application is responsible
 * for closing the file descriptor afterwards if desired.
 *
 * Parameters:
 *   r  - Reactor instance
 *   fd - Registered file descriptor
 *
 * Returns:
 *   0 on success, -1 on failure (errno set).
 *   ENOENT: fd not registered
 *
 * Thread-safety: Protected by internal mutex. Safe to call from any thread.
 */
int pq_reactor_del(pq_reactor_t *r, int fd);

/*
 * pq_reactor_run - Run one iteration of the event loop.
 *
 * Blocks on epoll_wait() for the specified timeout, then dispatches
 * callbacks for all events. Does not loop; returns after processing
 * one batch of events.
 *
 * Parameters:
 *   r          - Reactor instance
 *   timeout_ms - Timeout in milliseconds. -1 blocks indefinitely.
 *                0 returns immediately. Positive value is the max wait time.
 *
 * Returns:
 *   Number of events dispatched on success (0 for timeout, >0 for events).
 *   -1 on error (errno set).
 *   EINTR from epoll_wait is handled transparently (retries).
 *
 * Thread-safety: Not safe to call from multiple threads concurrently.
 *   The reactor should typically run in a single event loop thread.
 *   Use pq_reactor_add/mod/del from other threads as needed.
 *
 * Note: Callbacks are invoked synchronously from this function.
 */
int pq_reactor_run(pq_reactor_t *r, int timeout_ms);

/*
 * pq_reactor_loop - Run the event loop until signaled to stop.
 *
 * Repeatedly calls pq_reactor_run() with the given timeout until
 * the running flag is set to 0. Suitable for the main event loop.
 *
 * Parameters:
 *   r       - Reactor instance
 *   running - Pointer to volatile int. Loop runs while *running != 0.
 *             Set to 0 to exit the loop (e.g., from signal handler).
 *
 * Returns:
 *   0 on normal exit (running set to 0), -1 on error.
 *
 * Thread-safety: pq_reactor_loop() must run in a single thread.
 *   Other threads may safely call pq_reactor_add/mod/del concurrently.
 *
 * Example:
 *   volatile int running = 1;
 *   // ... signal handler sets running = 0 ...
 *   pq_reactor_loop(reactor, &running);
 */
int pq_reactor_loop(pq_reactor_t *r, volatile int *running);

/*
 * pq_reactor_add_timer - Register a periodic timer event.
 *
 * Creates an internal timerfd and registers it with the reactor.
 * The callback will be invoked approximately every interval_ms milliseconds.
 *
 * Timers are edge-triggered by default and use CLOCK_MONOTONIC to avoid
 * issues with system clock adjustments.
 *
 * Parameters:
 *   r           - Reactor instance
 *   interval_ms - Timer interval in milliseconds (must be > 0)
 *   cb          - Callback to invoke when timer fires
 *   userdata    - User context passed to callback
 *
 * Returns:
 *   Timer fd (non-negative) on success, -1 on failure (errno set).
 *   The timer fd can be used with pq_reactor_del() to cancel the timer.
 *
 * Thread-safety: Protected by internal mutex. Safe to call from any thread.
 *
 * Note: Timer callbacks receive events = PQ_EV_TIMER and fd = timer_fd.
 *       Timers are non-blocking and non-deferrable (CLOCK_MONOTONIC).
 */
int pq_reactor_add_timer(pq_reactor_t *r, int interval_ms, pq_event_cb cb, void *userdata);

#endif /* EPOLL_REACTOR_H */
