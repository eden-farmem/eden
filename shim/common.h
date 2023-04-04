/**
 * common.h - common definitions for the shim library
 */

#include "base/thread.h"

/**
 * Logging & ASSERTs
 * 
 * We need modified versions of logging calls that do not call 
 * malloc internally to avoid infinite loops. We will only use these 
 * functions for logging instead of <base/log.h> in this file.
 */
#define shim_log(fmt, ...)                                  \
    do {                                                    \
        fprintf(stderr, "[THR %d][%s][%s:%d]: " fmt "\n",   \
            thread_gettid(), __FILE__, __func__, __LINE__,  \
            ##__VA_ARGS__);                                 \
    } while (0)
#define shim_bug_on(cond, fmt, ...)                         \
    do {                                                    \
        if (cond) {                                         \
            shim_log(fmt, ##__VA_ARGS__);                   \
            exit(1);                                        \
        }                                                   \
    } while (0)

/* debug mode */
#ifdef DEBUG
#define shim_log_debug              shim_log
#else
#define shim_log_debug(fmt, ...)    do {} while (0)
#endif