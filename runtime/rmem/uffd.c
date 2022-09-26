/*
 * uffd.c - uffd helper methods
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "rmem/uffd.h"
#include "rmem/config.h"
#include "base/log.h"
#include "base/assert.h"

int userfaultfd(int flags) { 
    return syscall(SYS_userfaultfd, flags); 
}

int uffd_init(void) {
    int r;
    struct uffdio_api api = {
            .api = UFFD_API,
#ifdef REGISTER_MADVISE_NOTIF
            .features = UFFD_FEATURE_EVENT_FORK | UFFD_FEATURE_EVENT_REMAP |
                UFFD_FEATURE_EVENT_REMOVE | UFFD_FEATURE_EVENT_UNMAP
#else
            .features = UFFD_FEATURE_EVENT_FORK | UFFD_FEATURE_EVENT_REMAP |
                UFFD_FEATURE_EVENT_UNMAP
#endif
    };

// #ifdef UFFD_APP_POLL
//     api.features |= UFFD_FEATURE_POLL;
// #endif

    uint64_t ioctl_mask =
            (1ull << _UFFDIO_REGISTER) | (1ull << _UFFDIO_UNREGISTER);

    int fd = userfaultfd(O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        log_err("userfaultfd failed");
        BUG();
        return -1;
    }

    r = ioctl(fd, UFFDIO_API, &api);
    if (r < 0) {
        log_err("ioctl(fd, UFFDIO_API, ...) failed");
        BUG();
        return -1;
    }
    if ((api.ioctls & ioctl_mask) != ioctl_mask) {
        log_err("supported features %llx ioctls %llx", api.features, api.ioctls);
        BUG();
        return -1;
    }

    return fd;
}

int uffd_register(int fd, unsigned long addr, size_t size, int writeable) {
    int r;
    uint64_t ioctls_mask = (1ull << _UFFDIO_COPY);

    int mode;
    if (writeable)
        mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP;
    else
        mode = UFFDIO_REGISTER_MODE_MISSING;

    struct uffdio_register reg = {
        .mode = mode, 
        .range = {.start = addr, .len = size}
    };

    r = ioctl(fd, UFFDIO_REGISTER, &reg);
    if (r < 0) {
        log_err("ioctl(fd, UFFDIO_REGISTER, ...) failed: size %ld addr %lx",
            size, addr);
        BUG();
        goto out;
    }

    if ((reg.ioctls & ioctls_mask) != ioctls_mask) {
        log_debug("unexpected UFFD ioctls");
        r = -1;
        goto out;
    }
    log_debug("ioctl(fd, UFFDIO_REGISTER, ...) succeed: size %ld addr %lx", 
        size, addr);

out:
    return r;
}

int uffd_unregister(int fd, unsigned long addr, size_t size) {
    int r = 0;
    struct uffdio_range range = {.start = addr, .len = size};
    r = ioctl(fd, UFFDIO_UNREGISTER, &range);
    if (r < 0) log_err("ioctl(fd, UFFDIO_UNREGISTER, ...) failed");
    return r;
}

int uffd_copy(int fd, unsigned long dst, unsigned long src, int wpmode,
        bool retry, int *n_retries, bool wake_on_exist) {
    int r;
    struct uffdio_copy copy = {
        .dst = dst, 
        .src = src, 
        .len = CHUNK_SIZE, 
        .mode = wpmode
    };

    do {
        log_debug("uffd_copy from src %lx to dst %lx mode %d", src, dst, wpmode);
        errno = 0;

        /* TODO: Use UFFD_USE_PWRITE (see kona)? */
        r = ioctl(fd, UFFDIO_COPY, &copy);
        if (r < 0) {
            log_debug("uffd_copy copied %lld bytes, addr=%lx, errno=%d", 
                copy.copy, dst, errno);

            if (errno == ENOSPC) {
                // The child process has exited.
                // We should drop this request.
                r = 0;
                break;

            } else if (errno == EEXIST) {
                wake_on_exist = true;
                if (wake_on_exist) {
                    /* We will assert in uffd_wake if we fail */
                    r = uffd_wake(fd, dst, CHUNK_SIZE);
                } else {
                    log_info("uffd_copy err EEXIST but wake_on_exist=false: %lx", 
                        dst);
                    BUG();
                }
                break;
            } else if (errno == EAGAIN) {
                /* layout change in progress; try again */
                if (retry == false) {
                    /* do not retry, let the caller handle it */
                    r = EAGAIN;
                    break;
                }
                (*n_retries)++;
            } else {
                log_info("uffd_copy errno=%d: unhandled error", errno);
                BUG();
            }
        }
    } while (r && errno == EAGAIN);
    return r;
}

/* for bigger chunks but does not handle wake */
int uffd_copy_size(int fd, unsigned long dst, unsigned long src, size_t size,
        int wpmode) {
    int r;
    struct uffdio_copy copy = {
        .dst = dst, 
        .src = (long)src, 
        .len = size, 
        .mode = wpmode
    };

    assert(size >= CHUNK_SIZE);
    r = ioctl(fd, UFFDIO_COPY, &copy);
    if (r < 0) log_err("UFFDIO_COPY");
    return r;
}

int uffd_wp(int fd, unsigned long addr, size_t size, int wpmode, bool retry,
        int *n_retries) {
    int r;
    struct uffdio_writeprotect wp = {
        .mode = wpmode,
        .range = {.start = addr, .len = size}
    };

    do {
        log_debug("uffd_wp start %p size %lx mode %d", (void *)addr, size, wpmode);
        errno = 0;
        r = ioctl(fd, UFFDIO_WRITEPROTECT, &wp);
        if (r < 0) {
            log_debug("uffd_wp errno=%d", errno);
            if (errno == EEXIST || errno == ENOSPC) {
                /* This page is already write-protected OR the child process 
                    has exited. We should drop this request. */
                r = 0;
                break;
            } else if (errno == EAGAIN) {
                /* layout change in progress; try again */
                if (retry == false) {
                    /* do not retry, let the caller handle it */
                    r = EAGAIN;
                    break;
                }
                (*n_retries)++;
            } else {
                log_info("uffd_wp errno=%d: unhandled error", errno);
                BUG();
            }
        }
    } while (r && errno == EAGAIN);
    return r;
}

int uffd_wp_add(int fd, unsigned long fault_addr, size_t size, bool retry, 
        int *n_retries) {
    return uffd_wp(fd, fault_addr, size, true, retry, n_retries);
}

/* NOTE: make sure that page exists before issuing this */
int uffd_wp_remove(int fd,unsigned long fault_addr, size_t size, bool retry, 
        int *n_retries) {
    return uffd_wp(fd, fault_addr, size, false, retry, n_retries);
}

int uffd_zero(int fd, unsigned long addr, size_t size, bool retry, int *n_retries) {
    int r;
    struct uffdio_zeropage zero = {
        .mode = 0,
        .range = {.start = addr, .len = size}
    };

    do {
        log_debug("uffd_zero to addr %lx size=%lu", addr, size);
        errno = 0;
        r = ioctl(fd, UFFDIO_ZEROPAGE, &zero);
        if (r < 0) {
            log_debug("uffd_zero copied %lld bytes, errno=%d", zero.zeropage, errno);

            if (errno == ENOSPC) {
                // The child process has exited.
                // We should drop this request.
                r = 0;
                break;

            } else if (errno == EAGAIN || errno == EEXIST) {
                // layout change in progress; try again
                errno = EAGAIN;
                if (retry == false) {
                    /* do not retry, let the caller handle it */
                    r = EAGAIN;
                    break;
                }
                (*n_retries)++;
            } else {
                log_info("uffd_zero errno=%d: unhandled error", errno);
                BUG();
            }
        }
    } while (r && errno == EAGAIN);
    return r;
}

int uffd_wake(int fd, unsigned long addr, size_t size) {
    // This will wake all threads waiting on this range:
    // From https://lore.kernel.org/lkml/5661B62B.2020409@gmail.com/T/
    //
    // userfaults won't wait in "pending" state to be read anymore and any
    // UFFDIO_WAKE or similar operations that has the objective of waking
    // userfaults after their resolution, will wake all blocked userfaults
    // for the resolved range, including those that haven't been read() by
    // userland yet.

    struct uffdio_range range = {.start = addr, .len = size};
    int r;
    r = ioctl(fd, UFFDIO_WAKE, &range);
    if (r < 0) log_err("UFFDIO_WAKE");
    return r;
}