/**
 * mem.c - interposes on common memory functions to 1) disable preemption 
 * during these calls and 2) transparently provide Eden's remote memory  
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include <jemalloc/jemalloc.h>

#include "base/realmem.h"
#include "rmem/api.h"
#include "rmem/common.h"
#include "runtime/preempt.h"

#include "common.h"

/* jemalloc state */
__thread bool __from_jemalloc = false;
#define JEMALLOC_BEGIN() __from_jemalloc = true
#define JEMALLOC_END()   __from_jemalloc = false
#define FROM_JEMALLOC()  __from_jemalloc

/**
 * Runtime entry/exit helpers
 */

/* enter runtime and return if we were already in runtime */
bool runtime_enter()
{
    bool from_runtime;

    from_runtime = IN_RUNTIME();    
    if (!from_runtime)
        RUNTIME_ENTER();
    preempt_disable();
    return from_runtime;
}

/* exit runtime if specified */
void runtime_exit_on(bool exit)
{
    preempt_enable();
    if (exit)
        RUNTIME_EXIT();
}

/**
 * Some wrappers for RMem API
 */

void *rmlib_rmmap(void *addr, size_t length, int prot, 
    int flags, int fd, off_t offset)
{
    void *p = NULL;

    shim_bug_on((fd != -1) && (flags & MAP_ANONYMOUS),  \
        "bad mmap args: fd=%d, flags=%d", fd, flags);

    if (!(flags & MAP_ANONYMOUS) || !(flags & MAP_ANON) || (prot & PROT_EXEC) 
            || (flags & (MAP_STACK | MAP_FIXED | MAP_DENYWRITE))
            || (addr && !within_memory_region(addr)))
    {
        log_warn_ratelimited("WARNING! non-anon mmap");
        p = real_mmap(addr, length, prot, flags, fd, offset);
    } else {
        /* we don't support these flags */
        assertz(prot & PROT_EXEC);
        assertz(flags & MAP_STACK);
        assertz(flags & MAP_FIXED);
        assertz(flags & MAP_DENYWRITE);
        assert(fd == -1);
        assert(length);
        shim_log_debug("%s - using rmalloc", __func__);
        p = rmalloc(length);
    }
    return p;
}

/**
 *  Interface functions
 */

void *malloc(size_t size)
{
    bool from_runtime;
    void* retptr;

    from_runtime = runtime_enter();
    shim_log_debug("[%s], size=%lu, from-runtime=%d from-jemalloc=%d",
        __func__, size, from_runtime, FROM_JEMALLOC());

    if (from_runtime) {
        shim_log_debug("%s from runtime, using libc", __func__);
        retptr = real_malloc(size);
        goto out;
    }

    /* application malloc */
    shim_bug_on(!rmem_inited, "[%s] ERROR! rmem not initialized", __func__);
    JEMALLOC_BEGIN();
    shim_log_debug("using je_malloc");
    retptr = rmlib_je_malloc(size);
    JEMALLOC_END();

out:
    shim_log_debug("[%s] return=%p", __func__, retptr);
    runtime_exit_on(!from_runtime);
    return retptr;
}

void free(void *ptr)
{
    bool from_runtime;

    if (ptr == NULL)
        return;

    from_runtime = runtime_enter();
    shim_log_debug("[%s] ptr=%p from-runtime=%d from-jemalloc=%d", __func__,
        ptr, from_runtime, FROM_JEMALLOC());

    if (from_runtime) {
        shim_log_debug("[%s] from runtime, using libc", __func__);
        real_free(ptr);
        goto out;
    }

    /* if we are here, this should be a remote pointer. just warn for now */
    shim_bug_on(!rmem_inited, "[%s] ERROR! rmem not initialized", __func__);
    if (!within_memory_region(ptr)) {
        shim_log_debug("[%s] WARN - unexpected real ptr from app", __func__);
        real_free(ptr);
        goto out;
    }

    JEMALLOC_BEGIN();
    rmlib_je_free(ptr);
    JEMALLOC_END();

out:
    shim_log_debug("[%s] return", __func__);
    runtime_exit_on(!from_runtime);
}

void *realloc(void *ptr, size_t size)
{
    void *retptr;
    bool from_runtime;

    if (ptr == NULL) 
        return malloc(size);

    from_runtime = runtime_enter();
    shim_log_debug("[%s] ptr=%p, size=%lu, from-runtime=%d from-jemalloc=%d",
        __func__, ptr, size, from_runtime, FROM_JEMALLOC());

    if (from_runtime) {
        shim_log_debug("%s from runtime, using libc", __func__);
        retptr = real_realloc(ptr, size);
        goto out;
    }
    
    /* application realloc */
    shim_bug_on(!rmem_inited, "[%s] ERROR! rmem not initialized", __func__);
    JEMALLOC_BEGIN();
    retptr = rmlib_je_realloc(ptr, size);
    JEMALLOC_END();

out:
    shim_log_debug("[%s] return=%p", __func__, retptr);
    runtime_exit_on(!from_runtime);
    return retptr;
}

void *calloc(size_t nitems, size_t size)
{
    void *retptr;
    bool from_runtime;

    from_runtime = runtime_enter();
    shim_log_debug("[%s] number=%lu, size=%lu, from-runtime=%d", 
        __func__, nitems, size, from_runtime);

    if (from_runtime) {
        shim_log_debug("%s from runtime, using libc", __func__);
        retptr = real_calloc(nitems, size);
        goto out;
    }

    /* application calloc */
    shim_bug_on(!rmem_inited, "[%s] ERROR! rmem not initialized", __func__);
    JEMALLOC_BEGIN();
    retptr = rmlib_je_calloc(nitems, size);
    JEMALLOC_END();

out:
    shim_log_debug("[%s] return=%p", __func__, retptr);
    runtime_exit_on(!from_runtime);
    return retptr;
}

void *__internal_aligned_alloc(size_t alignment, size_t size)
{
    void *retptr;
    bool from_runtime;

    from_runtime = runtime_enter();
    shim_log_debug("[%s] alignment=%lu, size=%lu, from-runtime=%d", 
        __func__, alignment, size, from_runtime);

    if (from_runtime) {
        shim_log_debug("%s from runtime, using libc", __func__);
        retptr = real_memalign(alignment, size);
        goto out;
    }

    /* application aligned alloc */
    shim_bug_on(!rmem_inited, "[%s] ERROR! rmem not initialized", __func__);
    JEMALLOC_BEGIN();
    retptr = rmlib_je_aligned_alloc(alignment, size);
    JEMALLOC_END();

out:
    shim_log_debug("[%s] return=%p", __func__, retptr);
    runtime_exit_on(!from_runtime);
    return retptr;
}

int posix_memalign(void **ptr, size_t alignment, size_t size)
{
    shim_log_debug("[%s] ptr=%p, alignment=%lu, size=%lu", 
        __func__, ptr, alignment, size);
    /* TODO: need to check alignment, check return values */
    *ptr = __internal_aligned_alloc(alignment, size);
    return 0;
}

void *memalign(size_t alignment, size_t size)
{
    shim_log_debug("[%s] alignment=%lu, size=%lu", __func__, alignment, size);
    return __internal_aligned_alloc(alignment, size);
}

void *aligned_alloc(size_t alignment, size_t size)
{
    shim_log_debug("[%s] alignment=%lu, size=%lu", __func__, alignment, size);
    return __internal_aligned_alloc(alignment, size);
}

size_t malloc_usable_size(void * ptr)
{
    size_t size;
    bool from_runtime;

    from_runtime = runtime_enter();
    shim_log_debug("[%s] ptr %p", __func__, ptr);

    if (from_runtime) {
        shim_log_debug("%s from runtime, using libc", __func__);
        size = real_malloc_usable_size(ptr);
        goto out;
    }

    /* application call */
    shim_bug_on(!rmem_inited, "[%s] ERROR! rmem not initialized", __func__);
    JEMALLOC_BEGIN();
    size = rmlib_je_malloc_usable_size(ptr);
    JEMALLOC_END();

out:
    shim_log_debug("[%s] return=%ld", __func__, size);
    runtime_exit_on(!from_runtime);
    return size;
}

/**
 * Memory management functions (sys/mman.h).
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    void *retptr;
    bool from_runtime;

    from_runtime = runtime_enter();
    shim_log_debug("[%s] addr=%p,length=%lu,prot=%d,flags=%d,fd=%d,offset=%ld,from-"
    "runtime=%d", __func__, addr, length, prot, flags, fd, offset, from_runtime);

    /* First check for calls coming from jemalloc. These allocations are 
     * meant to be forwarded to remote memory; the tool must have been inited
     * by now as jemalloc calls are triggered by our own calls after init */
    if (FROM_JEMALLOC()) {
        shim_log_debug("internal jemalloc mmap, fwd to RLib: addr=%p", addr);
        shim_bug_on(!rmem_inited, "[je_mmap] ERROR! rmem not initialized");
        retptr = rmlib_rmmap(addr, length, prot, flags, fd, offset);
        goto out;
    }

    /* mmap coming directly from runtime */
    if (from_runtime) {
        shim_log_debug("%s from runtime, using real mmap", __func__);
        retptr = real_mmap(addr, length, prot, flags, fd, offset);
        goto out;
    }

    /* mmap coming from the app */
    shim_bug_on(!rmem_inited, "[%s] ERROR! rmem not initialized", __func__);
    shim_log_debug("%s directly from the app, fwd to RLib", __func__);
    retptr = rmlib_rmmap(addr, length, prot, flags, fd, offset);

out:
    shim_log_debug("[%s] return=%p", __func__, retptr);
    runtime_exit_on(!from_runtime);
    return retptr;
}

int munmap(void *ptr, size_t length)
{
    int ret;
    bool from_runtime;

    if (!ptr) 
        return 0;
    
    from_runtime = runtime_enter();
    shim_log_debug("[%s] ptr=%p, length=%lu, from-runtime=%d", __func__, ptr, 
        length, from_runtime);

    /* First check for calls coming from jemalloc. These deallocations are 
     * meant to be forwarded to remote memory; the tool must have been init'd 
     * by now as jemalloc calls are triggered by our own calls after init */
    if (FROM_JEMALLOC()) {
        shim_log_debug("internal jemalloc munmap, fwd to RLib: addr=%p", ptr);
        shim_bug_on(!rmem_inited, "[je_mmap] ERROR! rmem not initialized");
        assert(within_memory_region(ptr));
        ret = rmunmap(ptr, length);
        goto out;
    }

    if (from_runtime) {
        shim_log_debug("%s from runtime, using real munmap", __func__);
        assert(!within_memory_region(ptr));
        ret = real_munmap(ptr, length);
        goto out;
    }

    /* if we are here, this should be a remote pointer. just warn for now */
    shim_bug_on(!rmem_inited, "[%s] ERROR! rmem not initialized", __func__);
    if (!within_memory_region(ptr)) {
        shim_log_debug("[%s] WARN - unexpected real ptr from app", __func__);
        ret = real_munmap(ptr, length);
        goto out;
    }

    shim_log_debug("munmap directly from the app, fwd to RLib: addr=%p", ptr);
    ret = rmunmap(ptr, length);

out:
    shim_log_debug("[%s] return=%d", __func__, ret);
    runtime_exit_on(!from_runtime);
    return ret;
}

int madvise(void *addr, size_t length, int advice)
{
    int ret;
    bool from_runtime;

    from_runtime = runtime_enter();
    shim_log_debug("[%s] addr=%p, size=%lu, advice=%d, from-runtime=%d from-je=%d", 
        __func__, addr, length, advice, from_runtime, FROM_JEMALLOC());
    if (advice == MADV_DONTNEED)    shim_log_debug("MADV_DONTNEED flag");
    if (advice == MADV_HUGEPAGE)    shim_log_debug("MADV_HUGEPAGE flag");
    if (advice == MADV_FREE)        shim_log_debug("MADV_FREE flag");

    /* First check for calls coming from jemalloc. These deallocations are 
     * meant to be forwarded to remote memory; the tool must have been init'd 
     * by now as jemalloc calls are triggered by our own calls after init */
    if (FROM_JEMALLOC()) {
        shim_log_debug("internal jemalloc madvise, fwd to RLib: addr=%p", addr);
        shim_bug_on(!rmem_inited, "[je_mmap] ERROR! rmem not initialized");
        assert(within_memory_region(addr));
        ret = rmadvise(addr, length, advice);
        goto out;
    }

    if (from_runtime) {
        shim_log_debug("%s from runtime, using real madvise", __func__);
        ret = real_madvise(addr, length, advice);
        goto out;
    }

    /* if we are here, this should be a remote pointer. just warn for now */
    shim_bug_on(!rmem_inited, "[%s] ERROR! rmem not initialized", __func__);
    if (!within_memory_region(addr)) {
        shim_log_debug("[%s] WARN - unexpected real ptr from app", __func__);
        ret = real_madvise(addr, length, advice);
        goto out;
    }

    shim_log_debug("madvise directly from the app, fwd to RLib: addr=%p", addr);
    ret = rmadvise(addr, length, advice);

out:
    shim_log_debug("[%s] return=%d", __func__, ret);
    runtime_exit_on(!from_runtime);
    return ret;
}
