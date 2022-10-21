/*
 * rmem_api.c - externally-visible remote memory allocation functions
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>

#include "base/log.h"
#include "base/mem.h"
#include "base/atomic.h"
#include "rmem/common.h"
#include "rmem/eviction.h"
#include "rmem/page.h"
#include "rmem/region.h"
#include "defs.h"

/* TODO: Not sure why kona was doing this; remove and see. */
size_t __update_size(size_t size)
{
    unsigned long order;
    /* minimum mapping allowed is 1 page to keep allocations page aligned */
    size = (size < PAGE_SIZE ? PAGE_SIZE : size);
    /* increase size to next power of two */
    order = PAGE_SIZE;
    while (order < size) order <<= 1;
    size = align_up(size, order);
    return size;
}

/**
 * Support for malloc
 */
void *rmalloc(size_t size)
{
    RUNTIME_ENTER();
    void *retptr = NULL;
    struct region_t *mr;
    unsigned long long offset;
    bool booked = false;

    log_debug("rmalloc with size %ld", size);
    if (size <= 0)
        goto OUT;
    size = __update_size(size);

    /* find available region and atomically grab memory */
    mr = get_available_region(size);
    if (mr == NULL)
        goto OUT;

    do {
        offset = atomic_load(&mr->current_offset);
        BUG_ON(offset + size > mr->size);	/* out of memory */
        booked = atomic_compare_exchange_weak(&mr->current_offset, &offset, 
            offset + size);
    } while(!booked);

    /* found */
    log_debug("rmalloc allocation: addr: %llx, end=%llx, length=%ld",
        mr->addr + offset, mr->addr + offset + size, size);
    retptr = (void *)(mr->addr + offset);
    RSTAT(MALLOC_SIZE) += size;
    put_mr(mr);

OUT:
    RUNTIME_EXIT();
    log_debug("rmalloc done, ptr %p", retptr);
    return retptr;
}

/**
 * Support for realloc
 */
void *rmrealloc(void *ptr, size_t size, size_t old_size)
{
    RUNTIME_ENTER();
    void *retptr = NULL;
    struct region_t *mr;
    unsigned long long ptr_offset, offset;
    bool booked = false, can_resize_inplace = false;

    log_debug("rmrealloc at %p with size %ld", ptr, size);
    if (size <= 0)
        goto OUT;
    size = __update_size(size);

    if (ptr == NULL || old_size <= 0) {
        retptr = rmalloc(size);
        goto OUT;
    }

    /* find associated region and atomically grab memory */
    mr = get_region_by_addr_safe(size);
    if (mr == NULL) {
        log_err("realloc: cannot find the region with ptr");
        BUG();
    }

    /* not handling size decrements in the proper way for now - we just return 
     * the same region with a hole in it (doing it the proper way would also
     * make eviction more complicated as current_offset is not expected to go 
     * down)*/
    if (size < old_size) {
        retptr = ptr;
        goto OUT;
    }

    do {
        offset = atomic_load_explicit(&mr->current_offset, memory_order_acquire);
        ptr_offset = (unsigned long)ptr - mr->addr;
        can_resize_inplace = (offset == ptr_offset + old_size);
        if (!can_resize_inplace)
            break;
        BUG_ON(ptr_offset + size > mr->size);	/* out of memory */
        booked = atomic_compare_exchange_weak(&mr->current_offset, &offset, 
            ptr_offset + size);
    } while(!booked);

    assert(booked || !can_resize_inplace);
    if (booked) {
        /* resized in place */
        retptr = ptr;
        goto OUT;
    } else {
        /* cannot resize inplace, alloc new space and move */
        retptr = rmalloc(size);
        memmove(retptr, ptr, min(old_size, size));
        goto OUT;
    }
    put_mr(mr);
OUT:
    RUNTIME_EXIT();
    log_debug("rmrealloc done at %p, newptr %p", ptr, retptr);
    return retptr;
}

/**
 * Support for munmap
 */
int rmunmap(void *addr, size_t length)
{
    RUNTIME_ENTER();
    struct region_t *mr;
    unsigned long offset, page, max_addr;
    int ret = 0;
    pflags_t oldflags, flags;
    bool locked;

    log_debug("rmunmap at %p", addr);
    if (!addr) 
        goto OUT;

    /* find associated region */
    mr = get_region_by_addr_safe((unsigned long) addr);
    if (mr == NULL) {
        log_warn("rmunmap: cannot find the region with ptr");
        ret = -1;
        goto OUT;
    }

    /* get a lock on all the pages so we don't have concurrent page faults */
    /* TODO: this can be a costly operation for large sizes? */
    max_addr = mr->addr + atomic_load(&mr->current_offset);
    BUG_ON((unsigned long) addr + length > max_addr);
    for (offset = 0; offset < length; offset += CHUNK_SIZE) {
        page = (unsigned long) addr + offset;
        if (page >= max_addr)
            break;

        do {
            set_page_flags(mr, page, PFLAG_WORK_ONGOING, &oldflags);
            locked = !(oldflags & PFLAG_WORK_ONGOING);
            cpu_relax();
        } while(!locked);
    }

    /* Now we can do munmap (if MADVISE_REGISTER_UNMAP is defined, this will
     * result in a notif to the handler but I don't see why that would help 
     * except add perf overhead as we lock all the pages anyway */
    ret = munmap(addr, length);

    /* unlock all pages while also setting them unregistered if munmap worked */
    flags = PFLAG_WORK_ONGOING;
    if (ret == 0)   flags |= PFLAG_REGISTERED;
    clear_page_flags_range(mr, (unsigned long) addr, length, flags);
    if (ret == 0)
        RSTAT(MUNMAP_SIZE) += length;

OUT:
    RUNTIME_EXIT();
    log_debug("rmunmap done at %p, retcode %d", addr, ret);
    return ret;
}

/**
 * Support for madvise
 */
int rmadvise(void *addr, size_t length, int advice)
{
    RUNTIME_ENTER();
    struct region_t *mr;
    unsigned long offset, page, max_addr;
    unsigned long long pressure, size;
    int ret = 0, marked;
    pflags_t oldflags, flags;
    bool locked;

    log_debug("rmadvise at %p size %ld advice %d", addr, length, advice);
    if (!addr) 
        goto OUT;

    /* we don't know how to deal with other advices yet */
    if (advice != MADV_FREE && advice != MADV_DONTNEED) 
        goto OUT;

    /* find associated region */
    mr = get_region_by_addr_safe((unsigned long) addr);
    if (mr == NULL) {
        log_warn("rmadvise: cannot find the region with ptr");
        ret = -1;
        goto OUT;
    }

    /* get a lock on all the pages so we don't have concurrent page faults */
    /* TODO: this can be a costly operation for large sizes? */
    max_addr = mr->addr + atomic_load(&mr->current_offset);
    BUG_ON((unsigned long) addr + length > max_addr);
    for (offset = 0; offset < length; offset += CHUNK_SIZE) {
        page = (unsigned long) addr + offset;
        if (page >= max_addr)
            break;

        do {
            set_page_flags(mr, page, PFLAG_WORK_ONGOING, &oldflags);
            locked = !(oldflags & PFLAG_WORK_ONGOING);
            cpu_relax();
        } while(!locked);
    }

    /* Now we can do madvise (if MADVISE_REGISTER_REMOVE is defined, this will
     * result in a notif to the handler but I don't see why that would help 
     * except add perf overhead as we lock all the pages anyway */
    ret = madvise(addr, length, advice);

    /* unlock all pages while also setting them unregistered if munmap worked */
    flags = PFLAG_WORK_ONGOING;
    if (ret == 0)   flags |= PFLAG_PRESENT;
    marked = 0;
    for (offset = 0; offset < length; offset += CHUNK_SIZE) {
        page = (unsigned long) addr + offset;
        if (page >= max_addr)
            break;

        assert(!!(oldflags & PFLAG_WORK_ONGOING));  /* assert locked before */
        if (!!(oldflags & PFLAG_PRESENT))
            marked++;
    }

    if (ret == 0) {
        /* update pressure */
        size = marked * CHUNK_SIZE;
        atomic_fetch_sub_explicit(&memory_booked, size, memory_order_relaxed);
        pressure = atomic_fetch_sub_explicit(&memory_used, size, memory_order_relaxed);
        log_debug("Freed %d page(s), pressure=%lld", marked, pressure - size);
        RSTAT(MADV_SIZE) += length;
    }

OUT:
    RUNTIME_EXIT();
    log_debug("rmadvise done at %p, retcode %d", addr, ret);
    return ret;
}

/*** Unsupported (but potentially required or useful) functions ***/

/**
 * Free a region
 * (using jemalloc interpostion hopefully avoids this)
 */
int rmfree(void *ptr) {
    RUNTIME_ENTER();
    log_debug("rfree");
    /* TODO */
    RUNTIME_EXIT();
    return 0;
}

/**
 * Pins pages for a while in local memory
 */
int rmpin(void *addr, size_t size)
{
    RUNTIME_ENTER();
    log_debug("rmpin for %p size %ld", addr, size);
    BUG();  /* not supported, should work with eviction */
    RUNTIME_EXIT();
    return 0;
}

/**
 * Flushes pages to remote memory
 */
int rmflush(void *addr, size_t size, bool evict) {
    RUNTIME_ENTER();
    log_debug("rflush for %p size %ld", addr, size);
    BUG();  /* not supported, should work with eviction */
    RUNTIME_EXIT();
    return 0;
}