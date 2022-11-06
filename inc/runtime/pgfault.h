/*
 * pgfault.h - gateway to scheduler-supported remote memory
 */

#pragma once

#include "base/assert.h"
#include "rmem/backend.h"
#include "rmem/page.h"
#include "rmem/common.h"
#include "rmem/region.h"

/**
 * Pagefault API
 * hint the scheduler to check for an impending fault and take over if so
 */
#ifdef REMOTE_MEMORY_HINTS
#ifndef REMOTE_MEMORY
#error "REMOTE_MEMORY" must be defined for hints
#endif

#define hint_fault(addr,write,rd)                           \
    do {                                                    \
        if (__is_fault_pending(addr, write))                \
            thread_park_on_fault(addr, write, rd);          \
    } while (0);
#define hint_read_fault_rdahead(addr,rd)    hint_fault(addr, false, rd)
#define hint_write_fault_rdahead(addr,rd)   hint_fault(addr, true,  rd)
#define hint_read_fault(addr)               hint_fault(addr, false, 0)
#define hint_write_fault(addr)              hint_fault(addr, true,  0)
#else
#define hint_fault(addr,write,rd)           do {} while(0)
#define hint_read_fault_rdahead(addr,rd)    do {} while(0)
#define hint_write_fault_rdahead(addr,rd)   do {} while(0)
#define hint_read_fault(addr)               do {} while(0)
#define hint_write_fault(addr)              do {} while(0)
#endif

/* back-compat API */
#define possible_read_fault_on 	            hint_read_fault
#define possible_write_fault_on	            hint_write_fault

/**
 * Pagefault Internal
 */
int __vdso_init();
typedef long (*vdso_check_page_t)(const void *p);
extern vdso_check_page_t __is_page_mapped_vdso;
extern vdso_check_page_t __is_page_mapped_and_readonly_vdso;
extern __thread struct region_t* __cached_mr;


/* use VDSO-based page checks to determine an impending page fault */
static __always_inline bool __is_fault_pending_vdso(void *address, bool write)
{
    assert(__is_page_mapped_vdso);
    assert(__is_page_mapped_and_readonly_vdso);
    return (!write)
        ? __is_page_mapped_vdso(address)
        : __is_page_mapped_and_readonly_vdso(address);
}


/* use Eden's page state to determine an impending page fault */
static __always_inline bool __is_fault_pending_eden(void* address, bool write)
{
    bool nofault;
    pgflags_t pflags;
    pginfo_t pginfo;
    pgidx_t pgidx;
    bool page_present, page_dirty,page_evicting;
    struct region_t* mr;
    struct rmpage_node* page;

    /* check support */
    assert(rmem_enabled);

#ifdef NO_DYNAMIC_REGIONS
    /* we only support one region now so caching an unsafe reference for future 
     * fast path accesses. this is neither correct nor safe when we have 
     * multiple regions along with regular region updates */
    if (unlikely(!__cached_mr)) {
        __cached_mr = get_first_region_safe();
        assert(__cached_mr);
    }
    mr = __cached_mr;
#else
    mr = get_region_by_addr_unsafe((unsigned long) address);
#endif
    assert(is_in_memory_region_unsafe(mr, (unsigned long) address));
    pginfo = get_page_info(mr, (unsigned long) address);
    pflags = get_flags_from_pginfo(pginfo);
    page_present = !!(pflags & PFLAG_PRESENT);
    page_dirty = !!(pflags & PFLAG_DIRTY);
    page_evicting = !!(pflags & PFLAG_EVICT_ONGOING);
    nofault = page_dirty || (!write && page_present);

#ifdef HINT_EVICTION
    /* update time on the page to help with better eviction */
    if (nofault && !page_evicting) {
        /* PFLAG_EVICT_ONGOING is not enough to ensure that page node will 
         * exist when we access it below as we don't lock it. However, it takes
         * a long time from eviction start (when PFLAG_EVICT_ONGOING is set) to
         * actually removing the page node, so this should be super rare. It 
         * won't affect program correctness however because even if page node 
         * is released, it will only get assigned to another page and we would 
         * just be updating epoch on a wrong page in the rarest case - which is 
         * not that bad as it only effects when the page is evicted out. */
        pgidx = get_index_from_pginfo(pginfo);
        page = rmpage_get_node_by_id(mr, pgidx);

        /* this may not always be true due to the comment above */
        assert(page->addr == (unsigned long) address);
        page->epoch = epoch_now;
    }
#endif

    // log_debug("fault hinted on %p. faulting? %d", address, !nofault);
    return !nofault;
}

/* checks if a page at an address is in a state that results in page fault
 * (inlining in header file for low-overhead access) */
static inline bool __is_fault_pending(void* address, bool write)
{
#ifndef USE_VDSO_CHECKS
    return __is_fault_pending_vdso(address, write);
#else
    return __is_fault_pending_eden(address, write);
#endif
}