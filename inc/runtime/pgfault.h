/*
 * pgfault.h - gateway to scheduler-supported remote memory
 */

#pragma once

#include "base/assert.h"
#include "rmem/backend.h"
#include "rmem/pflags.h"
#include "rmem/region.h"

/* API */
/**
 * Pagefault API
 * hint the scheduler to check for an impending fault and take over if so
 */
#if defined(REMOTE_MEMORY) && defined(FAULT_HINTS)
#define hint_fault(addr,write,rd)                           \
    do {                                                    \
        if (__is_fault_pending(addr, write))                \
            kthr_send_fault_to_scheduler(addr, write, rd);  \
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
void kthr_send_fault_to_scheduler(void* address, bool write, int rdahead);

/* checks if a page at an address is in a state that results in page fault
 * (inlining in header file for low-overhead access) */
static inline bool __is_fault_pending(void* address, bool write)
{
    bool nofault;
#ifndef USE_VDSO_CHECKS
    pflags_t pflags;
    bool page_present, page_dirty;
    /* we only support one region now so caching an unsafe reference for future 
     * fast path accesses. this is neither correct nor safe when we have 
     * multiple regions along with regular region updates */
    if (unlikely(!__cached_mr)) {
        __cached_mr = get_first_region_unsafe();
        assert(__cached_mr);
    }
    assert(is_in_memory_region_unsafe(__cached_mr, (unsigned long) address));
    pflags = get_page_flags(__cached_mr, (unsigned long) address);
    page_present = !!(pflags & PFLAG_PRESENT);
    page_dirty = !!(pflags & PFLAG_DIRTY);
    nofault = page_dirty || (!write && page_present);
#else
    assert(__is_page_mapped_vdso);
    assert(__is_page_mapped_and_readonly_vdso);
    nofault = (!write)
        ? __is_page_mapped_vdso(address)
        : __is_page_mapped_and_readonly_vdso(address);
#endif
    // log_debug("fault hinted on %p. faulting? %d", address, !nofault);
    return !nofault;
}