/*
 * pgfault.c - support for page fault hints
 */

#include <sys/auxv.h>
#include "base/assert.h"
#include "base/vdso.h"
#include "rmem/backend.h"
#include "rmem/page.h"
#include "rmem/pgnode.h"
#include "rmem/common.h"
#include "rmem/region.h"
#include "runtime/pgfault.h"

BUILD_ASSERT(EDEN_MAX_READAHEAD <= FAULT_MAX_RDAHEAD_SIZE);

/* state */
__thread struct region_t* __cached_mr;

/* objects for vdso-based page checks */
const char *version = "LINUX_2.6";
const char *name_mapped = "__vdso_is_page_mapped";
const char *name_wp = "__vdso_is_page_mapped_and_wrprotected";
typedef long (*vdso_check_page_t)(const void *p);
vdso_check_page_t __is_page_mapped_vdso;
vdso_check_page_t __is_page_mapped_and_readonly_vdso;

/**
 * Initialize vDSO page check calls
 */
int __vdso_init()
{
#ifndef USE_VDSO_CHECKS
    BUG();
#endif

    /* find vDSO symbols */
    unsigned long sysinfo_ehdr;
    sysinfo_ehdr = getauxval(AT_SYSINFO_EHDR);
    if (!sysinfo_ehdr) {
        log_err("AT_SYSINFO_EHDR is not present");
        return -ENOENT;
    }

    vdso_init_from_sysinfo_ehdr(getauxval(AT_SYSINFO_EHDR));
    __is_page_mapped_vdso = (vdso_check_page_t)vdso_sym(version, name_mapped);
    if (!__is_page_mapped_vdso) {
        log_err("Could not find %s in vdso", name_mapped);
        return -ENOENT;
    }
    __is_page_mapped_and_readonly_vdso = (vdso_check_page_t)vdso_sym(version, name_wp);
    if (!__is_page_mapped_and_readonly_vdso) {
        log_err("Could not find %s in vdso", name_wp);
        return -ENOENT;
    }
    
    log_info("inited vdos page checks");
    return 0;
}


/* use VDSO-based page checks to determine an impending page fault */
static __always_inline bool __is_fault_pending_vdso(void *address, bool write)
{
    assert(__is_page_mapped_vdso);
    assert(__is_page_mapped_and_readonly_vdso);
    return (!write)
        ? !__is_page_mapped_vdso(address)
        : !__is_page_mapped_and_readonly_vdso(address);
}

/* use Eden's page state to determine an impending page fault */
static __always_inline bool __is_fault_pending_eden(void* address, bool write,
    bool hint_eviction)
{
    bool nofault;
    pgflags_t pflags;
    pginfo_t pginfo;
    bool page_present, page_dirty;
    struct region_t* mr;

    /* check support */
    assert(rmem_enabled);

    /* find the region the page belongs to */
#ifdef NO_DYNAMIC_REGIONS
    /* we only support one region now so caching an unsafe reference for future 
     * fast path accesses. this is not safe when we have multiple regions along
     * with dynamic region updates */
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
    nofault = page_dirty || (!write && page_present);


    /* regardless of fault or not, this check is a signal that page was going 
    * to be accessed. see if eviction wants to use that information */
    if (hint_eviction) {
#ifdef SC_EVICTION
        /* set the accessed bit if not already set */
        if (page_present && !(pflags & PFLAG_ACCESSED))
            set_page_flags(mr, (unsigned long) address, PFLAG_ACCESSED, NULL);
#endif
#ifdef LRU_EVICTION
        /* update time on the page to help with better eviction */
        if (page_present && !(pflags & PFLAG_EVICT_ONGOING)) {
            /* PFLAG_EVICT_ONGOING is not be enough to ensure that page node will 
            * exist when we access it below as we don't lock it. However, it takes
            * a long time from eviction start (when PFLAG_EVICT_ONGOING is set) to
            * actually removing the page node, so this should be super rare. It 
            * won't affect program correctness however because even if page node 
            * is released, it won't get deallocated (since we never free 
            * rmpage_node tcache entries) and will either stay in the cache or 
            * get assigned to another page in which case we would just be updating
            * epoch on a wrong page in a rare case - this is not that bad as 
            * page epoch it is only a hint for smarter eviction. */
            pgidx_t pgidx;
            struct rmpage_node* page;
            pgidx = get_index_from_pginfo_unsafe(pginfo);
            page = rmpage_get_node_by_id(pgidx);

            /* this may not always be true due to the comment above */
            // assert(page->addr & CHUNK_MASK == 0);
            // assert((page->addr == ((unsigned long) address & ~CHUNK_MASK));

            log_debug("fault hint on %p. updating epoch on page idx %d to %lu",
                address, pgidx, evict_epoch_now);
            page->epoch = evict_epoch_now;
        }
#endif
    }

    // log_debug("fault hinted on %p. faulting? %d", address, !nofault);
    RSTAT(ANNOT_HITS)++;
    return !nofault;
}

/* checks if a page at an address is in a state that results in page fault
 * (inlining in header file for low-overhead access) */
bool __is_fault_pending(void* address, bool write, bool hint_eviction)
{
#ifndef REMOTE_MEMORY
    log_err("REMOTE_MEMORY not defined, hinting is not supported");
    BUG();
#endif
#ifdef USE_VDSO_CHECKS
#if defined(SC_EVICTION) || defined(LRU_EVICTION)
#error "Eviction hinting not supported with VDSO checks"
#endif
    return __is_fault_pending_vdso(address, write);
#else
    return __is_fault_pending_eden(address, write, hint_eviction);
#endif
}