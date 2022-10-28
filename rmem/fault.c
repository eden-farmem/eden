
/*
 * fault.c - fault handling common
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include <unistd.h>

#include "base/list.h"
#include "rmem/backend.h"
#include "rmem/common.h"
#include "rmem/fault.h"
#include "rmem/page.h"
#include "rmem/stats.h"
#include "rmem/uffd.h"

/* fault handling common state */
__thread void* zero_page = NULL;
__thread char fstr[__FAULT_STR_LEN];

__thread unsigned int n_wait_q;
__thread struct list_head fault_wait_q;

/**
 * Per-thread zero page support
 */

void zero_page_init_thread()
{
    size_t size;
    size = CHUNK_SIZE * RMEM_MAX_CHUNKS_PER_OP;
    zero_page = aligned_alloc(CHUNK_SIZE, size);
    assert(zero_page);
    memset(zero_page, 0, size);
}

void zero_page_free_thread()
{
    assert(zero_page);
    free(zero_page);
}

/**
 * Fault handling
 */

/* are we already in the state that the fault hoped to acheive? */
bool is_fault_serviced(fault_t* f)
{    
    pgflags_t pflags;
    bool page_present, page_dirty, page_evicting;

    pflags = get_page_flags(f->mr, f->page);
    page_present = !!(pflags & PFLAG_PRESENT);
    page_dirty = !!(pflags & PFLAG_DIRTY);
    page_evicting = !!(pflags & PFLAG_EVICT_ONGOING);

    /* PFLAG_PRESENT is reliable except for some time during eviction. There is 
     * a small window during eviction (before madvise and clearing the 
     * PRESENT bit when a kernel fault might get here with the PRESENT
     * bit set while the page is absent */
    if(page_present && !(f->from_kernel && page_evicting)){
        if (f->is_read)
            return true;
        if((f->is_write || f->is_wrprotect) && page_dirty)
            return true;
    }
    return false;
}

/* checks if a page is in the same state as the faulting page to batch it 
 * together as a part of rdahead. this function only checks page flags and 
 * assumes that page locations relative to each other are already evaluated 
 * for read-ahead */
bool fault_can_rdahead(pgflags_t rdahead_page, pgflags_t base_page)
{
    /* both pages must be present or not-present */
    if ((base_page & PFLAG_PRESENT) != (rdahead_page & PFLAG_PRESENT))
        return false;

    /* if present, both must be dirty or non-dirty */
    if (!!(base_page & PFLAG_PRESENT)) 
        if ((base_page & PFLAG_DIRTY) != (rdahead_page & PFLAG_DIRTY))
            return false;
    
    /* both pages must be registered or not-registered */
    if ((base_page & PFLAG_REGISTERED) != (rdahead_page & PFLAG_REGISTERED))
        return false;

    /* TODO: anything else? */
    return true;
}

/* after receiving page fault */
enum fault_status handle_page_fault(int chan_id, fault_t* fault, 
    int* nevicts_needed, struct bkend_completion_cbs* cbs)
{
    struct region_t* mr;
    bool page_present, was_locked, no_wake;
    int i, ret, n_retries, nchunks;
    pgflags_t pflags, rflags, oldflags;
    unsigned long addr;
    unsigned long long pressure;
    uint64_t start_tsc, duration;
    *nevicts_needed = 0;

    /* see if this fault needs to be acted upon, because some other fault 
     * on the same page might have handled it by now */
    if (is_fault_serviced(fault)) {
        /* some other fault addressed the page, wake up if kernel fault */
        if (fault->from_kernel) {
            ret = uffd_wake(userfault_fd, fault->page, CHUNK_SIZE);
            assertz(ret);
        }
        /* fault done */
        log_debug("%s - fault done, was redundant", FSTR(fault));
        return FAULT_DONE;
    }
    else {
        /* try getting a lock on the page */
        mr = fault->mr;
        assert(mr);

        pflags = set_page_flags(mr, fault->page, PFLAG_WORK_ONGOING, &oldflags);
        was_locked = !!(oldflags & PFLAG_WORK_ONGOING);
        if (unlikely(was_locked)) {
            /* someone else is working on it, check back later */
            log_debug("%s - saw ongoing work, going to wait", FSTR(fault));
            return FAULT_IN_PROGRESS;
        }
        else {
            /* we are handling it */
            nchunks = 1;
            log_debug("%s - no ongoing work, start handling", FSTR(fault));

            /* at this point, we can check for read-ahead. see if we can get 
             * a lock on the next few pages that have similar requirements 
             * as the current page so we can make the same choices for them 
             * throughout the fault handling */
            for (i = 1; i <= fault->rdahead_max; i++) {
                addr = fault->page + i * CHUNK_SIZE;
                if(!is_in_memory_region_unsafe(mr, addr))
                    break;

                /* see if the page has similar faulting requirements as the 
                 * the base page */
                rflags = get_page_flags(mr, addr);
                if (!fault_can_rdahead(rflags, pflags))
                    break;

                /* try locking */
                rflags = set_page_flags(mr, addr, PFLAG_WORK_ONGOING, &oldflags);
                was_locked = !!(oldflags & PFLAG_WORK_ONGOING);
                if (was_locked) 
                    break;

                /* check again after locking */
                if (!fault_can_rdahead(rflags, pflags))
                    break;
                
                nchunks++;
                fault->rdahead++;
            }
            if (nchunks > 1) {
                RSTAT(RDAHEADS)++;
                RSTAT(RDAHEAD_PAGES) += fault->rdahead;
            }

            /* we can handle write-protect right away */
            page_present = !!(pflags & PFLAG_PRESENT);
            if (page_present && (fault->is_wrprotect | fault->is_write)) {
                no_wake = fault->from_kernel ? false : true;
                ret = uffd_wp_remove(userfault_fd, fault->page, 
                    nchunks * CHUNK_SIZE, no_wake, true, &n_retries);
                assertz(ret);
                RSTAT(UFFD_RETRIES) += n_retries;

                /* TODO: bump this item (and the rdaheads) in the LRU lists */

                /* done */
                log_debug("%s - removed wp for %d pages", FSTR(fault), nchunks);
                ret = set_page_flags_range(mr, fault->page, 
                    nchunks * CHUNK_SIZE, PFLAG_DIRTY);
                assert(ret == nchunks);
                return FAULT_DONE;
            }
            
            /* page not present, upgrade wp to write */
            if (fault->is_wrprotect) {
                fault_upgrade_to_write(fault, "from wrprotect on no page");
                RSTAT(WP_UPGRADES)++;
            }

#ifndef WP_ON_READ
            /* no WP on READ means every fault is a write fault */
            if (fault->is_read)
                fault_upgrade_to_write(fault, "no WP_ON_READ");
#endif

            /* first time adding page, use zero page */
            if (!(pflags & PFLAG_REGISTERED)) {
                /* first time should naturally be a write */
                // fault_upgrade_to_write(fault, "fresh serving");  /* UNDO */

#ifdef NO_ZERO_PAGE
                /* no zero page allowed for first serving; mark them 
                 * registered and proceed to read from remote */
                ret = set_page_flags_range(mr, fault->page, 
                    nchunks * CHUNK_SIZE, PFLAG_REGISTERED);
                assert(ret == nchunks);
#else
                log_debug("%s - serving %d zero pages", FSTR(fault), nchunks);

                /* copy zero page. TODO: Use UFFD_ZERO instead? */
                bool wrprotect;
                wrprotect = fault->is_read;
                no_wake = !fault->from_kernel;
                ret = uffd_copy(userfault_fd, fault->page, (unsigned long) 
                    zero_page, nchunks * CHUNK_SIZE, wrprotect, no_wake, 
                    true, &n_retries);
                assertz(ret);
                RSTAT(UFFD_RETRIES) += n_retries;
                RSTAT(FAULTS_ZP)++;
                log_debug("%s - added %d zero pages", FSTR(fault), nchunks);
                
                /* done */
                ret = set_page_flags_range(mr, fault->page, 
                    nchunks * CHUNK_SIZE, PFLAG_REGISTERED | PFLAG_PRESENT);
                assert(ret == nchunks);
                return FAULT_DONE;
#endif
            }

            /* send off page read */
            /* NOTE: kona also makes an attempt to read from rdma write_q
             * to preempt eviction but I won't do that here */
            start_tsc = 0;
            do {
                ret = rmbackend->post_read(chan_id, fault);
                if (ret == EAGAIN) {
                    /* start the timer the first time we start retrying */
                    if (!start_tsc)
                        start_tsc = rdtsc();

                    /* read queue is full, nothing to do but repeat and keep 
                     * checking for completions to free request slots. We can 
                     * just check for one completion here? */
                    rmbackend->check_for_completions(chan_id, cbs, 
                        RMEM_MAX_COMP_PER_OP, NULL, NULL);
		            cpu_relax();
                }
            } while(ret == EAGAIN);
            assertz(ret);
            fault->posted_chan_id = chan_id;

            /* save wait time if any */
            if (start_tsc) {
                duration = rdtscp(NULL) - start_tsc;
                RSTAT(BACKEND_WAIT_CYCLES) += duration;
            }

            /* book some memory for the pages */
            pressure = atomic_fetch_add_explicit(&memory_used, 
                nchunks * CHUNK_SIZE, memory_order_relaxed);
            pressure += nchunks * CHUNK_SIZE;
            if (pressure > local_memory)
                *nevicts_needed = nchunks;

            return FAULT_READ_POSTED;
        }
    }
    unreachable();
}

/* after reading the pages for a fault completed */
int fault_read_done(fault_t* f)
{
    int n_retries, r, i;
    bool wrprotect, no_wake;
    size_t size;
    struct rmpage_node* pgnode;
    struct list_head tmp;
    pgidx_t pgidx;
    pgflags_t flags;

    /* uffd copy the page back */
    assert(f->bkend_buf);
    wrprotect = f->is_read;
    no_wake = !f->from_kernel;
    size = (1 + f->rdahead) * CHUNK_SIZE;
    r = uffd_copy(userfault_fd, f->page, (unsigned long) f->bkend_buf, size, 
        wrprotect, no_wake, true, &n_retries);
    assertz(r);
    RSTAT(UFFD_RETRIES) += n_retries;

    /* free backend buffer */
    bkend_buf_free(f->bkend_buf);

    /* newly fetched pages - alloc page nodes */
    list_head_init(&tmp);
    for (i = 0; i <= f->rdahead; i++) { 
        /* get a page node */
        pgnode = rmpage_node_alloc();
        assert(pgnode);

        /* each page node gets an MR reference too which gets removed 
         * when the page is evicted out */
        __get_mr(f->mr);
        pgnode->mr = f->mr;
        pgnode->addr = f->page;
        list_add_tail(&tmp, &pgnode->link);

        pgidx = rmpage_get_node_id(pgnode);
        pgidx = set_page_index(f->mr, f->page, pgidx);
        assertz(pgidx); /* old index must be 0 */
    }

    /* add to page list */
    spin_lock(&cold_pages.lock);
    list_append_list(&cold_pages.pages, &tmp);
    cold_pages.npages += (1 + f->rdahead);
    spin_unlock(&cold_pages.lock);

    /* set page flags */
    flags = PFLAG_PRESENT;
    if (!wrprotect) flags |= PFLAG_DIRTY;
    set_page_flags_range(f->mr, f->page, size, flags);
    return 0;
}

/* after servicing fault is completely done */
void fault_done(fault_t* f) 
{
    size_t size;
    int marked;

    /* remove lock (in the ascending order) */
    size = (1 + f->rdahead) * CHUNK_SIZE;
    marked = clear_page_flags_range(f->mr, f->page, 
        size, PFLAG_WORK_ONGOING);
    assert(marked == (1 + f->rdahead));
    RSTAT(FAULTS_DONE)++;
    log_debug("%s - fault done", FSTR(f));

    /* free */
    put_mr(f->mr);
    fault_free(f);
}