
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
    zero_page = aligned_alloc(CHUNK_SIZE, CHUNK_SIZE);
    assert(zero_page);
    memset(zero_page, 0, CHUNK_SIZE);
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
    pflags_t pflags;
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

/* after receiving page fault */
enum fault_status handle_page_fault(int chan_id, fault_t* fault, 
    int* nevicts_needed, struct bkend_completion_cbs* cbs)
{
    pflags_t pflags, oldflags;
    struct region_t* mr;
    bool page_present, was_locked, no_wake;
    int i, ret, n_retries, nchunks;
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
            log_debug("%s - no ongoing work, start handling", FSTR(fault));

            /* we can handle write-protect right away */
            page_present = !!(pflags & PFLAG_PRESENT);
            if (page_present && (fault->is_wrprotect | fault->is_write)) {
                no_wake = fault->from_kernel ? false : true;
                ret = uffd_wp_remove(userfault_fd, fault->page, CHUNK_SIZE, 
                    no_wake, true, &n_retries);
                assertz(ret);
                RSTAT(UFFD_RETRIES) += n_retries;

                /* TODO: bump this item in the LRU lists */

                /* done */
                log_debug("%s - removed write protection", FSTR(fault));
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
            nchunks = 1;
            if (!(pflags & PFLAG_REGISTERED)) {
                assert(nchunks == 1);
                log_debug("%s - serving zero page", FSTR(fault));
                
                /* first time should naturally be a write */
                // fault_upgrade_to_write(fault, "fresh serving");  /* UNDO */

#ifndef NO_ZERO_PAGE
                /* copy zero page. TODO; Use UFFD_ZERO instead? */
                bool wrprotect;
                wrprotect = fault->is_read;
                no_wake = !fault->from_kernel;
                ret = uffd_copy(userfault_fd, fault->page, (unsigned long) 
                    zero_page, CHUNK_SIZE, wrprotect, no_wake, true, &n_retries);
                assertz(ret);
                RSTAT(UFFD_RETRIES) += n_retries;
                RSTAT(FAULTS_ZP)++;
                log_debug("%s - added zero page", FSTR(fault));
                
                /* done */
                set_page_flags(mr, fault->page, PFLAG_REGISTERED, NULL);
                return FAULT_DONE;
#endif
            }

            /* at this point, we can support read-ahead. see if we can get 
                * a lock on the next few pages that are missing */
            for (i = 1; i <= fault->rdahead_max; i++) {
                addr = fault->page + i * CHUNK_SIZE;
                if(!is_in_memory_region_unsafe(mr, addr))
                    break;
                /* try lock */
                pflags = set_page_flags(mr, addr, PFLAG_WORK_ONGOING, &oldflags);
                was_locked = !!(oldflags & PFLAG_WORK_ONGOING);
                page_present = !!(pflags & PFLAG_PRESENT);
                if (page_present || was_locked) 
                    break;
                nchunks++;
                fault->rdahead++;
            }
            if (nchunks > 1) {
                RSTAT(RDAHEADS)++;
                RSTAT(RDAHEAD_PAGES) += (nchunks - 1);
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
    pflags_t pgidx;

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

        /* TODO: shall we take mr references on active pages too? */
        pgnode->mr = f->mr;
        pgnode->addr = f->page;
        list_add_tail(&tmp, &pgnode->link);

        pgidx = rmpage_get_node_id(pgnode);
        pgidx = set_page_index_atomic(f->mr, f->page, pgidx);
        assertz(pgidx); /* old index must be 0 */
    }

    /* add to page list */
    spin_lock(&cold_pages.lock);
    list_append_list(&cold_pages.pages, &tmp);
    cold_pages.npages += (1 + f->rdahead);
    spin_unlock(&cold_pages.lock);

    /* set page flags */
    pflags_t flags = PFLAG_PRESENT;
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