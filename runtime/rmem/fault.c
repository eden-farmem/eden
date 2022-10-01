
/*
 * fault.c - fault handling common
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include <unistd.h>

#include "rmem/fault.h"
#include "rmem/pflags.h"
#include "rmem/uffd.h"

#include "../defs.h"

/* fault handling common state */
__thread void* zero_page = NULL;
__thread char fstr[__FAULT_STR_LEN];

struct dne_fifo_head dne_q;
unsigned int n_dne_fifo;
__thread dne_q_item_t dne_q_items[DNE_QUEUE_SIZE];

/**
 * Per-thread zero page support
 */

void zero_page_init_thread() {
    zero_page = aligned_alloc(CHUNK_SIZE, CHUNK_SIZE);
    assert(zero_page);
    memset(zero_page, 0, CHUNK_SIZE);
}

void zero_page_free_thread() {
    assert(zero_page);
    free(zero_page);
}

/**
 * Per-thread DNE support
 * Keeps recently fetched pages for a while before leaving then open for 
 * eviction */

void dne_q_init_thread() {
    TAILQ_INIT(&dne_q);
    n_dne_fifo = 0;
}

void dne_q_free_thread() {
    /* nothing to do */
}

void dne_on_new_fault(struct region_t *mr, unsigned long addr) 
{
    pflags_t oldflags;
    dne_q_item_t *q_item = NULL;
    if (n_dne_fifo >= DNE_QUEUE_SIZE) {
        // Queue is full. Remove oldest entry from head
        q_item = TAILQ_FIRST(&dne_q);
        TAILQ_REMOVE(&dne_q, q_item, link);

        log_debug("DNE FIFO pop and clearing DNE flag: %lx", q_item->addr);
        clear_page_flags(q_item->mr, q_item->addr, PFLAG_NOEVICT, &oldflags);
    } else {
        // Queue is not full yet, just use the next item.
        q_item = &dne_q_items[n_dne_fifo];
        n_dne_fifo++;
        log_debug("Increaing DNE FIFO size: %u", n_dne_fifo);
    }

    // Prepare the q_item for new insertion.
    q_item->addr = addr;
    q_item->mr = mr;

    // Actually add q_item to tail of queue
    log_debug("DNE FIFO push: %lx", q_item->addr);
    TAILQ_INSERT_TAIL(&dne_q, q_item, link);
    return;
}

/**
 * Fault handling
 */

bool handle_page_fault(fault_t* fault, int* nevicts_needed)
{
    pflags_t pflags, oldflags;
    pflags_t flags[FAULT_MAX_RDAHEAD_SIZE+1];
    struct region_t* mr;
    bool page_present, page_dirty, page_evicting, noaction, was_locked;
    bool no_wake, wrprotect, need_eviction = false, fdone = false;
    int i, ret, n_retries, nchunks;
    unsigned long addr;
    unsigned long long pressure;
    *nevicts_needed = 0;
    
    /* accounting */
    if (fault->is_read)         RSTAT(FAULTS_R)++;
    if (fault->is_write)        RSTAT(FAULTS_W)++;
    if (fault->is_wrprotect)    RSTAT(FAULTS_WP)++;

    /* find region */
    mr = get_region_by_addr_safe(fault->page);
    BUG_ON(!mr);    /* we dont do region deletions yet so it must exist*/
    assert(mr->addr);
    fault->mr = mr;

    /* see if this fault needs to be acted upon, because some other fault 
        * on the same page might have handled it by now. There is a small 
        * window, however, during eviction (before madvise and clearing the 
        * PRESENT bit when a kernel fault might get here with PRESENT
        * bit set but needs to be handled */
    pflags = get_page_flags(mr, fault->page);
    page_present = !!(pflags & PFLAG_PRESENT);
    page_dirty = !!(pflags & PFLAG_DIRTY);
    page_evicting = !!(pflags & PFLAG_EVICT_ONGOING);
    noaction = fault->is_read && page_present && 
        !(fault->from_kernel && page_evicting);
    noaction = (fault->is_write || fault->is_wrprotect) && page_dirty;
    if (unlikely(noaction)) {
        /* some other fault addressed the page, wake up if kernel fault */
        if (fault->from_kernel) {
            ret = uffd_wake(userfault_fd, fault->page, CHUNK_SIZE);
            assertz(ret);
        }
        fdone = true;
        goto out;
    }
    else {
        /* try getting a lock on the page */
        pflags = set_page_flags(mr, fault->page, PFLAG_WORK_ONGOING, &oldflags);
        was_locked = !!(oldflags & PFLAG_WORK_ONGOING);
        if (unlikely(was_locked)) {
            // someone else is working on it, add to waitq
            log_debug("%s - saw ongoing work, going to wait", FSTR(fault));
            /* TODO: add to waitq */

        }
        else {
            /* we are handling it */
            log_debug("%s - no ongoing work, start handling", FSTR(fault));

            /* we can handle write-protect right away */
            page_present = !!(pflags & PFLAG_PRESENT);
            if (page_present && (fault->is_wrprotect | fault->is_write)) {
                n_retries = 0;
                no_wake = fault->from_kernel ? false : true;
                ret = uffd_wp_remove(userfault_fd, fault->page, CHUNK_SIZE, 
                    no_wake, true, &n_retries);
                assertz(ret);
                RSTAT(UFFD_RETRIES)++;

                /* done */
                log_debug("%s - removed write protection", FSTR(fault));
                fdone = true;
                goto out;
            }
            else {
                /* upgrade to write fault */
                fault_upgrade_to_write(fault);
                RSTAT(WP_UPGRADES)++;
            }

#ifndef WP_ON_READ
            /* no WP on READ means every fault is a write fault */
            if (fault->is_read)
                fault_upgrade_to_write(fault);
#endif

            /* first time adding page, use zero page */
            if (!(pflags & PFLAG_REGISTERED)) {
                assert(nchunks == 1);
                log_debug("%s - serving zero page", FSTR(fault));
                
                /* first time should naturally be a write */
                fault_upgrade_to_write(fault);

                /* copy zero page. TODO; Use UFFD_ZERO instead? */
                n_retries = 0;
                wrprotect = !fault->is_write;
                no_wake = !fault->from_kernel;
                ret = uffd_copy(userfault_fd, fault->page, (unsigned long) 
                    zero_page, CHUNK_SIZE, wrprotect, no_wake, true, &n_retries);
                assertz(ret);
                RSTAT(UFFD_RETRIES) += n_retries;
                RSTAT(FAULTS_ZP)++;
                
                /* done */
                log_debug("%s - added zero page", FSTR(fault));
                fdone = true;
                goto out;
            }

            /* at this point, we can support read-ahead. see if we can get 
                * a lock on the next few pages that are missing */
            flags[0] = pflags;
            nchunks = 1;
            for (i = 1; i <= fault->rdahead_max; i++) {
                addr = fault->page + i * CHUNK_SIZE;
                if(!is_in_memory_region_unsafe(mr, addr))
                    break;
                /* try lock */
                flags[i] = set_page_flags(mr, addr, PFLAG_WORK_ONGOING, &oldflags);
                was_locked = !!(oldflags & PFLAG_WORK_ONGOING);
                page_present = !!(flags[i] & PFLAG_PRESENT);
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
                * to preempt eviction but I won't handle that here */
            // ret = rmbackend->post_read_async(fault); /* TODO */
            assertz(ret);

            /* book some memory for the pages */
            pressure = atomic_fetch_add(&memory_booked, nchunks * CHUNK_SIZE);
            pressure += nchunks * CHUNK_SIZE;
            need_eviction = (pressure > local_memory);
            if (need_eviction)
                *nevicts_needed = (local_memory - pressure) / CHUNK_SIZE;
        }
    }
    
out:
    if (fdone)
        fault_done(fault);
    return need_eviction;
}

void fault_done(fault_t* fault) {
    unsigned long addr;
    int i;
    pflags_t oldflags;

    /* set do-not-evict and add to DNE (if not hinted as single-use) */
    /* TODO: how useful is this? */
    if (!fault->single_use) {
        for (i = 0; i <= fault->rdahead; i++) {
            addr = fault->page + i * CHUNK_SIZE;
            set_page_flags(fault->mr, addr, PFLAG_NOEVICT, &oldflags);
            /* only add if not already */
            if (!(oldflags & PFLAG_NOEVICT))
                dne_on_new_fault(fault->mr, addr);
        }
    }

    /* remove lock */
    clear_page_flags(fault->mr, fault->page, PFLAG_WORK_ONGOING, &oldflags);
    RSTAT(FAULTS_DONE)++;
    log_debug("%s - fault done", FSTR(fault));

    /* free */
    put_mr(fault->mr);
    fault_free(fault);
}

