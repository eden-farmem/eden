
/*
 * fault.c - fault handling common
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include <unistd.h>

#include "rmem/backend.h"
#include "rmem/fault.h"
#include "rmem/pflags.h"
#include "rmem/uffd.h"
#include "rmem/pflags.h"

#include "../defs.h"

/* fault handling common state */
__thread void* zero_page = NULL;
__thread char fstr[__FAULT_STR_LEN];

__thread struct dne_fifo_head dne_q;
__thread unsigned int n_dne_fifo;
__thread dne_q_item_t dne_q_items[DNE_QUEUE_SIZE];

__thread unsigned int n_wait_q;
__thread struct fault_wait_q_head fault_wait_q;

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
    int* nevicts_needed, struct completion_cbs* cbs)
{
    pflags_t pflags, oldflags;
    pflags_t flags[FAULT_MAX_RDAHEAD_SIZE+1];
    struct region_t* mr;
    bool page_present, was_locked, no_wake, wrprotect;
    int i, ret, n_retries, nchunks = 0;
    unsigned long addr;
    unsigned long long pressure;
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
            return FAULT_AGAIN;
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
                return FAULT_DONE;
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
                return FAULT_DONE;
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
             * to preempt eviction but I won't do that here */
            do {
                ret = rmbackend->post_read(chan_id, fault);
                if (ret == EAGAIN) {
                    /* read queue is full, nothing to do but repeat and keep 
                     * checking for completions to free request slots. We can 
                     * just check for one completion here? */
                    /* TODO: we may want to count idle cycles here */    
                    rmbackend->check_for_completions(chan_id, cbs, 
                        RMEM_MAX_COMP_PER_OP, NULL, NULL);
		            cpu_relax();
                }
            } while(ret == EAGAIN);
            assertz(ret);
            fault->posted_chan_id = chan_id;

            /* book some memory for the pages */
            pressure = atomic_fetch_add(&memory_booked, nchunks * CHUNK_SIZE);
            pressure += nchunks * CHUNK_SIZE;
            if (pressure > local_memory)
                *nevicts_needed = nchunks;

            return FAULT_READ_POSTED;
        }
    }
    unreachable();
}

/* after reading the pages for a fault completed */
int fault_read_done(fault_t* f, unsigned long buf_addr, size_t size)
{
    int n_retries, r;
    bool wrprotect, no_wake;
    assert(size == (1 + f->rdahead) * CHUNK_SIZE);

    /* uffd copy the page back */
    wrprotect = !f->is_write;
    no_wake = !f->from_kernel;
    r = uffd_copy(userfault_fd, f->page, buf_addr, size, wrprotect, no_wake, 
        true, &n_retries);
    assertz(r);
    RSTAT(UFFD_RETRIES) += n_retries;

    /* set page flags */
    pflags_t flags = PFLAG_PRESENT;
    if (!wrprotect) flags |= PFLAG_DIRTY;
    set_page_flags_range(f->mr, f->page, size, flags);
    return 0;
}

/* after servicing fault is completely done */
void fault_done(fault_t* fault) 
{
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

/**
 * Per-thread fault wait queue support
 * Holds off concurrent faults on a page while one of them service it 
 */
void fault_wait_q_init_thread()
{
    TAILQ_INIT(&fault_wait_q);
    n_wait_q = 0;
}