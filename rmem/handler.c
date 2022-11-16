/*
 * handler.h - dedicated handler core for remote memory
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <linux/userfaultfd.h>
#include <unistd.h>

#include "base/cpu.h"
#include "rmem/backend.h"
#include "rmem/common.h"
#include "rmem/config.h"
#include "rmem/dump.h"
#include "rmem/eviction.h"
#include "rmem/fault.h"
#include "rmem/handler.h"
#include "rmem/page.h"
#include "rmem/region.h"
#include "rmem/uffd.h"

#ifndef RMEM_STANDALONE
#include "../runtime/defs.h"
#endif

/* handler state */
__thread struct hthread *my_hthr = NULL;
__thread int current_stealing_kthr_id = -1;
__thread unsigned long current_blocking_page = 0;
__thread bool current_page_unblocked = false;

/* check if a fault already exists in the wait queue */
bool does_fault_exist_in_wait_q(struct fault *fault)
{
    struct fault *f;
    list_for_each(&my_hthr->fault_wait_q, f, link) {
        if (f->page == fault->page)
            return true;
    }
    return false;
}

/* called after fetched pages are ready on handler read completions */
int hthr_fault_read_done(fault_t* f)
{
    int r;
    r = fault_read_done(f);
    assertz(r);

    /* release fault */
    fault_done(f);
    return 0;
}


#ifndef RMEM_STANDALONE

/** 
 * Targeted stealing from Shenango kthreads
 */

/* called on the completions stolen from the shenango kthreads */
int hthr_fault_read_steal_done(fault_t* f)
{
    int r;
    struct kthread* owner;

    /* get owner kthread */
    assert(current_stealing_kthr_id >= 0);
    owner = allks[current_stealing_kthr_id];
    assert(owner);
    log_debug("%s - stolen by handler", FSTR(f));

    /* check for bugs */
    assert(f);
    assert(my_hthr->bkend_chan_id != f->posted_chan_id);    /* assert steal */
    assert(owner->bkend_chan_id == f->posted_chan_id);      /* assert owner */
    assert(!f->from_kernel);        /* stole it from shenango threads */
    assert(f->bkend_buf);           /* expecting read buffer */
    assert(!f->stolen_from_cq);     /* no double-steal */

    /* mark as stolen */
    f->stolen_from_cq = 1;
    RSTAT(READY_STEALS)++;

    /* finish servicing the fault */
    r = fault_read_done(f);
    assertz(r);

    /* set the thread ready */
    assert(f->thread);
    thread_ready_safe(owner, f->thread);

    /* check if this is the target blocking page */
    if (f->page == current_blocking_page)
        current_page_unblocked = true;

    /* release fault */
    fault_done(f);
    return 0;
}

/* try to unblock a kernel/handler fault that has been waiting for a while.
 * currently, we look at the kthread that locked the page and perform 
 * targeted stealing to progress its faults and release the page */
bool handler_try_unblock_fault(fault_t* f)
{
    struct kthread* owner;
    int nfaults_stolen, ntotal;
    pginfo_t pginfo;
    pgthread_t kthr_id;
    pgflags_t pflags;
    bool unblocked;

    /* check if already unlocked */
    pginfo = get_page_info(f->mr, f->page);
    pflags = get_flags_from_pginfo(pginfo);
    if (!(pflags & PFLAG_WORK_ONGOING))
        /* unlocked */
        return true;
    
    /* get the kthread that is working on the faulting page */
    kthr_id = get_thread_from_pginfo(pginfo);
    if (!kthr_id)
        /* then it may have moved on by the time we got here */
        return false;

    owner = allks[kthr_id - 1];
    assert(owner);
    log_debug("%s - found kthread %d blocking the page", FSTR(f), kthr_id-1);

    /* save the owner kthread id globally so it is visible to the completion
     * callbacks. similarly, also save the blocking page so we can figure out 
     * if we really unblocked the target page in the callbacks */
    assert(current_stealing_kthr_id == -1);
    assert(current_blocking_page == 0);
    assert(!current_page_unblocked);
    current_stealing_kthr_id = kthr_id - 1;
    current_blocking_page = f->page;
    store_release(&current_page_unblocked, false);

    /* check completions with handler stealing callbacks; we don't need to 
     * lock the owner thread as completion-stealing is thread-safe */
    ntotal = rmbackend->check_for_completions(owner->bkend_chan_id, 
        &hthr_stealer_cbs, RMEM_MAX_COMP_PER_OP, &nfaults_stolen, NULL);
    log_debug("handler stole %d completions on chan %d, %d of them reads",
            ntotal, owner->bkend_chan_id, nfaults_stolen);

    /* remove the stolen faults from owner kthreads count */
    if (nfaults_stolen) {
        spin_lock(&owner->pf_lock);
        owner->pf_pending -= nfaults_stolen;
        spin_unlock(&owner->pf_lock);
    }

    /* stealing done; reset the globally visible state */
    unblocked = load_acquire(&current_page_unblocked);
    assert(current_stealing_kthr_id == (kthr_id - 1));
    current_stealing_kthr_id = -1;
    current_blocking_page = 0;
    current_page_unblocked = false;

    return unblocked;
}

#endif

/* poll for faults/other notifications coming from UFFD */
static inline fault_t* read_uffd_fault()
{
    ssize_t read_size;
    struct uffd_msg message;
    struct fault* fault;
    unsigned long long addr, flags, size;
    struct region_t* mr;

    struct pollfd evt = { .fd = userfault_fd, .events = POLLIN };
    if (poll(&evt, 1, 0) > 0) {
        /* we have something pending on ths fd */
        if ((evt.revents & POLLERR) || (evt.revents & POLLHUP)) {
            log_warn_ratelimited("unexpected wrong poll event from uffd");
            return NULL;
        }

        /* get fault object to save the read */
        fault = fault_alloc();
        if (unlikely(!fault)) {
            log_debug("couldn't get a fault object");
            return NULL;    /* we'll try again later */
        }
        memset(fault, 0, sizeof(fault_t));

        read_size = read(evt.fd, &message, sizeof(struct uffd_msg));
        if (unlikely(read_size != sizeof(struct uffd_msg))) {
            /* EAGAIN is fine; another handler may have gotten to it first */
            if (errno != EAGAIN) {
                log_err("unexpected read size %ld, errno %d on uffd", 
                    read_size, errno);
                BUG();
            }
            fault_free(fault);
            return NULL;
        }

        /* we have successfully read data into message */
        switch (message.event) {
            case UFFD_EVENT_PAGEFAULT:
                addr = message.arg.pagefault.address;
                flags = message.arg.pagefault.flags;
                log_debug("uffd pagefault event %d: addr=%llx, flags=0x%llx",
                    message.event, addr, flags);
                fault->page = addr & ~CHUNK_MASK;
                fault->is_wrprotect = !!(flags & UFFD_PAGEFAULT_FLAG_WP);
                fault->is_write = !!(flags & UFFD_PAGEFAULT_FLAG_WRITE);
                fault->is_read = !(fault->is_write || fault->is_wrprotect);
                fault->from_kernel = true;
                fault->rdahead_max = 0;   /*no readaheads for kernel faults*/
                fault->rdahead  = 0;
                /* NOTE: can also save thread id: message.arg.pagefault.feat.ptid */
                return fault;
            case UFFD_EVENT_FORK:
                /* fork not supported */
                log_err("faulted process performed a fork or clone, fd:%d",
                    message.arg.fork.ufd);
                BUG();
            case UFFD_EVENT_REMAP:
                /* remap: hopefully won't be here due to interposition? */
                log_warn("faulted process performed a mremap");
                return NULL;
            case UFFD_EVENT_REMOVE:
                /* we get here for evicted pages with REGISTER_MADVISE_REMOVE */
#ifndef REGISTER_MADVISE_REMOVE
                log_err("REMOVE event unexpected without REGISTER_MADVISE_REMOVE");
                BUG();
#endif
                log_debug("process madvise at %p to %p, size=%llu",
                    (void *)message.arg.remove.start,
                    (void *)(message.arg.remove.end - 1),
                    message.arg.remove.end - message.arg.remove.start);
                addr = message.arg.remove.start & ~CHUNK_MASK;
                size = message.arg.remove.end - message.arg.remove.start;

                /* mark pages not present and adjust memory counters */
                mr = get_region_by_addr_safe(addr);
                /* we should have locked the page by this point */
                assert(!!(get_page_flags(mr, addr) & PFLAG_WORK_ONGOING));
                clear_page_flags_range(mr, addr, size, PFLAG_PRESENT);
                put_mr(mr);
                RSTAT(UFFD_NOTIF)++;
                return NULL;
            case UFFD_EVENT_UNMAP:
                /* we get here (presumably) for unintercepted munmap */
#ifndef REGISTER_MADVISE_UNMAP
                log_err("UNMAP event unexpected without REGISTER_MADVISE_UNMAP");
                BUG();
#endif
                log_debug("process munmap at %p to %p, size=%llu",
                    (void *)message.arg.remove.start,
                    (void *)(message.arg.remove.end - 1),
                    message.arg.remove.end - message.arg.remove.start);
                addr = message.arg.remove.start & ~CHUNK_MASK;
                size = message.arg.remove.end - message.arg.remove.start;

                /* deregister pages (we will adjust memory after eviction) */
                mr = get_region_by_addr_safe(addr);
                /* we should have locked the page by this point */
                assert(!!(get_page_flags(mr, addr) & PFLAG_WORK_ONGOING));
                clear_page_flags_range(mr, addr, size, PFLAG_REGISTERED);
                /* TODO: add these pages as readily evictible!! */
                put_mr(mr);
                RSTAT(UFFD_NOTIF)++;
                return NULL;
            default:
                log_err("unknown uffd event %d", message.event);
                BUG();
        }
    }
    return NULL;
}

/**
 * Main handler thread function
 */
static void* rmem_handler(void *arg) 
{
    bool need_eviction, unblocked;
    unsigned long long pressure;
    fault_t *fault, *next;
    int nevicts, nevicts_needed, batch, r;
    enum fault_status fstatus;
    struct region_t* mr;
    assert(arg != NULL);        /* expecting a hthread_t */
    my_hthr = (hthread_t*) arg; /* save our hthread_t */
    unsigned long now_tsc;

    /* init */
    r = thread_init_perthread();    /* for tcache support */
	assertz(r);
    rmem_common_init_thread(&my_hthr->bkend_chan_id, my_hthr->rstats, 0);
    list_head_init(&my_hthr->fault_wait_q);
    my_hthr->n_wait_q = 0;

    /* do work */
    while(!my_hthr->stop) {
        need_eviction = false;
        nevicts = nevicts_needed = 0;
        now_tsc = rdtsc();

        /* pick faults from the backlog (wait queue) first */
        fault = list_top(&my_hthr->fault_wait_q, fault_t, link);
        while (fault != NULL) {
            next = list_next(&my_hthr->fault_wait_q, fault, link);
            fstatus = handle_page_fault(my_hthr->bkend_chan_id, fault, 
                &nevicts_needed, &hthr_cbs);
            switch (fstatus) {
                case FAULT_DONE:
                    log_debug("%s - done, released from wait", FSTR(fault));
                    list_del_from(&my_hthr->fault_wait_q, &fault->link);
                    assert(my_hthr->n_wait_q > 0);
                    my_hthr->n_wait_q--;
                    fault_done(fault);
                    break;
                case FAULT_READ_POSTED:
                    log_debug("%s - done, released from wait", FSTR(fault));
                    list_del_from(&my_hthr->fault_wait_q, &fault->link);
                    assert(my_hthr->n_wait_q > 0);
                    my_hthr->n_wait_q--;
                    if (nevicts_needed > 0)
                        goto eviction;
                    break;
                case FAULT_IN_PROGRESS:
                    log_debug("%s - not released from wait", FSTR(fault));
                    RSTAT(WAIT_RETRIES)++;

#ifndef RMEM_STANDALONE
                    /* if the fault has been waiting too long, try unblocking */
                    if (unlikely(fault->tstamp_tsc && 
                        (now_tsc - fault->tstamp_tsc) > 
                            HANDLER_WAIT_BEFORE_STEAL_US * cycles_per_us))
                    {
                        log_debug("%s - waited too long", FSTR(fault));
                        fault->tstamp_tsc = now_tsc;
                        unblocked = handler_try_unblock_fault(fault);
                        /* if unblocked, try this fault again */
                        if (unblocked)
                            continue;
                    }
#endif
                    break;
            }

            /* go to next fault */
            fault = next;
        }

        /* check for incoming uffd faults */
        fault = read_uffd_fault();
        if (fault) {
            /* accounting */
            RSTAT(FAULTS)++;
            if (fault->is_read)         RSTAT(FAULTS_R)++;
            if (fault->is_write)        RSTAT(FAULTS_W)++;
            if (fault->is_wrprotect)    RSTAT(FAULTS_WP)++;

            /* find region */
            mr = get_region_by_addr_safe(fault->page);
            BUG_ON(!mr);  /* we dont do region deletions yet so it must exist */
            assert(mr->addr);
            fault->mr = mr;

            /* start handling fault */
            fstatus = handle_page_fault(my_hthr->bkend_chan_id, fault, 
                &nevicts_needed, &hthr_cbs);
            switch (fstatus) {
                case FAULT_DONE:
                    fault_done(fault);
                    break;
                case FAULT_IN_PROGRESS:
                    /* handler thread should not see duplicate faults as we 
                     * don't expect kernel to send the same fault twice; 
                     * although duplicate faults seems to occur when debugging 
                     * with GDB after a previously faulting thread is let go 
                     * from a breakpoint, so comment it out when debugging */
                    // assert(!does_fault_exist_in_wait_q(fault));

                    /* add to wait, with a timestamp */
                    assertz(fault->tstamp_tsc);
                    fault->tstamp_tsc = rdtsc();
                    list_add_tail(&my_hthr->fault_wait_q, &fault->link);
                    my_hthr->n_wait_q++;
                    log_debug("%s - added to wait", FSTR(fault));
                    break;
                case FAULT_READ_POSTED:
                    /* nothing to do here, we check for completions later*/
                    break;
            }
        }

eviction:
        /*  do eviction if needed */
        need_eviction = (nevicts_needed > 0);
        if (!need_eviction) {
            /* if eviction wasn't already signaled by the earlier fault, 
             * see if we need one in general (since this is the handler thread)*/
            pressure = atomic64_read(&memory_used);
            need_eviction = (pressure >= local_memory * eviction_threshold);
        }

        /* start eviction */
        if (need_eviction) {
            nevicts = 0;
            do {
                /* can use bigger batches in handler threads if idling */
                batch = evict_batch_size;
                if (nevicts_needed > 0) 
                    batch = EVICTION_MAX_BATCH_SIZE;
                nevicts += do_eviction(my_hthr->bkend_chan_id, &hthr_cbs, batch);
            } while(nevicts < nevicts_needed);
        }

        /* handle read/write completions from the backend */
        rmbackend->check_for_completions(my_hthr->bkend_chan_id, &hthr_cbs, 
            RMEM_MAX_COMP_PER_OP, NULL, NULL);

        /* check for remote memory dump */
        if (unlikely(dump_rmem_state_and_exit)) {
            dump_rmem_state();
            unreachable();
        }
    }

    /* destroy state */
    zero_page_free_thread();
    assert(list_empty(&my_hthr->fault_wait_q));
    return NULL;
}

/* create a new fault handler thread */
hthread_t* new_rmem_handler_thread(int pincore_id)
{
    int r;
    hthread_t* hthr = aligned_alloc(CACHE_LINE_SIZE, sizeof(hthread_t));
    assert(hthr);
    memset(hthr, 0, sizeof(hthread_t));

    /* create thread */
    hthr->stop = false;
    r = pthread_create(&hthr->thread, NULL, rmem_handler, (void*)hthr);
    if (r < 0) {
        log_err("pthread_create for rmem handler failed: %d", errno);
        return NULL;
    }

    /* pin thread */
    r = cpu_pin_thread(hthr->thread, pincore_id);
    assertz(r);

    return hthr;
}

/* stop and deallocate a fault handler thread */
int stop_rmem_handler_thread(hthread_t* hthr)
{
    /* signal and wait for thread to stop */
    assert(!hthr->stop);
    hthr->stop = true;
	pthread_join(hthr->thread, NULL);

    /* destroy per thread */
    rmem_common_destroy_thread();

    /* deallocate */
    free(hthr);
    return 0;
}

/* handler thread backend read/write completion ops for own cq */
struct bkend_completion_cbs hthr_cbs = {
    .read_completion = hthr_fault_read_done,
    .write_completion = owner_write_back_completed
};

/* handler thread backend read/write completion ops when stealing */
struct bkend_completion_cbs hthr_stealer_cbs = {
    .read_completion = hthr_fault_read_steal_done,
    .write_completion = stealer_write_back_completed
};