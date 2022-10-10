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
#include "rmem/eviction.h"
#include "rmem/fault.h"
#include "rmem/handler.h"
#include "rmem/pflags.h"
#include "rmem/region.h"
#include "rmem/uffd.h"

#include "../defs.h"

/* handler state */
__thread struct hthread *my_hthr = NULL;

/* handler fault after fetched pages are ready */
int hthr_fault_read_done(fault_t* f)
{
    int r;
    r = fault_read_done(f);
    assertz(r);

    /* release fault */
    fault_done(f);
    return 0;
}

/* poll for faults/other notifications coming from UFFD */
static inline fault_t* read_uffd_fault() {
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
                fault->is_write = !!(flags & UFFD_PAGEFAULT_FLAG_WRITE);
                fault->is_wrprotect = !!(flags & UFFD_PAGEFAULT_FLAG_WP);
                assert(!(fault->is_write && fault->is_wrprotect));
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
    bool need_eviction;
    unsigned long long pressure;
    fault_t *fault, *next;
    int nevicts, nevicts_needed, batchsz, r;
    enum fault_status fstatus;
    struct region_t* mr;
    assert(arg != NULL);        /* expecting a hthread_t */
    my_hthr = (hthread_t*) arg; /* save our hthread_t */

    static struct bkend_completion_cbs hthr_cbs = {
        .read_completion = hthr_fault_read_done,
        .write_completion = write_back_completed
    };

    /* init */
    r = thread_init_perthread();    /* for tcache support */
	assertz(r);
    fault_tcache_init_thread();
    bkend_buf_tcache_init_thread();
    zero_page_init_thread();
    dne_q_init_thread();
    TAILQ_INIT(&my_hthr->fault_wait_q);
    my_hthr->n_wait_q = 0;

    /* do work */
    while(!my_hthr->stop) {
        need_eviction = false;
        nevicts = nevicts_needed = 0;

        /* pick faults from the backlog first */
        fault = TAILQ_FIRST(&my_hthr->fault_wait_q);
        while (fault != NULL) {
            next = TAILQ_NEXT(fault, link);
            fstatus = handle_page_fault(my_hthr->bkend_chan_id, fault, 
                &nevicts_needed, &hthr_cbs);
            switch (fstatus) {
                case FAULT_DONE:
                    log_debug("%s - done, released from wait", FSTR(fault));
                    TAILQ_REMOVE(&my_hthr->fault_wait_q, fault, link);
                    my_hthr->n_wait_q--;
                    assert(my_hthr->n_wait_q >= 0);
                    fault_done(fault);
                    break;
                case FAULT_READ_POSTED:
                    log_debug("%s - done, released from wait", FSTR(fault));
                    TAILQ_REMOVE(&my_hthr->fault_wait_q, fault, link);
                    my_hthr->n_wait_q--;
                    assert(my_hthr->n_wait_q >= 0);
                    if (nevicts_needed > 0)
                        goto eviction;
                    break;
                case FAULT_AGAIN:
                    log_debug("%s - not released from wait", FSTR(fault));
                    break;
            }
            fault = next;
        }

        /* check for uffd faults */
        fault = read_uffd_fault();
        if (fault) {
            /* accounting */
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
                case FAULT_AGAIN:
                    /* add to wait */
                    TAILQ_INSERT_TAIL(&my_hthr->fault_wait_q, fault, link);
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
            pressure = atomic_load(&memory_used);
            need_eviction = (pressure > local_memory * eviction_threshold);
        }

        /* start eviction */
        if (need_eviction) {
            nevicts = 0;
            do {
                /* can use bigger batches in handler threads if idling */
                batchsz = EVICTION_MAX_BATCH_SIZE;
                if (nevicts_needed > 0) 
                    batchsz = min(nevicts_needed, EVICTION_MAX_BATCH_SIZE);
                nevicts += do_eviction(my_hthr->bkend_chan_id, &hthr_cbs, batchsz);
            } while(nevicts < nevicts_needed);
        }

        /* handle read/write completions from the backend */
        rmbackend->check_for_completions(my_hthr->bkend_chan_id, &hthr_cbs, 
            RMEM_MAX_COMP_PER_OP, NULL, NULL);

#ifdef SECOND_CHANCE_EVICTION
        /* TODO: clear all hot bits once in a while */
#endif
    }

    /* destroy state */
    zero_page_free_thread();
    dne_q_free_thread();
    assert(TAILQ_EMPTY(&my_hthr->fault_wait_q));
    return NULL;
}

/* create a new fault handler thread */
hthread_t* new_rmem_handler_thread(int pincore_id)
{
    int r;
    hthread_t* hthr = malloc(sizeof(hthread_t));
    assert(hthr);
    memset(hthr, 0, sizeof(hthread_t));

    /* get a backend channel */
    hthr->bkend_chan_id = rmbackend->get_new_data_channel();
    assert(hthr->bkend_chan_id >= 0);

    /* create thread */
    hthr->stop = false;
    r = pthread_create(&hthr->thread, NULL, rmem_handler, (void*)hthr);
    if (r < 0) {
        log_err("pthread_create for rmem handler failed: %d", errno);
        return NULL;
    }
    pthread_setname_np(hthr->thread, "rmem_handler");

    /* pin thread */
    r = cpu_pin_thread(hthr->thread, pincore_id);
    assertz(r);

    return hthr;
}

/* stop and deallocate a fault handler thread */
int stop_rmem_handler_thread(hthread_t* hthr)
{
    int r;

    /* signal and wait for thread to stop */
    assert(!hthr->stop);
    hthr->stop = true;
	struct timespec wait = {.tv_nsec = 5E8 }; /* 1/2 second */
    r = pthread_timedjoin_np(hthr->thread, NULL, &wait);
    assertz(r);

    /* deallocate */
    free(hthr);
    return 0;
}