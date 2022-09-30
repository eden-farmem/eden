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
#include "rmem/config.h"
#include "rmem/eviction.h"
#include "rmem/fault.h"
#include "rmem/handler.h"
#include "rmem/pflags.h"
#include "rmem/region.h"
#include "rmem/uffd.h"

#include "runtime/rmem.h"
#include "../defs.h"

/* handler state */
__thread struct hthread *my_hthr = NULL;
__thread struct region_t *eviction_region_safe = NULL;
__thread uint64_t last_evict_try_count = 0;

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
            return NULL;
        }

        /* we have successfully read data into message */
        switch (message.event) {
            case UFFD_EVENT_PAGEFAULT:
                addr = message.arg.pagefault.address;
                flags = message.arg.pagefault.flags;
                log_debug("uffd pagefault event %d: addr=%llx, flags=0x%llx",
                    message.event, addr, flags);
                fault->page = addr & CHUNK_MASK;
                fault->is_write = !!(flags & UFFD_PAGEFAULT_FLAG_WRITE);
                fault->is_wrprotect = !!(flags & UFFD_PAGEFAULT_FLAG_WP);
                assert(!(fault->is_write && fault->is_wrprotect));
                fault->is_read = !(fault->is_write || fault->is_wrprotect);
                fault->from_kernel = true;
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
                /* we get here for evicted pages with REGISTER_MADVISE_NOTIF 
                 * otherwise call it a bug */
#ifdef REGISTER_MADVISE_NOTIF
                log_debug("process madvise at %p to %p, size=%llu",
                    (void *)message.arg.remove.start,
                    (void *)(message.arg.remove.end - 1),
                    message.arg.remove.end - message.arg.remove.start);
                addr = message.arg.remove.start & CHUNK_MASK;
                size = message.arg.remove.end - message.arg.remove.start;

                /* mark pages not present and adjust memory counters */
                mr = get_region_by_addr_safe(addr);
                r = clear_page_flags_range(mr, addr, size, PFLAG_PRESENT);
                pressure = atomic_fetch_sub_explicit(
                    &memory_booked, r*PAGE_SIZE, memory_order_acquire);
                pressure = atomic_fetch_sub_explicit(
                    &memory_used, r*PAGE_SIZE, memory_order_acquire);
                log_debug("Freed %d page(s), pressure=%lld", r, 
                    pressure - r*PAGE_SIZE);
                put_mr(mr);
                RSTAT(UFFD_NOTIF)++;
                return NULL;
#else
                log_err("REMOVE event not expected for no REGISTER_MADVISE_NOTIF");
                BUG();
#endif
            case UFFD_EVENT_UNMAP:
                /* we get here (presumably) for unintercepted munmap */
                log_debug("process madvise/munmap at %p to %p, size=%llu",
                    (void *)message.arg.remove.start,
                    (void *)(message.arg.remove.end - 1),
                    message.arg.remove.end - message.arg.remove.start);
                addr = message.arg.remove.start & CHUNK_MASK;
                size = message.arg.remove.end - message.arg.remove.start;

                /* deregister pages (we will adjust memory after eviction) */
                mr = get_region_by_addr_safe(addr);
                clear_page_flags_range(mr, addr, size, PFLAG_PRESENT);
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

static void* rmem_handler(void *arg) {
    pflags_t pflags, oldflags;
    struct region_t* mr;
    bool page_present, page_dirty, noaction, ongoing;
    bool need_eviction, no_wake, wrprotect;
    int ret, n_retries;
    unsigned long long pressure;
    fault_t* fault;
    
    assert(arg != NULL);        /* expecting a hthread_t */
    my_hthr = (hthread_t*) arg; /* save our hthread_t */

    /* init */
    fault_tcache_init_thread();
    zero_page_init_thread();
    dne_q_init_thread();

    /* do work */
    while(!my_hthr->stop) {
        need_eviction = false;

check_ready_q:
        /* check faults that are done */
        ret++;  /*TODO*/
        
check_uffd:
        /* check for uffd faults */
        fault = read_uffd_fault();
        if(!fault)
            goto eviction;
        /* accounting */
        if (fault->is_read)         RSTAT(FAULTS_R)++;
        if (fault->is_write)        RSTAT(FAULTS_W)++;
        if (fault->is_wrprotect)    RSTAT(FAULTS_WP)++;

        /* find region */
        mr = get_region_by_addr_safe(fault->page);
        /* we dont do region deletions yet so it must exist*/
        BUG_ON(!mr);
        assert(mr->addr);
        fault->region = mr;

        pflags = get_page_flags(mr, fault->page);
        page_present = !!(pflags & PFLAG_PRESENT);
        page_dirty = !!(pflags & PFLAG_DIRTY);
        noaction = fault->is_read && page_present;
        noaction = (fault->is_write || fault->is_wrprotect) && page_dirty;
        if (unlikely(noaction)) {
            // goto uffd queue (may need wake-up)
            // TODO re-cache it in DNE
        }
        else {
            oldflags = set_page_flags(mr, fault->page, PFLAG_WORK_ONGOING);
            ongoing = !!(oldflags & PFLAG_WORK_ONGOING);
            if (unlikely(ongoing)) {
                // someone else is working on it, add to waitq
                log_debug("%s - saw ongoing work, going to wait", FSTR(fault));
            }
            else {
                /* we need to handle it */
                log_debug("%s - no ongoing work, start handling", FSTR(fault));

                /* set do-not-evict */
                oldflags = set_page_flags(mr, fault->page, PFLAG_NOEVICT);
                pflags = oldflags | PFLAG_NOEVICT;

                /* add to the local DNE queue if I'm the first to set NOEVICT */
                /* TODO: How useful is this? */
                if (!(oldflags & PFLAG_NOEVICT))
                    dne_on_new_fault(mr, fault->page, (pflags & PFLAG_NOEVICT));

                /* we can handle write-protect right away */
                page_present = !!(pflags & PFLAG_PRESENT);
                if (page_present && fault->is_wrprotect) {
                    n_retries = 0;
                    no_wake = fault->from_kernel ? false : true;
                    ret = uffd_wp_remove(userfault_fd, fault->page, CHUNK_SIZE, 
                        no_wake, false, &n_retries);
                    /* TODO: we may want to handle (ret == EAGAIN) later */
                    BUG_ON(ret != 0);
                    RSTAT(FAULTS_DONE)++;

                    /* free fault */
                    fault_free(fault);
                    fault = NULL;
                    put_mr(mr);
                    log_debug("%s - removed write protection", FSTR(fault));
                    goto eviction;
                }
                else {
                    /* upgrade to write fault */
                    fault_upgrade_to_write(fault);
                    RSTAT(WP_UPGRADES)++;
                }

                /* book some memory first */
                pressure = atomic_fetch_add(&memory_booked, PAGE_SIZE);
                need_eviction = (pressure + PAGE_SIZE > local_memory);

#ifndef WP_ON_READ
                /* no WP on READ means every fault is a write fault */
                if (fault->is_read)
                    fault_upgrade_to_write(fault);
#endif

                /* first time adding page, use zero page */
                if (!(pflags & PFLAG_REGISTERED)) {
                     log_debug("%s - serving zero page", FSTR(fault));
                    
                    /* first time should naturally be a write */
                    fault_upgrade_to_write(fault);

                    /* copy zero page. TODO; Use UFFD_ZERO instead? */
                    n_retries = 0;
                    wrprotect = !fault->is_write;
                    no_wake = !fault->from_kernel;
                    ret = uffd_copy(userfault_fd, fault->page, (unsigned long) 
                        zero_page, CHUNK_SIZE, wrprotect, no_wake, true, &n_retries);
                    RSTAT(UFFD_COPY_RETRIES) += n_retries;
                    BUG_ON(ret != 0);

                    /* TODO: clear fault in progress */
                    /* TODO: release waiting faults */
                    RSTAT(FAULTS_ZP)++;
                    RSTAT(FAULTS_DONE)++;
                    
                    /* free fault */
                    fault_free(fault);
                    fault = NULL;
                    put_mr(mr);
                    log_debug("%s - added zero page", FSTR(fault));
                    goto eviction;
                }

                /* send off page read */
                /* NOTE: kona also makes an attempt to read from rdma write_q
                 * to preempt eviction but I won't handle that here */
                // ret = rmbackend->post_read_async(fault); /* TODO */
                assertz(ret);
            }
        }

eviction:
        /* if memory is not enough/past pressure, try eviction */
        if (!need_eviction) {
            /* if eviction wasn't already signaled by the earlier fault, 
             * see if we need one in general (since this is the handler thread) */
            pressure = atomic_load(&memory_used);
            need_eviction = (pressure > local_memory * eviction_threshold);
            if (!need_eviction)
                goto check_responses;
        }
        
        /* find a region to do eviction. Rotate regions every once in a while */
        if (eviction_region_safe == NULL)
            eviction_region_safe = get_next_evictable_region();
        else if (RSTAT(EVICT_RETRIES) > last_evict_try_count + EVICTION_REGION_SWITCH_THR) {
            put_mr(eviction_region_safe);
            /* NOTE: we're gonna hold this safe reference until we switch again 
             * which may be too long in some cases. Not gonna handle now! */
            eviction_region_safe = get_next_evictable_region();
            last_evict_try_count = RSTAT(EVICT_RETRIES);
        }
        
        /* start eviction. Can use bigger batches in handler threads */
        do_eviction(eviction_region_safe, EVICTION_MAX_BATCH_SIZE);

check_responses:
        /* handle read/write completions from the backend */
        ret++;  /*TODO*/
        // rmbackend->poll_completions(hook);
    }

    /* destroy state */
    zero_page_free_thread();
    dne_q_free_thread();
    return NULL;
}

/* create a new fault handler thread */
hthread_t* new_rmem_handler_thread(int pincore_id) {
    int r;
    hthread_t* hthr = malloc(sizeof(hthread_t));
    assert(hthr);
    memset(hthr, 0, sizeof(hthread_t));

    /* create thread */
    hthr->stop = false;
    r = pthread_create(&hthr->thread, NULL, rmem_handler, (void*)hthr);
    if (r < 0) {
        log_err("pthread_create for rmem handler failed: %d", errno);
        return NULL;
    }
    pthread_setname_np(hthr->thread, "rmem_handler");

    /* pin thread */
    r = cores_pin_thread(hthr->thread, pincore_id);
    assertz(r);

    return hthr;
}

/* stop and deallocate a fault handler thread */
int stop_rmem_handler_thread(hthread_t* hthr) {
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