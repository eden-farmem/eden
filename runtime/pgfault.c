/*
 * pgfault.c - support for userspace page faults
 */

#include <sys/auxv.h>

#include "base/lock.h"
#include "base/log.h"
#include "base/time.h"
#include "base/vdso.h"
#include "rmem/eviction.h"
#include "rmem/fault.h"
#include "rmem/pflags.h"
#include "rmem/region.h"
#include "runtime/thread.h"
#include "runtime/pgfault.h"
#include "runtime/sync.h"

#include "defs.h"

/* state */
__thread struct region_t* __cached_mr = NULL;

/* objects for vdso-based page checks */
const char *version = "LINUX_2.6";
const char *name_mapped = "__vdso_is_page_mapped";
const char *name_wp = "__vdso_is_page_mapped_and_wrprotected";
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
    return 0;
}

/* finish handling fault - the page is in the state required by the fault */
int kthr_fault_done(fault_t* f)
{
    /* release thread */
    assert(f->thread);
    thread_ready(f->thread);

    /* release fault */
    fault_done(f);
    return 0;
}

/* handler fault after fetched pages are ready */
int kthr_fault_read_done(fault_t* f, unsigned long buf_addr, size_t size)
{
    int r;
    struct kthread *k;
    
    /* we expect the lock to be taken before calling completions */
    k = myk();
    assert_spin_lock_held(&k->pf_lock);
    if (k->bkend_chan_id != f->posted_chan_id)
        RSTAT(TOTAL_STEALS)++;

    /* finish up page mapping */
    r = fault_read_done(f, buf_addr, size);
    assertz(r);

    /* release thread & fault */
    r = kthr_fault_done(f);
    assertz(r);

    return 0;
}

/* kthread check for completions. returns the number of completions 
 * that serviced faults (at this point, threads associated with those 
 * faults will have been added to the ready queue */
int kthr_check_for_completions(struct kthread* k, int max_budget)
{
    int nfaults_done, ntotal; 
    ntotal = rmbackend->check_for_completions(k->bkend_chan_id, &kthr_cbs, 
        max_budget, &nfaults_done, NULL);
    assert(k->pf_pending >= nfaults_done);
    k->pf_pending -= nfaults_done;
    log_debug("handled %d completions on chan %d", ntotal, k->bkend_chan_id);
    return nfaults_done;
}

/* kthread run through waiting faults to see if they are ready to go */
int kthr_handle_waiting_faults(struct kthread* k)
{
    struct fault *fault, *next;
    int nevicts_needed, nevicts = 0, faults_done = 0;  
    enum fault_status fstatus;
    fault = TAILQ_FIRST(&k->fault_wait_q);
    while (fault != NULL) {
        next = TAILQ_NEXT(fault, link);
        fstatus = handle_page_fault(k->bkend_chan_id, fault, &nevicts_needed, 
            &kthr_cbs);
        switch (fstatus) {
            case FAULT_DONE:
                log_debug("%s - done, released from wait", FSTR(fault));
                TAILQ_REMOVE(&k->fault_wait_q, fault, link);
                kthr_fault_done(fault);
                k->pf_pending--;
                assert(k->n_wait_q > 0);
                k->n_wait_q--;
                faults_done++;
                break;
            case FAULT_READ_POSTED:
                log_debug("%s - done, released from wait", FSTR(fault));
                TAILQ_REMOVE(&k->fault_wait_q, fault, link);
                assert(k->n_wait_q > 0);
                k->n_wait_q--;
                if (nevicts_needed > 0) {
                    nevicts = 0;
                    while(nevicts < nevicts_needed)
                        nevicts += do_eviction(k->bkend_chan_id, &kthr_cbs, 
                            min(nevicts_needed, EVICTION_MAX_BATCH_SIZE));
                    /* TODO: shall we break after one eviction or continue? */
                }
                break;
            case FAULT_AGAIN:
                log_debug("%s - not released from wait", FSTR(fault));
                break;
        }
        fault = next;
    }
    return faults_done;
}

/**
 * Handle the fault in Shenango
 */
void kthr_send_fault_to_scheduler(void* address, bool write, int rdahead)
{
#ifndef REMOTE_MEMORY
    log_err("remote memory not defined");
    BUG();
#endif
    struct fault* fault;
    unsigned long page;
    struct kthread *k;
    struct region_t* mr;
    int nevicts_needed = 0, nevicts = 0;
    enum fault_status fstatus;

    /* disable preempt and get fault lock. If we're spending too much time 
     * getting this lock, we may have to do more fine-grained locking */
    k = getk();
    spin_lock(&k->pf_lock);

    /* alloc fault object */
    page = ((unsigned long) address) & ~CHUNK_MASK;
    fault = fault_alloc();
    if (unlikely(!fault)) {
        log_debug("couldn't get a fault object");
        BUG();
    }
    memset(fault, 0, sizeof(fault_t));
    fault->page = page;
    fault->is_read = !write;
    fault->is_write = write;
    fault->from_kernel = false;
    fault->rdahead_max = rdahead;
    fault->rdahead = 0;
    fault->thread = thread_self();
    log_debug("fault posted at %lx write %d", page, write);

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
    fstatus = handle_page_fault(k->bkend_chan_id, fault, &nevicts_needed, &kthr_cbs);
    switch (fstatus) {
        case FAULT_DONE:
            fault_done(fault);
            spin_unlock(&k->pf_lock);
            putk();
            return;
        case FAULT_AGAIN:
            /* add to wait and yield to run another thread */
            TAILQ_INSERT_TAIL(&k->fault_wait_q, fault, link);
            k->n_wait_q++;
            log_debug("%s - added to wait", FSTR(fault));
            goto yield_thread_and_wait;
            break;
        case FAULT_READ_POSTED:
            /* nothing to do here, we check for completions later*/
            if (nevicts_needed)
                goto eviction;
            goto yield_thread_and_wait;
            break;
    }

eviction:
    /* start eviction; evict only as much as necessary on shenango cores */
    while(nevicts < nevicts_needed)
        nevicts += do_eviction(k->bkend_chan_id, &kthr_cbs, 
            min(nevicts_needed - nevicts, EVICTION_MAX_BATCH_SIZE));

yield_thread_and_wait:
    k->pf_pending++;
    thread_park_and_unlock_np(&k->pf_lock); /* yield */

    /* fault serviced if we get here */
    assert(fault->thread == thread_self());
    assert(!__is_fault_pending(address, write));
}

/* kthread backend read/write completion ops */
struct completion_cbs kthr_cbs = {
    .read_completion = kthr_fault_read_done,
    .write_completion = write_back_completed
};