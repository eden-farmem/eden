/*
 * kfault.c - fault handling in shenango kthreads
 */

#include <sys/auxv.h>

#include "base/lock.h"
#include "base/log.h"
#include "base/time.h"
#include "base/vdso.h"
#include "rmem/eviction.h"
#include "rmem/fault.h"
#include "rmem/page.h"
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
    
    log_info("inited vdos page checks");
    return 0;
}

/**
 * Fault handling after read completions
 */

/* finish handling fault - the page is in the state required by the fault */
int kthr_fault_done(fault_t* f)
{
    /* release thread */
    assert(f->thread);
#ifdef BLOCKING_HINTS
    /* if we're blocking the core during the fault, we will be handling 
     * completions from the faulting thread, so just set it to ready but 
     * do not add it to the ready queue */
	assert(f->thread->state == THREAD_STATE_SLEEPING);
	f->thread->state = THREAD_STATE_RUNNABLE;
#else
    /* wake up thread and add it back to the ready queue */
    faulted_thread_ready_preempt_off(f->thread);
#endif

    /* release fault */
    fault_done(f);
    return 0;
}

/* called when the faults are being stolen after backend read completions */
int kthr_fault_read_steal_done(fault_t* f)
{
    struct kthread *stealer;

#ifdef BLOCKING_HINTS
    /* can't be here for blocking rmem */
    BUG();
#endif
    
    /* ensure everything in order */
    stealer = myk();
    assert(f);
    assert(stealer->bkend_chan_id != f->posted_chan_id);  /* assert steal */
    assert(f->bkend_buf);       /* expecting read buffer */
    f->stolen_from_cq = 1;      /* mark as stolen */
    RSTAT(READY_STEALS)++;

    /* add to stolen completions queue */
    list_add_tail(&stealer->fault_cq_steals_q, &f->link);
    stealer->n_cq_steals_q++;

    /* add to stealer pending */
    assert_spin_lock_held(&stealer->pf_lock);
    stealer->pf_pending++;
    return 0;
}

/* handle fault after the fetched pages are ready */
int kthr_fault_read_done(fault_t* f)
{
    int r;

    /* finish up page mapping */
    r = fault_read_done(f);
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
    int ndone, ntotal; 
    ntotal = rmbackend->check_for_completions(k->bkend_chan_id, 
        &kthr_owner_cbs, max_budget, &ndone, NULL);
    if (ntotal > 0)
        log_debug("handled %d completions on chan %d, faults done %d", 
            ntotal, k->bkend_chan_id, ndone);
    return ndone;
}

/* kthread steal completions. returns the number of stolen READ completions
 * that are now waiting in the cq_steals_q; write completions are handled 
 * synchronously as they require minimal work that doesn't require thread-local
 * state */
int kthr_steal_completions(struct kthread* owner, int max_budget)
{
    struct kthread* stealer;
    int nfaults_stolen, ntotal;

    /* check completions with stealer callbacks; stealer will have to be much 
     * faster as we hold the owner thread hostage so we use a much lighter 
     * callback that just adds completed faults to the queue rather than handle 
     * them inside it */
    stealer = myk();
    assert_spin_lock_held(&stealer->pf_lock);
    ntotal = rmbackend->check_for_completions(owner->bkend_chan_id, 
        &kthr_stealer_cbs, max_budget, &nfaults_stolen, NULL);

    /* remove them from owner kthead count, we will add to the stealer 
     * count in the callback */
    spin_lock(&owner->pf_lock);
    // assert(owner->pf_pending >= nfaults_stolen);
    owner->pf_pending -= nfaults_stolen;
    spin_unlock(&owner->pf_lock);

    if (ntotal > 0)
        log_debug("handled %d completions on chan %d, stolen %d reads", 
            ntotal, owner->bkend_chan_id, nfaults_stolen);
    return nfaults_stolen;
}

/* kthread run through stolen read completions and finish serving them */
int kthr_handle_stolen_completed_faults(struct kthread* k)
{
    struct fault *f;
    int ndone;
    
    /* no need to take the pf_lock as fault_cq_steals_q is never accessed by 
     * another kthread */
    ndone = k->n_cq_steals_q;
    f = list_pop(&k->fault_cq_steals_q, fault_t, link);
    while (f != NULL) {
        kthr_fault_read_done(f);
        assert(k->n_cq_steals_q > 0);
        k->n_cq_steals_q--;
        f = list_pop(&k->fault_cq_steals_q, fault_t, link);
    }

    assertz(k->n_cq_steals_q);  /* check we served everything */
    return ndone;
}

/**
 * Fault handling for waiting faults
 */

/* kthread steal waiting faults. returns the number of stolen READ completions
 * that are now waiting in the cq_steals_q; write completions are handled 
 * synchronously as they require minimal work that doesn't require thread-local
 * state */
int kthr_steal_waiting_faults(struct kthread* stealer, struct kthread* owner)
{
    int avail, nstolen = 0;
    struct fault *f;

    /* we take owner's pf_lock as necessary but stealer's pf_lock must be 
     * locked while stealing */
    assert_spin_lock_held(&stealer->pf_lock);

    /* steal upto half from the wait queue */
    spin_lock(&owner->pf_lock);
    avail = div_up(owner->n_wait_q, 2);
    if (avail > 0) {
        f = list_pop(&owner->fault_wait_q, fault_t, link);
        assert(f || !owner->n_wait_q);
        while (f != NULL) {
            /* remove from owner's queue */
            // assert(owner->pf_pending > 0);
            assert(owner->n_wait_q > 0);
            owner->pf_pending--;
            owner->n_wait_q--;

            /* add to stealer's queue */
            list_add_tail(&stealer->fault_wait_q, &f->link);
            stealer->pf_pending++;
            stealer->n_wait_q++;
            RSTAT(WAIT_STEALS)++;

            /* accounting */
            nstolen++;
            f = NULL;
            avail--;
            if (!avail)
                break;

            /* get next */
            f = list_pop(&owner->fault_wait_q, fault_t, link);
            assert(f || !owner->n_wait_q);
            assert(!avail || f);
        }

        /* ensure no leakage */
        assert(!f);
    }
    spin_unlock(&owner->pf_lock);
    return nstolen;
}

/* pop the next waiting fault from the wait queue  */
static inline struct fault* kthr_pop_next_waiting_fault(struct kthread* k)
{
    struct fault* f;
    spin_lock(&k->pf_lock);
    f = list_pop(&k->fault_wait_q, fault_t, link);
    assert(f || !k->n_wait_q);
    if (f != NULL) {
        assert(k->n_wait_q > 0);
        k->n_wait_q--;
    }
    spin_unlock(&k->pf_lock);
    return f;
}

/* kthread run through waiting faults to see if they are ready to go */
int kthr_handle_waiting_faults(struct kthread* k)
{
    struct fault *fault;
    int nevicts_needed, nevicts;
    int nwaiting, ndone = 0;
    enum fault_status fstatus;

    /* harmless without lock; doesn't have to be correct */
    nwaiting = k->n_wait_q; 

    /* get the first fault out */
    fault = kthr_pop_next_waiting_fault(k);

    while (fault != NULL) {
        /* try handling the fault */
        fstatus = handle_page_fault(k->bkend_chan_id, fault, &nevicts_needed, 
            &kthr_owner_cbs);
        switch (fstatus) {
            case FAULT_DONE:
                log_debug("%s - released from wait, done", FSTR(fault));
                kthr_fault_done(fault);
                ndone++;
                break;
            case FAULT_READ_POSTED:
                log_debug("%s - released from wait, posted read", FSTR(fault));
                if (nevicts_needed > 0) {
                    nevicts = 0;
                    while(nevicts < nevicts_needed)
                        nevicts += do_eviction(k->bkend_chan_id,
                            &kthr_owner_cbs, evict_batch_size);
                }
                break;
            case FAULT_IN_PROGRESS:
                /* fault not ready to handle, add it back to tail */
                log_debug("%s - not released from wait", FSTR(fault));
                spin_lock(&k->pf_lock);
                list_add_tail(&k->fault_wait_q, &fault->link);
                k->n_wait_q++;
                RSTAT(WAIT_RETRIES)++;
                spin_unlock(&k->pf_lock);
                break;
        }

        nwaiting--;
        if (nwaiting == 0)
            break;

        /* get next fault */
        fault = kthr_pop_next_waiting_fault(k);
    }

    return ndone;
}

/* kthread backend read/write completion ops for owner thread */
struct bkend_completion_cbs kthr_owner_cbs = {
    .read_completion = kthr_fault_read_done,
    .write_completion = owner_write_back_completed
};

/* kthread backend read/write completion ops for stealer thread */
struct bkend_completion_cbs kthr_stealer_cbs = {
    .read_completion = kthr_fault_read_steal_done,
    .write_completion = stealer_write_back_completed
};