/*
 * rmem.c - remote memory init
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include "rmem/backend.h"
#include "rmem/config.h"
#include "rmem/fault.h"
#include "rmem/handler.h"
#include "rmem/page.h"
#include "rmem/region.h"
#include "rmem/uffd.h"
#include "runtime/pgfault.h"

#include "defs.h"

/* state */
bool rmem_hints_enabled = false;

/**
 * rmem_init - initializes remote memory
 */
int rmem_init()
{
    int r;
    unsigned long nslabs;

    if (!rmem_enabled) {
        log_info("rmem not enabled, skipping init");
        return 0;
    }

    /* remote memory does not support burstable or on-demand cores for now */
    if (guaranteedks != maxks || spinks != maxks){
        log_err("remote mem does not yet support burstable or on-demand cores");
        return 1;
    }

    /* init rmem */
    nslabs = (RDMA_SERVER_MEMORY_GB * 1073741824L / RMEM_SLAB_SIZE);
    r = rmem_common_init(nslabs, RMEM_HANDLER_CORE_LOW, 
            RMEM_HANDLER_CORE_HIGH, fsampler_samples_per_sec);
    if (r) return r;

#ifdef USE_VDSO_CHECKS
    /* init vdso objects */
    r = __vdso_init();
    if (r) return r;
#endif

    return 0;
}

/**
 * rmem_init_thread - initializes per-thread remote memory 
 * support shenango threads
 */
int rmem_init_thread()
{
    if (!rmem_enabled) {
        log_debug("rmem not enabled, skipping per-thread init");
        return 0;
    }
    
    /* limit on number of kthreads due to pgthread_t size */
    BUG_ON(my_kthr_id < 0);
    if ((my_kthr_id + 1) > PAGE_THREAD_MAX) {
        log_err("cannot support more than %llu kthreads", PAGE_THREAD_MAX);
        return 1;
    }

    struct kthread *k = myk();
    rmem_common_init_thread(&k->bkend_chan_id, k->rstats, my_kthr_id + 1);
    return 0;
}

/**
 * rmem_destroy_thread - destroy per-thread remote memory support
 * (shenango doesn't destroy anything before shutting down so the control never 
 * gets here but we're still gonna implement cleanup in good faith!)
 */
int rmem_destroy_thread()
{
    BUG_ON(!rmem_enabled);
    rmem_common_destroy_thread();
    assert(list_empty(&myk()->fault_wait_q));
    assert(list_empty(&myk()->fault_cq_steals_q));
    return 0;
}

/**
 * rmem_destroy - remote memory clean-up
 * (shenango doesn't destroy anything before shutting down so the control never 
 * gets here but we're still gonna implement cleanup in good faith!)
 */
int rmem_destroy()
{
    BUG_ON(!rmem_enabled);
    return rmem_common_destroy();
}