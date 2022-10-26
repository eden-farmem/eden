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
#include "rmem/region.h"
#include "rmem/uffd.h"
#include "runtime/pgfault.h"

#include "defs.h"

/**
 * rmem_init - initializes remote memory
 */
int rmem_init()
{
    int r;

    /* remote memory does not support burstable or on-demand cores for now */
    if (guaranteedks != maxks || spinks != maxks){
        log_err("remote mem does not yet support burstable or on-demand cores");
        return 1;
    }

    /* init rmem */
    r = rmem_common_init();
    if (r)
        return r;

#ifdef USE_VDSO_CHECKS
    /* init vdso objects */
    __vdso_init();
#endif

    return 0;
}

/**
 * rmem_init_thread - initializes per-thread remote memory 
 * support shenango threads
 */
int rmem_init_thread()
{
    struct kthread *k = myk();
    rmem_common_init_thread(&k->bkend_chan_id, k->rstats);
    return 0;
}

/**
 * rmem_init_late - remote memory post-init actions
 */
int rmem_init_late()
{
    return 0;
}

/**
 * rmem_destroy_thread - destroy per-thread remote memory support
 * (shenango doesn't destroy anything before shutting down so the control never 
 * gets here but we're still gonna implement cleanup in good faith!)
 */
int rmem_destroy_thread()
{
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
    return rmem_common_destroy();
}