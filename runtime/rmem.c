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

/* externed global settings */
bool rmem_enabled = true;    /*TODO: set me to false by default*/
rmem_backend_t rmbackend_type = RMEM_BACKEND_DEFAULT; /* TODO: add to cfg */
double eviction_threshold = EVICTION_THRESHOLD;
double eviction_done_threshold = EVICTION_DONE_THRESHOLD;
uint64_t local_memory = LOCAL_MEMORY_SIZE;

/* global state for remote memory */
struct rmem_backend_ops* rmbackend = NULL;
int userfault_fd = -1;
hthread_t** handlers = NULL;
int nhandlers = 0;
atomic_ullong memory_booked;
atomic_ullong memory_used;

/**
 * rmem_init - initializes remote memory
 */
int rmem_init()
{
    int ret;
    log_debug("rmem_init with %.2lf GB local memory", 
        local_memory * 1.0 / (1 << 30));

    /* remote memory does not support burstable or on-demand cores for now */
    if (guaranteedks != maxks || spinks != maxks){
        log_err("remote mem does not yet support burstable or on-demand cores");
        return 1;
    }

    /* init global data structures */
    CIRCLEQ_INIT(&region_list);
    memory_booked = ATOMIC_VAR_INIT(0);
    memory_used = ATOMIC_VAR_INIT(0);
    /* TODO:init all fault queues */
    /* TODO: init dne queue */

    /* init userfaultfd */
    userfault_fd = uffd_init();
    assert(userfault_fd >= 0);

    /* initialize backend buf pool (used by backend) */
    ret = bkend_buf_tcache_init();
    assertz(ret);

    /* initialize backend */
    switch(rmbackend_type) {
        case RMEM_BACKEND_LOCAL:
            rmbackend = &local_backend_ops;
            break;
        case RMEM_BACKEND_RDMA:
            rmbackend = &rdma_backend_ops;
            break;
        default:
            BUG();  /* unhandled backend */
    }
    ret = rmbackend->init();
    assertz(ret);

    /* add some memory to start with */
    ret = rmbackend->add_memory(NULL, RDMA_SERVER_NSLABS);
    assert(ret > 0);

    /* assign tcaches for faults */
    ret = fault_tcache_init();
    assertz(ret);

    /* kick off rmem handlers 
     * (currently just one but we can add more) */
    nhandlers = 4;
    handlers = malloc(nhandlers*sizeof(hthread_t*));
    handlers[0] = new_rmem_handler_thread(PIN_RMEM_HANDLER_CORE);
    /* note that these extra cores are not excluded from shenango core list */
    handlers[1] = new_rmem_handler_thread(PIN_RMEM_HANDLER_CORE-1);
    handlers[2] = new_rmem_handler_thread(PIN_RMEM_HANDLER_CORE-2);
    handlers[3] = new_rmem_handler_thread(PIN_RMEM_HANDLER_CORE-3);


#ifdef USE_VDSO_CHECKS
    /* init vdso objects */
    __vdso_init();
#endif

    return 0;
}

/**
 * rmem_init_thread - initializes per-thread remote memory support (only for
 * shenango threads, not rmem handlers)
 */
int rmem_init_thread()
{
    struct kthread *k = myk();

    /* init per-thread data */
    fault_tcache_init_thread();
    bkend_buf_tcache_init_thread();
    zero_page_init_thread();
    dne_q_init_thread();

    /* get dedicated backend channel */
    k->bkend_chan_id = rmbackend->get_new_data_channel();
    assert(k->bkend_chan_id >= 0);
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
    zero_page_free_thread();
    dne_q_free_thread();
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
    int i, ret;

    /* stop and destroy handlers */
    for (i = 0; i < nhandlers; i++) {
        ret = stop_rmem_handler_thread(handlers[i]);
        assertz(ret);
    }
    free(handlers);

    /* TODO: anyway to destroy fault tcache? */

    /* ensure all regions freed */
    struct region_t *mr = NULL;
    CIRCLEQ_FOREACH(mr, &region_list, link)   
        remove_memory_region(mr);
    assert(CIRCLEQ_EMPTY(&region_list));

    /* destroy backend */
    if (rmbackend != NULL) {
        rmbackend->destroy();
        rmbackend = NULL;
    }
    return 0;
}