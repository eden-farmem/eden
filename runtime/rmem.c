/*
 * rmem.c - remote memory init
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>

#include <rmem/backend.h>
#include <rmem/config.h>
#include <rmem/region.h>
#include <rmem/uffd.h>
#include "defs.h"

/* externed global settings */
bool rmem_enabled = true;    /*TODO: set me to false by default*/
rmem_backend_t rmbackend_type = RMEM_BACKEND_DEFAULT; /* TODO: add to cfg */
double eviction_threshold = EVICTION_THRESHOLD;
double eviction_done_threshold = EVICTION_DONE_THRESHOLD;
int eviction_batch_size = EVICTION_BATCH_SIZE;  /* TODO: assert < 8 * sz(ull)*/
uint64_t local_memory = LOCAL_MEMORY_SIZE;

/* global state for remote memory */
struct rmem_backend_ops* rmbackend = NULL;
int userfault_fd = -1;

/**
 * rmem_init - initializes remote memory
 */
int rmem_init()
{
    int ret;
    log_debug("rmem_init");

    /* init global data structures */
    spin_lock_init(&regions_lock);
    SLIST_INIT(&region_list);

    /* TODO:init all fault queues */
    /* TODO: init dne queue */
    /* TODO: init memory_pressure = ATOMIC_VAR_INIT(0); */
    /* TODO: init stats counters */

    /* init userfaultfd */
    userfault_fd = uffd_init();
    assert(userfault_fd >= 0);

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
    assert(ret);
    
    return 0;
}

/**
 * rmem_init_thread - initializes per-thread remote memory support
 */
int rmem_init_thread()
{
    struct kthread *k = myk();
    return rmbackend->perthread_init(k);
}

/**
 * rmem_init_late - remote memory post-init actions
 */
int rmem_init_late()
{
    return 0;
}

/**
 * rmem_destroy - remote memory clean-up
 * shenango doesn't destroy anything before shutting down so the control never 
 * gets here but we're still gonna implement cleanup in good faith!
 */
int rmem_destroy()
{
    /* ensure all regions freed */
    struct region_t *mr = NULL;
    SLIST_FOREACH(mr, &region_list, link)
        remove_memory_region(mr);
    assert(SLIST_EMPTY(&region_list));

    /* destroy backend */
    if (rmbackend != NULL) {
        rmbackend->destroy();
        rmbackend = NULL;
    }
    return 0;
}

