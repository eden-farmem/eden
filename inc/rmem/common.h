/*
 * common.h - remote memory common for 
 * shenango and handler threads
 */

#ifndef __RMEM_COMMON_H__
#define __RMEM_COMMON_H__

#include <stddef.h>
#include "base/types.h"
#include "rmem/handler.h"

/* global remote memory settings */
extern bool rmem_enabled;
extern rmem_backend_t rmbackend_type;
extern uint64_t local_memory;
extern double eviction_threshold;
extern int evict_batch_size;
extern int evict_ngens;

/* global state */
extern int nhandlers;
extern hthread_t** handlers;
extern atomic64_t memory_used;

/* thread-local */
extern __thread pgthread_t current_kthread_id;

/* init & destroy */
int rmem_common_init(void);
int rmem_common_init_thread(int* new_chan_id, uint64_t* stats_ptr, 
    pgthread_t kthr_id);
int rmem_common_destroy_thread(void);
int rmem_common_destroy(void);

#endif  // __RMEM_COMMON_H__