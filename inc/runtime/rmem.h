/*
 * rmem.h - remote memory definitions
 */

#ifndef __RMEM_H__
#define __RMEM_H__

#include "base/types.h"

/* global remote memory settings */
extern bool rmem_enabled;
extern uint64_t local_memory;
extern double eviction_threshold;
extern double eviction_done_threshold;
extern int eviction_batch_size;

#endif  // __RMEM_H__