/*
 * rmem.h - remote memory definitions
 */

#ifndef __RMEM_H__
#define __RMEM_H__

#include <stdatomic.h>
#include "base/types.h"
#include <rmem/handler.h>

/* global remote memory settings */
extern bool rmem_enabled;
extern uint64_t local_memory;
extern double eviction_threshold;
extern double eviction_done_threshold;

/* global state */
extern atomic_ullong memory_booked;
extern atomic_ullong memory_used;

#endif  // __RMEM_H__