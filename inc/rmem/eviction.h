/*
 * eviction.h - eviction helpers
 */

#ifndef __EVICTION_H__
#define __EVICTION_H__

#include "rmem/backend.h"
#include "rmem/region.h"

int write_back_completed(struct region_t* mr, unsigned long addr, size_t size);
int do_eviction(int chan_id, struct bkend_completion_cbs* cbs, int max_batch_size);

#endif  // __EVICTION_H__