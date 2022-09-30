/*
 * eviction.h - eviction helpers
 */

#ifndef __EVICTION_H__
#define __EVICTION_H__

void do_eviction(struct region_t* mr, int max_batch_size);

#endif  // __EVICTION_H__