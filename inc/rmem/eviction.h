/*
 * eviction.h - eviction helpers
 */

#ifndef __EVICTION_H__
#define __EVICTION_H__

#include "rmem/backend.h"
#include "rmem/region.h"

/**
 * Eviction main
 */
int do_eviction(int chan_id, struct bkend_completion_cbs* cbs, int max_batch_size);
int owner_write_back_completed(struct region_t* mr, unsigned long addr, size_t size);
int stealer_write_back_completed(struct region_t* mr, unsigned long addr, size_t size);

/**
 * Page LRU lists support
 */

struct page_list {
    struct list_head pages;
    size_t npages;
    spinlock_t lock;
};
extern struct page_list evict_gens[EVICTION_MAX_GENS];
extern int nr_evict_gens;
extern int evict_gen_mask;
extern int evict_gen_now;
extern unsigned long evict_epoch_now;

int eviction_init(void);
int eviction_init_thread(void);

#endif  // __EVICTION_H__