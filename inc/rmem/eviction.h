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
int write_back_completed(struct region_t* mr, unsigned long addr, size_t size);
int do_eviction(int chan_id, struct bkend_completion_cbs* cbs, int max_batch_size);

/**
 * Page LRU lists support
 */

#define HOT_LRU_PERCENT     20
#define WARM_LRU_PERCENT    40

struct page_list {
    struct list_head pages;
    size_t npages;
    size_t max_pages;
    spinlock_t lock;
};
typedef struct page_list page_list_t;
extern page_list_t hot_pages;
extern page_list_t warm_pages;
extern page_list_t cold_pages;

void lru_lists_init(void);

#endif  // __EVICTION_H__