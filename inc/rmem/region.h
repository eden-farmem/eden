/*
 * region.h - Remote memory region management helpers
 */

#ifndef __REGION_H__
#define __REGION_H__

#include <infiniband/verbs.h>   /* TODO: get rid of this dependency */
#include <sys/queue.h>
#include <stdatomic.h>

#include "base/lock.h"
#include "rmem/config.h"
#include "rmem/backend.h"

struct region_t {
    volatile size_t size;
    unsigned long addr;
    unsigned long remote_addr;
    atomic_ullong current_offset;

    atomic_char *page_flags;  /* TODO: may want to switch to regular char */
    atomic_int ref_cnt;

    /* TODO: move RDMA-specific data into separate rdma region */
    struct ibv_mr rdma_mr;
    struct server_conn_t *server;
    
    SLIST_ENTRY(region_t) link;
} __aligned(CACHE_LINE_SIZE);

/* region data */
SLIST_HEAD(region_listhead, region_t);
extern struct region_listhead region_list;
extern spinlock_t regions_lock;

/* functions */
int register_memory_region(struct region_t *mr, int writeable);
void remove_memory_region(struct region_t *mr);


/* memory region helpers */
static inline bool get_mr(struct region_t *mr) {
    int r = atomic_fetch_add_explicit(&mr->ref_cnt, 1, memory_order_acquire);
    BUG_ON(r < 0);
    return (r > 0);
}

static inline bool is_in_memory_region(struct region_t *mr, unsigned long addr) {
    return addr >= mr->addr && addr < mr->addr + mr->size;
}

static inline bool within_memory_region(void *ptr) {
    if (ptr == NULL || SLIST_EMPTY(&region_list))
        return false;

    struct region_t *mr = NULL;
    SLIST_FOREACH(mr, &region_list, link) {
        if (is_in_memory_region(mr, (unsigned long)ptr)) {
            return true;
        }
    }
    return false;
}

static inline struct region_t *get_available_mr(size_t size) {
    struct region_t *mr = NULL;
    SLIST_FOREACH(mr, &region_list, link) {
        size_t required_space = size;
        if (mr->current_offset + required_space <= mr->size) {
            log_debug("%s:found avilable mr:%p for size:%ld", __func__, mr, size);
            return mr;
        } else {
            log_debug("%s: mr:%p is out of memory. size:%ld, current offset:%lld",
                __func__, mr, mr->size, mr->current_offset);
        }
    }
    log_info("available mr does not have enough memory to serve, add new slab");
    return NULL;
}

static inline struct region_t *find_region_by_addr(unsigned long addr) {
    struct region_t *mr = NULL;
    SLIST_FOREACH(mr, &region_list, link) {
        if (is_in_memory_region(mr, addr)) {
            /* ideally we should get_mr() here to deal with region deletions */
            return mr;
        }
    }
    return NULL;
}

static inline void put_mr_references(struct region_t *mr, int n) {
    log_debug("decreasing ref_cnt for mr %p", mr);
    int r = atomic_fetch_sub_explicit(&mr->ref_cnt, n, memory_order_consume);
    if (r > 1) return;
    assert(r == 1);
    remove_memory_region(mr);
}

static inline void put_mr(struct region_t *mr) {
    assert(mr);
    if (mr != NULL) put_mr_references(mr, 1);
}

static inline int close_remove_memory_region(struct region_t *reg) {
    log_debug("close remove memory region");
    if (!reg) {
        BUG();
        return -1;
    }
    put_mr_references(reg, 1);
    return 0;
}

#endif    // __REGION_H__