/*
 * page.h - remote memory page metadata and page nodes
 */

#ifndef __RMEM_PAGE_H__
#define __RMEM_PAGE_H__

#include <stdatomic.h>
#include "base/list.h"
#include "base/tcache.h"
#include "rmem/eviction.h"
#include "rmem/region.h"

/**
 * Page flags - definition and helpers
 */

enum {
    PSHIFT_REGISTERED = 0,
    PSHIFT_PRESENT,
    PSHIFT_DIRTY,
    PSHIFT_WORK_ONGOING,
    PSHIFT_EVICT_ONGOING,
    PSHIFT_HOT_MARKER,
    PSHIFT_HOT_MARKER2,
    PAGE_FLAGS_NUM
};
BUILD_ASSERT(sizeof(pflags_t) * 8 >= PAGE_FLAGS_NUM);

#define PFLAG_REGISTERED    (1u << PSHIFT_REGISTERED)
#define PFLAG_PRESENT       (1u << PSHIFT_PRESENT)
#define PFLAG_DIRTY         (1u << PSHIFT_DIRTY)
#define PFLAG_WORK_ONGOING  (1u << PSHIFT_WORK_ONGOING)
#define PFLAG_EVICT_ONGOING (1u << PSHIFT_EVICT_ONGOING)
#define PFLAG_HOT_MARKER    (1u << PSHIFT_HOT_MARKER)
#define PFLAG_HOT_MARKER2   (1u << PSHIFT_HOT_MARKER2)
#define PAGE_FLAGS_MASK     ((1u << PAGE_FLAGS_NUM) - 1)

static inline atomic_pflags_t *page_ptr(struct region_t *mr, unsigned long addr)
{
    int offset = ((addr - mr->addr) >> CHUNK_SHIFT);
    return &mr->page_flags[offset];
}

static inline pflags_t get_page_flags(struct region_t *mr, unsigned long addr)
{
    atomic_pflags_t *ptr = page_ptr(mr, addr);
    return (*ptr) & PAGE_FLAGS_MASK;
}

/* sets flags on a page and returns new flags (and oldflags in ptr) */
static inline pflags_t set_page_flags(struct region_t *mr, unsigned long addr, 
    pflags_t flags, pflags_t* oldflags_out)
{
    pflags_t oldflags, new_flags;
    atomic_pflags_t *ptr;
    assert((flags & ~PAGE_FLAGS_MASK) == 0);  /* only page flags */

    ptr = page_ptr(mr, addr);
    oldflags = atomic_fetch_or(ptr, flags);
    oldflags = oldflags & PAGE_FLAGS_MASK;
    if (oldflags_out)
        *oldflags_out = oldflags;
    new_flags = oldflags | flags;
    return new_flags;
}

/* clears flags on a page and returns new flags (and oldflags in ptr) */
static inline pflags_t clear_page_flags(struct region_t *mr, unsigned long addr, 
    pflags_t flags, pflags_t* oldflags_out)
{
    pflags_t oldflags, new_flags;
    atomic_pflags_t *ptr;
    assert((flags & ~PAGE_FLAGS_MASK) == 0);  /* only page flags */
    
    ptr = page_ptr(mr, addr);
    oldflags = atomic_fetch_and(ptr, ~flags);
    oldflags = oldflags & PAGE_FLAGS_MASK;
    if (oldflags_out)
        *oldflags_out = oldflags;
    new_flags = oldflags & (~flags);
    return new_flags;
}

static inline int set_page_flags_range(struct region_t *mr, unsigned long addr,
    size_t size, pflags_t flags)
{
    unsigned long offset;
    pflags_t oldflags;
    int chunks = 0;

    for (offset = 0; offset < size; offset += CHUNK_SIZE) {
        set_page_flags(mr, addr + offset, flags, &oldflags);
        if (!(oldflags & flags)) {
            log_debug("[%s] page flags set (clear earlier) for page: %lx", 
                __func__, addr + offset);
            chunks++;
        }
    }
    /* return number of pages were actually set */
    return chunks;
}

static inline int clear_page_flags_range(struct region_t *mr, 
    unsigned long addr, size_t size, pflags_t flags)
{
    unsigned long offset;
    int chunks = 0;
    pflags_t oldflags;

    for (offset = 0; offset < size; offset += CHUNK_SIZE) {
        clear_page_flags(mr, addr + offset, flags, &oldflags);
        if (!!(oldflags & flags)) {
            log_debug("[%s] page flags cleared (set earlier) for page: %lx", 
                __func__, addr + offset);
            chunks++;
        }
    }
    /* return number of pages that were actually reset */
    return chunks;
}

/**
 * Page node index in metadata - definition and helpers
 */
#define PAGE_INDEX_SHIFT    (PAGE_FLAGS_NUM)
#define PAGE_INDEX_LEN      (sizeof(pflags_t) * 8 - PAGE_INDEX_SHIFT)
#define PAGE_INDEX_MASK     (((1ULL << PAGE_INDEX_LEN) - 1) << PAGE_INDEX_SHIFT)
BUILD_ASSERT(PAGE_INDEX_MASK > 0);

/* get the page structure index from provided page flags */
static inline pflags_t get_page_index_from_flags(pflags_t flags)
{
    assert(!!(flags & PFLAG_WORK_ONGOING)); /*require a page lock to read index*/
    return (flags & PAGE_INDEX_MASK) >> PAGE_INDEX_SHIFT;
}

/* get the page structure index from page metadata */
static inline pflags_t get_page_index_atomic(struct region_t *mr,
    unsigned long addr)
{
    atomic_pflags_t *ptr;
    ptr = page_ptr(mr, addr);
    return get_page_index_from_flags(atomic_load(ptr));
}

/* saves the provided page structure index in page flags and returns old idx */
static inline pflags_t set_page_index_atomic(struct region_t *mr,
    unsigned long addr, pflags_t index)
{
    pflags_t flags, new_flags;
    atomic_pflags_t *ptr;
    bool swapped;
    assert((index & ~((1 << PAGE_INDEX_LEN) - 1)) == 0); /* check index fits */

    /* compare-and-swap to not affect other flags */
    ptr = page_ptr(mr, addr);
    do {
        flags = atomic_load(ptr);
        assert(!!(flags & PFLAG_WORK_ONGOING)); /* require a page lock to set */
        new_flags = (flags & ~PAGE_INDEX_MASK); /* keep non-index bits */
        new_flags |= (index << PAGE_INDEX_SHIFT);
        swapped = atomic_compare_exchange_weak(ptr, &flags, new_flags);
    } while(!swapped);

    /* old index */
    return (flags & PAGE_INDEX_MASK) >> PAGE_INDEX_SHIFT;
}

/**
 * Page node support (for locally present pages)
 * These nodes are juggled around LRU lists until the pages get kicked out to 
 * remote memory, after which they are reused for other pages
 */
struct rmpage_node {
    struct region_t *mr;
    unsigned long addr;
    struct list_node link;
    struct page_list* listhead;
};
typedef struct rmpage_node rmpage_node_t;

/* Page node pool (tcache) support */
DECLARE_PERTHREAD(struct tcache_perthread, rmpage_node_pt);
extern rmpage_node_t* rmpage_nodes;
extern size_t rmpage_node_count;

int rmpage_node_tcache_init(void);
void rmpage_node_tcache_init_thread(void);
bool rmpage_is_node_valid(rmpage_node_t* pgnode);

/* rmpage_node_alloc - allocates a page node from pool */
static inline rmpage_node_t* rmpage_node_alloc(void)
{
    rmpage_node_t* pgnode;
    pgnode = (rmpage_node_t*) tcache_alloc(&perthread_get(rmpage_node_pt));
    if (unlikely(!pgnode)) {
        log_err("out of page nodes!");
        BUG();
    }
    memset(pgnode, 0, sizeof(rmpage_node_t));
    return pgnode;
}

/* rmpage_node_free - frees a page node */
static inline void rmpage_node_free(rmpage_node_t* node)
{
    assert(rmpage_is_node_valid(node));
    tcache_free(&perthread_get(rmpage_node_pt), node);
}

/* rmpage_get_node_id - gets a shortened index to a page node that can be saved 
 * in page metadata and used to retrieve the node later */
static inline pflags_t rmpage_get_node_id(rmpage_node_t* node)
{
    assert(rmpage_is_node_valid(node));
    return (pflags_t)(node - rmpage_nodes);
}

static inline rmpage_node_t* rmpage_get_node_by_id(pflags_t id)
{
    assert(id >= 0 && id < rmpage_node_count);
    return &rmpage_nodes[id];
}


#endif    // __RMEM_PAGE_H_