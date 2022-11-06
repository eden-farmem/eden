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
BUILD_ASSERT(sizeof(pgflags_t) * 8 >= PAGE_FLAGS_NUM);

#define PFLAG_REGISTERED    (1u << PSHIFT_REGISTERED)
#define PFLAG_PRESENT       (1u << PSHIFT_PRESENT)
#define PFLAG_DIRTY         (1u << PSHIFT_DIRTY)
#define PFLAG_WORK_ONGOING  (1u << PSHIFT_WORK_ONGOING)
#define PFLAG_EVICT_ONGOING (1u << PSHIFT_EVICT_ONGOING)
#define PFLAG_HOT_MARKER    (1u << PSHIFT_HOT_MARKER)
#define PFLAG_HOT_MARKER2   (1u << PSHIFT_HOT_MARKER2)
#define PAGE_FLAGS_MASK     ((1u << PAGE_FLAGS_NUM) - 1)

static inline atomic_pginfo_t *page_ptr(struct region_t *mr, unsigned long addr)
{
    int offset = ((addr - mr->addr) >> CHUNK_SHIFT);
    return &mr->page_info[offset];
}

/**
 * Gets page metadata, includes flags and page node index
 */
static inline pginfo_t get_page_info(struct region_t *mr, unsigned long addr)
{
    atomic_pginfo_t *ptr = page_ptr(mr, addr);
    return *ptr;
}

/**
 * Gets page flags from pginfo
 */
static inline pgflags_t get_flags_from_pginfo(pginfo_t pginfo)
{
    return (pgflags_t) (pginfo & PAGE_FLAGS_MASK);
}

/**
 * Gets page flags
 */
static inline pgflags_t get_page_flags(struct region_t *mr, unsigned long addr)
{
    return get_flags_from_pginfo(get_page_info(mr, addr));
}

/**
 * Sets flags on a page and returns new flags (and oldflags in ptr)
 */
static inline pgflags_t set_page_flags(struct region_t *mr, unsigned long addr, 
    pgflags_t flags, pgflags_t* oldflags_out)
{
    pginfo_t oldinfo;
    pgflags_t oldflags, new_flags;
    atomic_pginfo_t *ptr;
    assert((flags & ~PAGE_FLAGS_MASK) == 0);  /* only page flags */

    log_debug("setting flags 0x%x on page 0x%lx", flags, addr);
    ptr = page_ptr(mr, addr);
    oldinfo = atomic_fetch_or(ptr, flags);
    oldflags = oldinfo & PAGE_FLAGS_MASK;
    if (oldflags_out)
        *oldflags_out = oldflags;
    new_flags = oldflags | flags;
    return new_flags;
}

/**
 * Clears flags on a page and returns new flags (and oldflags in ptr)
 */
static inline pgflags_t clear_page_flags(struct region_t *mr, unsigned long addr, 
    pgflags_t flags, pgflags_t* oldflags_out)
{
    pginfo_t oldinfo;
    pgflags_t oldflags, new_flags;
    atomic_pginfo_t *ptr;
    assert((flags & ~PAGE_FLAGS_MASK) == 0);  /* only page flags */
    
    log_debug("clearing flags 0x%x on page 0x%lx", flags, addr);
    ptr = page_ptr(mr, addr);
    oldinfo = atomic_fetch_and(ptr, ~flags);
    oldflags = oldinfo & PAGE_FLAGS_MASK;
    if (oldflags_out)
        *oldflags_out = oldflags;
    new_flags = oldflags & (~flags);
    return new_flags;
}

/**
 * Sets page flags on each page in the range
 */
static inline int set_page_flags_range(struct region_t *mr, unsigned long addr,
    size_t size, pgflags_t flags)
{
    unsigned long offset;
    pgflags_t oldflags;
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

/**
 * Clears page flags on each page in the range
 */
static inline int clear_page_flags_range(struct region_t *mr, 
    unsigned long addr, size_t size, pgflags_t flags)
{
    unsigned long offset;
    int chunks = 0;
    pgflags_t oldflags;

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
#define PAGE_INDEX_LEN      (sizeof(pginfo_t) * 8 - PAGE_INDEX_SHIFT)
#define PAGE_INDEX_MASK     (((1ULL << PAGE_INDEX_LEN) - 1) << PAGE_INDEX_SHIFT)
BUILD_ASSERT(PAGE_INDEX_MASK > 0);

/**
 * Gets page node index from pginfo
 */
static inline pgidx_t get_index_from_pginfo(pginfo_t pginfo)
{
    /* requires that page be locked to read index */
    assert(!!(pginfo & PFLAG_WORK_ONGOING));
    return (pgidx_t) ((pginfo & PAGE_INDEX_MASK) >> PAGE_INDEX_SHIFT);
}

/**
 * Gets page node index
 */
static inline pgidx_t get_page_index(struct region_t *mr, unsigned long addr)
{
    return get_index_from_pginfo(get_page_info(mr, addr));
}

/**
 * Sets page node index on a page and returns the old index
 */
static inline pgidx_t set_page_index(struct region_t *mr,
    unsigned long addr, pgidx_t index)
{
    pginfo_t pginfo, newinfo;
    atomic_pginfo_t *ptr;
    bool swapped;
    assert((index & ~((1 << PAGE_INDEX_LEN) - 1)) == 0); /* check index fits */

    /* compare-and-swap to not affect other flags */
    ptr = page_ptr(mr, addr);
    do {
        pginfo = atomic_load(ptr);
        assert(!!(pginfo & PFLAG_WORK_ONGOING)); /* require a page lock to set */
        newinfo = (pginfo & ~PAGE_INDEX_MASK);   /* keep non-index bits */
        newinfo |= (index << PAGE_INDEX_SHIFT);
        swapped = atomic_compare_exchange_weak(ptr, &pginfo, newinfo);
    } while(!swapped);

    /* old index */
    return (pginfo & PAGE_INDEX_MASK) >> PAGE_INDEX_SHIFT;
}

/**
 * Clears page node index on a page and returns the old index
 */
static inline pgidx_t clear_page_index(struct region_t *mr, unsigned long addr)
{
    return set_page_index(mr, addr, 0);
}

/**
 * Page node support (for locally present pages)
 * These nodes are juggled around LRU lists until the pages get kicked out to 
 * remote memory, after which they are reused for other pages
 */
struct rmpage_node {
    struct region_t *mr;
    unsigned long addr;
    unsigned long epoch;    /* epoch when page was last accessed */
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
static inline pgidx_t rmpage_get_node_id(rmpage_node_t* node)
{
    assert(rmpage_is_node_valid(node));
    return (pgidx_t)(node - rmpage_nodes);
}

static inline rmpage_node_t* rmpage_get_node_by_id(pgidx_t id)
{
    assert(id >= 0 && id < rmpage_node_count);
    return &rmpage_nodes[id];
}


#endif    // __RMEM_PAGE_H_