/*
 * pflags.h - utils for handling remote memory page metadata
 */

#ifndef __PFLAGS_H__
#define __PFLAGS_H__

#include <stdatomic.h>
#include "rmem/region.h"

enum {
    PSHIFT_REGISTERED = 0,
    PSHIFT_PRESENT,
    PSHIFT_DIRTY,
    PSHIFT_NOEVICT,
    PSHIFT_WORK_ONGOING,
    PSHIFT_EVICT_ONGOING,
    PSHIFT_HOT_MARKER,
    UNUSED_1,
    PAGE_FLAGS_NUM
};
BUILD_ASSERT(is_power_of_two(PAGE_FLAGS_NUM));
BUILD_ASSERT(sizeof(pflags_t) * 8 == PAGE_FLAGS_NUM);

#define PFLAG_REGISTERED    (1u << PSHIFT_REGISTERED)
#define PFLAG_PRESENT       (1u << PSHIFT_PRESENT)
#define PFLAG_DIRTY         (1u << PSHIFT_DIRTY)
#define PFLAG_NOEVICT       (1u << PSHIFT_NOEVICT)
#define PFLAG_WORK_ONGOING  (1u << PSHIFT_WORK_ONGOING)
#define PFLAG_EVICT_ONGOING (1u << PSHIFT_EVICT_ONGOING)
#define PFLAG_HOT_MARKER    (1u << PSHIFT_HOT_MARKER)
#define PAGE_FLAGS_MASK     ((1u << PAGE_FLAGS_NUM) - 1)

static inline atomic_pflags_t *page_flags_ptr(struct region_t *mr, unsigned long addr,
        int *bits_offset) {
    int offset = ((addr - mr->addr) >> CHUNK_SHIFT);
    *bits_offset = 0;   /* TODO: remove */
    return &mr->page_flags[offset];
}

static inline pflags_t get_page_flags(struct region_t *mr, unsigned long addr) {
    int bit_offset;
    atomic_pflags_t *ptr = page_flags_ptr(mr, addr, &bit_offset);
    return (*ptr >> bit_offset) & PAGE_FLAGS_MASK;
}

static inline bool is_page_flags_set(struct region_t *mr, 
        unsigned long addr, pflags_t flags) {
    return !!(get_page_flags(mr, addr) & flags);
}

static inline bool is_pflags_set_in(pflags_t original, pflags_t expected) {
    return !!(original & expected);
}

/* sets flags on a page and returns new flags (and oldflags in ptr) */
static inline pflags_t set_page_flags(struct region_t *mr, 
    unsigned long addr, pflags_t flags, pflags_t* oldflags_out)
{
    int bit_offset;
    pflags_t oldflags, new_flags;
    atomic_pflags_t *ptr = page_flags_ptr(mr, addr, &bit_offset);

    oldflags = atomic_fetch_or(ptr, flags << bit_offset);
    oldflags = (oldflags >> bit_offset) & PAGE_FLAGS_MASK;
    if (oldflags_out)
        *oldflags_out = oldflags;
    new_flags = oldflags | flags;
    return new_flags;
}

/* clears flags on a page and returns new flags (and oldflags in ptr) */
static inline pflags_t clear_page_flags(struct region_t *mr, 
    unsigned long addr, pflags_t flags, pflags_t* oldflags_out)
{
    int bit_offset;
    pflags_t oldflags, new_flags;
    atomic_pflags_t *ptr = page_flags_ptr(mr, addr, &bit_offset);

    oldflags = atomic_fetch_and(ptr, ~(flags << bit_offset));
    oldflags = (oldflags >> bit_offset) & PAGE_FLAGS_MASK;
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

static inline int clear_page_flags_range(struct region_t *mr, unsigned long addr,
    size_t size, pflags_t flags)
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

#endif    // __PFLAGS_H_
