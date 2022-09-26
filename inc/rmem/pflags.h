/*
 * pflags.h - utils for handling remote memory page metadata
 */

#ifndef __PFLAGS_H__
#define __PFLAGS_H__

#include <stdatomic.h>
#include "rmem/region.h"

enum {
    PAGE_FLAG_P_SHIFT,
    PAGE_FLAG_D_SHIFT,
    PAGE_FLAG_E_SHIFT,
    PAGE_FLAG_Z_SHIFT,
    PAGE_FLAG_F_SHIFT,
    PAGE_FLAG_H_SHIFT,
    UNUSED_2,
    UNUSED_3,
    PAGE_FLAGS_NUM
};
BUILD_ASSERT(!(PAGE_FLAGS_NUM & (PAGE_FLAGS_NUM - 1))); /*power of 2*/

#define PAGE_FLAG_P (1u << PAGE_FLAG_P_SHIFT)    // Page is present
#define PAGE_FLAG_D (1u << PAGE_FLAG_D_SHIFT)    // Page is dirty
#define PAGE_FLAG_E (1u << PAGE_FLAG_E_SHIFT)    // Do not evict page
#define PAGE_FLAG_Z (1u << PAGE_FLAG_Z_SHIFT)    // Zeropage done
#define PAGE_FLAG_F (1u << PAGE_FLAG_F_SHIFT)    // Page fault in progress
#define PAGE_FLAG_H (1u << PAGE_FLAG_H_SHIFT)    // Page marked hot
#define PAGE_FLAGS_MASK ((1u << PAGE_FLAGS_NUM) - 1)

inline atomic_char *page_flags_ptr(struct region_t *mr, unsigned long addr,
        int *bits_offset) {
    int b = ((addr - mr->addr) >> CHUNK_SHIFT) * PAGE_FLAGS_NUM;
    *bits_offset = b % 8;
    return &mr->page_flags[b / 8];
}

#define RET_BOOL static inline bool 
#define RET_UCHAR static inline unsigned char

inline unsigned char get_page_flags(struct region_t *mr, unsigned long addr) {
    int bit_offset;
    atomic_char *ptr = page_flags_ptr(mr, addr, &bit_offset);
    return (*ptr >> bit_offset) & PAGE_FLAGS_MASK;
}

RET_BOOL is_page_dirty(struct region_t *mr, unsigned long addr) {
    return !!(get_page_flags(mr, addr) & PAGE_FLAG_D);
}

RET_BOOL is_page_present(struct region_t *mr, unsigned long addr) {
    return !!(get_page_flags(mr, addr) & PAGE_FLAG_P);
}

RET_BOOL is_page_fault_in_progress(struct region_t *mr, unsigned long addr) {
    return !!(get_page_flags(mr, addr) & PAGE_FLAG_F);
}

RET_BOOL is_page_marked_hot(struct region_t *mr, unsigned long addr) {
    return !!(get_page_flags(mr, addr) & PAGE_FLAG_H);
}

inline bool is_page_do_not_evict(struct region_t *mr, unsigned long addr) {
    return !!(get_page_flags(mr, addr) & PAGE_FLAG_E);
}

RET_BOOL is_page_zeropage_done(struct region_t *mr, unsigned long addr) {
    return !!(get_page_flags(mr, addr) & PAGE_FLAG_Z);
}

RET_BOOL is_page_dirty_flags(unsigned char flags) {
    return !!(flags & PAGE_FLAG_D);
}

RET_BOOL is_page_present_flags(unsigned char flags) {
    return !!(flags & PAGE_FLAG_P);
}

RET_BOOL is_page_do_not_evict_flags(unsigned char flags) {
    return !!(flags & PAGE_FLAG_E);
}

RET_BOOL is_page_zeropage_done_flags(unsigned char flags) {
    return !!(flags & PAGE_FLAG_Z);
}

RET_BOOL is_page_marked_hot_flags(unsigned char flags) {
    return !!(flags & PAGE_FLAG_H);
}

RET_UCHAR set_page_flags(struct region_t *mr, unsigned long addr, 
        unsigned char flags) {
    int bit_offset;
    unsigned char old_flags;
    atomic_char *ptr = page_flags_ptr(mr, addr, &bit_offset);

    old_flags = atomic_fetch_or(ptr, flags << bit_offset);
    return (old_flags >> bit_offset) & PAGE_FLAGS_MASK;
}

RET_UCHAR set_page_present(struct region_t *mr, unsigned long addr) {
    return set_page_flags(mr, addr, PAGE_FLAG_P);
}

RET_UCHAR set_page_dirty(struct region_t *mr, unsigned long addr) {
    return set_page_flags(mr, addr, PAGE_FLAG_D | PAGE_FLAG_P);
}

RET_UCHAR set_page_do_not_evict(struct region_t *mr, unsigned long addr) {
    return set_page_flags(mr, addr, PAGE_FLAG_E);
}

RET_UCHAR set_page_zeropage_done(struct region_t *mr, unsigned long addr) {
    return set_page_flags(mr, addr, PAGE_FLAG_Z);
}

RET_UCHAR set_page_fault_in_progress(struct region_t *mr, unsigned long addr) {
    return set_page_flags(mr, addr, PAGE_FLAG_F);
}

RET_UCHAR set_page_hot(struct region_t *mr, unsigned long addr) {
    return set_page_flags(mr, addr, PAGE_FLAG_H);
}

RET_UCHAR clear_page_flags(struct region_t *mr, unsigned long addr,
        unsigned char flags) {
    int bit_offset;
    unsigned char old_flags;
    atomic_char *ptr = page_flags_ptr(mr, addr, &bit_offset);

    old_flags = atomic_fetch_and(ptr, ~(flags << bit_offset));
    return (old_flags >> bit_offset) & PAGE_FLAGS_MASK;
}

RET_UCHAR clear_page_present(struct region_t *mr, unsigned long addr) {
    return clear_page_flags(mr, addr, PAGE_FLAG_P | PAGE_FLAG_D | PAGE_FLAG_E);
}

RET_UCHAR clear_page_dirty(struct region_t *mr, unsigned long addr) {
    return clear_page_flags(mr, addr, PAGE_FLAG_D);
}

RET_UCHAR clear_page_do_not_evict(struct region_t *mr, unsigned long addr) {
    return clear_page_flags(mr, addr, PAGE_FLAG_E);
}

RET_UCHAR clear_page_zeropage_done(struct region_t *mr, unsigned long addr) {
    return clear_page_flags(mr, addr, PAGE_FLAG_Z);
}

RET_UCHAR clear_page_fault_in_progress(struct region_t *mr, unsigned long addr) {
    return clear_page_flags(mr, addr, PAGE_FLAG_F);
}

RET_UCHAR clear_page_hot(struct region_t *mr, unsigned long addr) {
    return clear_page_flags(mr, addr, PAGE_FLAG_H);
}

// static int mark_chunks_nonpresent(struct region_t *mr, unsigned long addr,
//         size_t size) {
//     unsigned long offset;
//     int old_flags, chunks = 0;

//     for (offset = 0; offset < size; offset += CHUNK_SIZE) {
//         old_flags = clear_page_present(mr, addr + offset);

//         if (!!(old_flags & PAGE_FLAG_P)) {
//             // pr_debug("Clear page present for: %lx", addr + offset); UNDO
//             chunks++;
//         }
//     }
//     // Return how many pages were marked as not present
//     return chunks;
// }

#undef RET_BOOL
#undef RET_UCHAR
#endif    // __PFLAGS_H_
