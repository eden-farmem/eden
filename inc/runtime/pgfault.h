/*
 * pgfault.h - gateway to scheduler-supported remote memory
 */

#pragma once

#include "base/stddef.h"

/* runtime internal */
int __vdso_init();
bool __is_fault_pending(void* address, bool write, bool hint_eviction);
void thread_park_on_fault(void* address, bool write, int rdahead, int evprio);

/**
 * Pagefault API
 * hint the scheduler to check for an impending page fault and take over if so
 */

#if defined(REMOTE_MEMORY_HINTS) || defined(EDEN_HINTS)
#define hint_fault(addr,write,rd,prio)                      \
    do {                                                    \
        if (__is_fault_pending(addr, write, true))          \
            thread_park_on_fault(addr, write, rd, prio);    \
    } while (0);
#else
#define hint_fault(addr,write,rd,prio)      do {} while(0)
#endif

/* API */
#define hint_read_fault(addr)               hint_fault(addr, false, 0,  0)
#define hint_write_fault(addr)              hint_fault(addr, true,  0,  0)
#define hint_read_fault_rdahead(addr,rd)    hint_fault(addr, false, rd, 0)
#define hint_write_fault_rdahead(addr,rd)   hint_fault(addr, true,  rd, 0)
#define hint_read_fault_prio(addr,pr)       hint_fault(addr, false, 0,  pr)
#define hint_write_fault_prio(addr,rd)      hint_fault(addr, true,  0,  pr)
#define hint_read_fault_all(addr,rd,pr)     hint_fault(addr, false, rd, pr)
#define hint_write_fault_all(addr,rd,pr)    hint_fault(addr, true,  rd, pr)

/* back-compat API */
#define possible_read_fault_on 	            hint_read_fault
#define possible_write_fault_on	            hint_write_fault


/**
 *  Other useful functions/macros
 **/

#define EDEN_PAGE_SHIFT         12
#define EDEN_PAGE_SIZE          (1UL << EDEN_PAGE_SHIFT)
#define EDEN_PAGE_OFFSET_MASK   (EDEN_PAGE_SIZE-1)
#define EDEN_PAGE_ID_MASK       (~(EDEN_PAGE_SIZE-1))
#define EDEN_MAX_READAHEAD      63
#define PAGE_ID(addr) (((unsigned long) addr) & EDEN_PAGE_ID_MASK)


/**
 * Hints that account for sequential page access to skip
 * unnecessary page checks 
 **/

#if defined(REMOTE_MEMORY_HINTS) || defined(EDEN_HINTS)
#define hint_fault_seq(addr, write, rdahead, prio)		            \
({                                                                  \
    static unsigned long __last_page = 0;                           \
    if (unlikely(!__last_page || PAGE_ID(addr) != __last_page)) {   \
        __last_page = PAGE_ID(addr);                                \
        hint_fault(addr, write, rdahead, prio);	                    \
    }                                                               \
})

#define hint_fault_seq_rdahead(addr, write, rdahead, prio)		    \
({                                                                  \
    static unsigned long __start = 0;	                            \
    static unsigned long __end = 0;		                            \
    if (unlikely(!__start || (unsigned long) addr < __start ||      \
            (unsigned long) addr >= __end)) {                       \
        __start = PAGE_ID(addr);                                    \
        __end = __start + ((1 + rdahead) << EDEN_PAGE_SHIFT);	    \
        hint_fault(addr, write, rdahead, prio);	                    \
    }                                                               \
})
#else
#define hint_fault_seq(addr)                        do {} while(0)
#define hint_fault_seq_rdahead(addr, rdahead)       do {} while(0)
#endif

#define hint_seq_read_fault(addr)   hint_fault_seq(addr, false, 0, 0)
#define hint_seq_write_fault(addr)  hint_fault_seq(addr, true,  0, 0)
#define hint_seq_read_fault_rdahead(addr, rdahead)  hint_fault_seq_rdahead(addr, false, rdahead, 0)
#define hint_seq_write_fault_rdahead(addr, rdahead) hint_fault_seq_rdahead(addr, true,  rdahead, 0)

/** 
 * Region-based hints to get a multi-page region at once
 */

#define hint_fault_region(addr, size, write, max_rdahead, prio)                \
({                                                                             \
    int rdahead;                                                               \
    char *__start, *__end;                                                     \
                                                                               \
    __start = (char*)(align_down((unsigned long) addr, EDEN_PAGE_SIZE));       \
    __end = (char*)(align_down((unsigned long) addr + size, EDEN_PAGE_SIZE));  \
    while (__start <= __end) {                                                 \
        rdahead = MIN((__end - __start) >> EDEN_PAGE_SHIFT, max_rdahead);      \
        hint_fault(__start, write, rdahead, prio)                              \
        __start += (((1 + rdahead)) << EDEN_PAGE_SHIFT);                       \
    }                                                                          \
})

#define hint_read_fault_region(addr, size)                      hint_fault_region(addr, size, false, 0, 0)
#define hint_write_fault_region(addr, size)                     hint_fault_region(addr, size, true,  0, 0)
#define hint_read_fault_region_rdahead(addr, size, rdahead)     hint_fault_region(addr, size, false, rdahead, 0)
#define hint_write_fault_region_rdahead(addr, size, rdahead)    hint_fault_region(addr, size, true,  rdahead, 0)

/* back-compat API */
#define hint_read_fault_pbsafe  hint_read_fault_region
#define hint_write_fault_pbsafe hint_write_fault_region
