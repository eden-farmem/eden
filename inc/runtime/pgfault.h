/*
 * pgfault.h - gateway to scheduler-supported remote memory
 */

#pragma once

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

#define EDEN_PAGE_SHIFT    12
#define EDEN_PAGE_SIZE     (1UL << EDEN_PAGE_SHIFT)
#define EDEN_PAGE_MASK     (~(EDEN_PAGE_SIZE-1))
#define EDEN_MAX_READAHEAD 63

/* estimate number of pages to read-ahead based on a range */
#define readahead(addr, size)     \
    ((((unsigned long) addr + size - 1) >> EDEN_PAGE_SHIFT) -  \
    ((unsigned long) addr >> EDEN_PAGE_SHIFT))

/* hints that account for sequential access pattern */
#define hint_seq_read_fault(addr)		                            \
({                                                                  \
    static unsigned long __last_page = 0;                           \
    if (unlikely(!__last_page                                       \
            || (addr & ~EDEN_PAGE_MASK) != __last_page)) {          \
        __last_page = ((unsigned long) addr) & ~EDEN_PAGE_MASK;     \
        hint_read_fault(addr);	                                    \
    }                                                               \
})

#define hint_seq_read_fault_rdahead(addr, rdahead)		            \
({                                                                  \
    static unsigned long __start = 0;	                            \
    static unsigned long __end = 0;		                            \
    if (unlikely(!__start || addr < __start ||  addr > __end)) {    \
        __start = ((unsigned long) addr) & ~EDEN_PAGE_MASK;         \
        __end = __start + (rdahead << EDEN_PAGE_SHIFT) - 1;		    \
        hint_read_fault_rdahead(addr, rdahead);	                    \
    }                                                               \
})

#define hint_seq_write_fault(addr)		                            \
({                                                                  \
    static unsigned long __last_page = 0;                           \
    if (unlikely(!__last_page                                       \
            || (addr & ~EDEN_PAGE_MASK) != __last_page)) {          \
        __last_page = ((unsigned long) addr) & ~EDEN_PAGE_MASK;     \
        hint_read_fault(addr);	                                    \
    }                                                               \
})

#define hint_seq_write_fault_rdahead(addr, rdahead)		            \
({                                                                  \
    static unsigned long __start = 0;	                            \
    static unsigned long __end = 0;		                            \
    if (unlikely(!__start || addr < __start ||  addr > __end)) {    \
        __start = ((unsigned long) addr) & ~EDEN_PAGE_MASK;         \
        __end = __start + (rdahead << EDEN_PAGE_SHIFT) - 1;		    \
        hint_read_fault_rdahead(addr, rdahead);	                    \
    }                                                               \
})
