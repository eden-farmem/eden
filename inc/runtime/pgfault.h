/*
 * pgfault.h - gateway to scheduler-supported remote memory
 */

#pragma once

/* runtime internal */
int __vdso_init();
bool __is_fault_pending(void* address, bool write, bool hint_eviction);

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

