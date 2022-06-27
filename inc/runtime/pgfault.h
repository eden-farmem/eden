/*
 * pgfault.h - support for userspace pagefaults
 */

#pragma once

#ifdef WITH_KONA
#include <klib.h>
#endif

/*
 * Scheduler-supported page faults 
 */

#ifdef PAGE_FAULTS
	#error "Use PAGE_FAULTS_SYNC or PAGE_FAULTS_ASYNC"
#endif
#if defined(PAGE_FAULTS_ASYNC) || defined(PAGE_FAULTS_SYNC)
	#define PAGE_FAULTS
#endif

#define PROFILING

#define PAGE_SHIFT (12)
#define PAGE_SIZE (1ull << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))

#ifdef WITH_KONA		/*kona backend*/
	#define FAULT_FLAG_READ             APP_FAULT_FLAG_READ
	#define FAULT_FLAG_WRITE            APP_FAULT_FLAG_WRITE
	typedef app_fault_packet_t pgfault_t;
#else					/*default*/
	#define FAULT_FLAG_READ             (1<<0)
	#define FAULT_FLAG_WRITE            (1<<1)
	struct _pgfault {
		uint16_t channel;
		uint16_t flags;
		/* note: it's essential that the backend returns tag unmodified */
		void* tag;
		unsigned long fault_addr;
	};
	typedef struct _pgfault pgfault_t;	
#endif

/* define and register backend */
struct fault_backend_ops {
	int (*post_async)(int channel, pgfault_t *fault);
	int (*poll_response_async)(int channel);
	int (*read_response_async)(int channel, pgfault_t *response_buf);
	int (*is_ready)(void);
	int (*get_available_channel)(void);
};
extern struct fault_backend_ops fault_backend;

/* UNDO */
typedef long (*vdso_check_page_t)(const void *p);
extern vdso_check_page_t is_page_mapped;
extern vdso_check_page_t is_page_mapped_and_wrprotected;


/* functions */
void possible_read_fault_on(void* address);
void possible_write_fault_on(void* address);
