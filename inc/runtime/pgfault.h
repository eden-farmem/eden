/*
 * pgfault.h - support for userspace pagefaults
 */

#pragma once

#include <base/stddef.h>
#include <base/list.h>
#include <base/lock.h>
#include <runtime/thread.h>
#include <runtime/preempt.h>
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

#define PAGE_SIZE 4096

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

/* functions */
void possible_read_fault_on(void* address);
void possible_write_fault_on(void* address);
