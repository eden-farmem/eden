/*
 * pgfault.c - support for userspace pagefaults
 */

#include <sys/auxv.h>

#include <base/lock.h>
#include <base/log.h>
#include <runtime/thread.h>
#include <runtime/pgfault.h>
#include <runtime/sync.h>
#include <runtime/vdso.h>

#include "defs.h"

/*
 * Scheduler-supported page faults 
 */

const char *version = "LINUX_2.6";
const char *name = "__vdso_prefetch_page";
typedef long (*prefetch_page_t)(const void *p);
static prefetch_page_t prefetch_page;

/**
 * pgfault_init - initializes page fault support 
 */
int pgfault_init()
{
#ifndef PAGE_FAULTS
	log_debug("PAGE_FAULTS not set, skipping pgfault_init");
	return 0;
#endif

	unsigned long sysinfo_ehdr;

	/* find prefetch_page vDSO symbol */
	sysinfo_ehdr = getauxval(AT_SYSINFO_EHDR);
	if (!sysinfo_ehdr) {
		log_err("AT_SYSINFO_EHDR is not present");
		return -ENOENT;
	}

	/* this requires a kernel with the prefetch_page vDSO patch:
	 * https://patchwork.kernel.org/project/linux-mm/cover/20210225072910.2811795-1-namit@vmware.com/ */
	vdso_init_from_sysinfo_ehdr(getauxval(AT_SYSINFO_EHDR));
	prefetch_page = (prefetch_page_t)vdso_sym(version, name);
	if (!prefetch_page) {
		log_err("Could not find %s in vdso", name);
		return -ENOENT;
	}

	/* check if a backend is available */
	if (fault_backend.is_ready == NULL) {
		log_err("found no backend for PAGE_FAULTS");
		return -EPERM;
	}
	if (!fault_backend.is_ready()) {
		/* TODO: should we wait until ready? */
		log_err("backend not ready for PAGE_FAULTS");
		return -EPERM;
	}
	return 0;
}

/**
 * pgfault_init_thread - initializes per-thread page fault support
 */
int pgfault_init_thread()
{
#ifndef PAGE_FAULTS
	log_debug("PAGE_FAULTS not set, skipping pgfault_init_thread");
	return 0;
#endif
	struct kthread *k = myk();

	k->pf_count = 0;
	spin_lock_init(&k->pf_lock);
	list_head_init(&k->pf_waiters);

	k->pf_channel = fault_backend.get_available_channel();
	if (k->pf_channel < 0) {
		log_err("could not get a pagefault channel");
		return -ENOENT;
	}
	return 0;
}

/**
 * pgfault_wait - block current thread and place it 
 * on current kthread's page fault wait queue
 * (called after the fault event is succesfully 
 * sent to the fault handler)
 */
void pgfault_wait()
{
	thread_t *myth;
	struct kthread *k = myk();

	spin_lock_np(&k->pf_lock);
	myth = thread_self();
	/* TODO: is link assured to be available? 
	 * it could also be used with a mutex, condvar, barrier, etc. */
	list_add_tail(&k->pf_waiters, &myth->link);
	k->pf_count++;
	thread_park_and_unlock_np(&k->pf_lock);
}

/**
 * pgfault_release -  release a thread from current 
 * kthread's page fault wait queue. the thread is 
 * expected to be in the queue (no checks done).
 * (called after the fault handler responds)
 */
void pgfault_release(thread_t *th)
{
	struct kthread *k = myk();

	spin_lock_np(&k->pf_lock);
	assert(!list_empty(&k->pf_waiters));
	list_del_from(&k->pf_waiters, &th->link);
	k->pf_count--;
	spin_unlock_np(&k->pf_lock);
	thread_ready(th);
}

static inline void __possible_fault_on(void* address, int flags) 
{
#ifndef PAGE_FAULTS
	return;
#endif
	int ret;
	unsigned long page_addr;

	/* check if page exists */
	page_addr = (unsigned long)address & ~(PAGE_SIZE - 1);
	ret = prefetch_page((void*) page_addr);
	if (ret == 0)
		return;

	/* prepare page fault */
	struct kthread *k = myk();
	thread_t* myth = thread_self();
	pgfault_t fault = {
		.channel = k->pf_channel,
		.fault_addr = page_addr,
		.flags = flags,
		.taginfo = (void*) myth
	};
	
	/* post */
	ret = fault_backend.post_async(fault.channel, &fault);
#ifdef PAGE_FAULTS_ASYNC
	/* wait until a queue slot is available; if the queue
	 * is often full, consider increasing queue size? */
	int found;
	while(ret != 0) {
		/* NOTE: never block on the fault queue without monitoring 
		 * the response queue, it might be blocked precisely because
		 * we're not emptying the response queue and the backend could
		 * not entertain any more faults */
		found = fault_backend.poll_response_async(k->pf_channel);
		if (unlikely(found)) {
			/* yield to scheduler so it can free the response and 
			 * hope that by the next time we get scheduled, the backend 
			 * moved forward, allowing us to post more faults */
			thread_yield_kthread();
		}
		cpu_relax();
		ret = fault_backend.post_async(fault.channel, &fault);
		STAT(PF_POST_RETRIES)++;
	};

	/* place thread on wait queue; return control to scheduler */
	STAT(PF_POSTED)++;
	pgfault_wait();
#else
	assert(ret == 0);	/* post() shouldn't fail in synchronous case */
	STAT(PF_POSTED)++;

	/* poll wait for the fault response */
	pgfault_t response = {0};
	do {
		ret = fault_backend.read_response_async(k->pf_channel, &response);
		cpu_relax();
	} while(ret != 0);

	assert((thread_t*) response.taginfo == myth);	/* sanity check */
	STAT(PF_RETURNED)++;
#endif

	/* the page should exist at this point */	
	assert(prefetch_page((void*) page_addr) == 0);
}

void possible_read_fault_on(void* address) {
	__possible_fault_on(address, FAULT_FLAG_READ);
}

void possible_write_fault_on(void* address) {
	__possible_fault_on(address, FAULT_FLAG_WRITE);
}

/* register a backend */
#ifdef WITH_KONA		/*kona backend*/
	struct fault_backend_ops fault_backend = {
		.post_async = app_post_fault_async,
		.poll_response_async = app_poll_fault_resp_async,
		.read_response_async = app_read_fault_resp_async,
		.is_ready = is_appfaults_initialized,
		.get_available_channel = app_faults_get_next_channel
	};	
#else					/*default*/
	struct fault_backend_ops fault_backend = {0};		
#endif
