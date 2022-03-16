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
	struct kthread *k = myk();
	k->pf_pending = 0;
#ifndef PAGE_FAULTS
	log_debug("PAGE_FAULTS not set, skipping pgfault_init_thread");
	return 0;
#endif

	k->pf_channel = fault_backend.get_available_channel();
	if (k->pf_channel < 0) {
		log_err("could not get a pagefault channel");
		return -ENOENT;
	}
	return 0;
}


static inline void __possible_fault_on(void* address, int flags) 
{
#ifndef PAGE_FAULTS
	return;
#endif
	int ret, posted = 0;
	unsigned long page_addr;
	struct kthread *k;
#ifdef PAGE_FAULTS_SYNC
	struct kthread *l;
#endif

	/* check if page exists */
	page_addr = (unsigned long)address & ~(PAGE_SIZE - 1);
	ret = prefetch_page((void*) page_addr);
	if (ret == 0)
		return;

	thread_t* myth = thread_self();
	pgfault_t fault = {
		.channel = -1,	/* to be filled */
		.fault_addr = page_addr,
		.flags = flags,
		.tag = (void*) myth
	};

	do {
		/* we may be running in a different kthread
		 * in each loop due to preemption or stealing */
		k = getk();
		spin_lock(&k->pf_lock);
		fault.channel = k->pf_channel;

		/* post */
		log_debug("thread %p posting fault %lx on channel %d", 
			myth, page_addr, fault.channel);
		ret = fault_backend.post_async(fault.channel, &fault);
		posted = (ret == 0);
		STAT(PF_POST_RETRIES)++;
		if (posted) {
			break;
		}
#ifdef PAGE_FAULTS_SYNC
		BUG();	/* post shouldn't fail in sync case */
#endif

		/* nothing we can do except wait and try again later */
		log_debug("thread %p could not post. yielding", myth);
		spin_unlock(&k->pf_lock);
		putk();
		thread_yield();
	} while (!posted);
	k->pf_pending++;
	STAT(PF_POSTED)++;

#ifdef PAGE_FAULTS_SYNC
	spin_unlock(&k->pf_lock);
	putk();

	/* poll wait for the fault response */
	pgfault_t response = {0};
	do {
		l = getk();
		/* make sure we're running on the same kernel thread */
		assert(k->pf_channel == l->pf_channel);	
		ret = fault_backend.read_response_async(l->pf_channel, &response);
		putk();
		cpu_relax();
	} while(ret != 0);

	assert(response.fault_addr == page_addr);	/* sanity checks */
	assert((thread_t*) response.tag == myth);
	STAT(PF_RETURNED)++;
#else 
	/* wait until woken up */
	thread_park_and_unlock_np(&k->pf_lock);
#endif

	/* the page should exist at this point */	
// #ifdef DEBUG	// UNDO
	log_debug("thread %p released after servicing %lx", myth, page_addr);
	if (prefetch_page((void*) page_addr) != 0) {
		STAT(PF_FAILED)++;
		log_debug("thread %p pagefault serviced but can't find page %lx", myth, page_addr);
	}
// #endif
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
