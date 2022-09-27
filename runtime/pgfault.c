/*
 * pgfault.c - support for userspace pagefaults
 */

#include <sys/auxv.h>

#include <base/lock.h>
#include <base/log.h>
#include <base/time.h>
#include <runtime/thread.h>
#include <runtime/pgfault.h>
#include <runtime/sync.h>
#include <runtime/vdso.h>

#include "defs.h"

/*
 * Scheduler-supported page faults 
 */

const char *version = "LINUX_2.6";
const char *name_mapped = "__vdso_is_page_mapped";
const char *name_wp = "__vdso_is_page_mapped_and_wrprotected";
typedef long (*vdso_check_page_t)(const void *p);
vdso_check_page_t is_page_mapped_vdso;
vdso_check_page_t is_page_mapped_and_readonly_vdso;

/**
 * pgfault_init - initializes page fault support 
 */
int pgfault_init()
{
#ifndef PAGE_FAULTS
	log_info("PAGE_FAULTS not set, skipping pgfault_init");
	return 0;
#endif

#ifdef PAGE_FAULTS_ASYNC
	log_info("initializing ASYNC pagefaults");
#else
	log_info("initializing SYNC pagefaults");
#endif

	unsigned long sysinfo_ehdr;

	/* find vDSO symbols */
	sysinfo_ehdr = getauxval(AT_SYSINFO_EHDR);
	if (!sysinfo_ehdr) {
		log_err("AT_SYSINFO_EHDR is not present");
		return -ENOENT;
	}

	vdso_init_from_sysinfo_ehdr(getauxval(AT_SYSINFO_EHDR));
	is_page_mapped_vdso = (vdso_check_page_t)vdso_sym(version, name_mapped);
	if (!is_page_mapped_vdso) {
		log_err("Could not find %s in vdso", name_mapped);
		return -ENOENT;
	}
	is_page_mapped_and_readonly_vdso = (vdso_check_page_t)vdso_sym(version, name_wp);
	if (!is_page_mapped_and_readonly_vdso) {
		log_err("Could not find %s in vdso", name_wp);
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

	/* fast path */
#ifdef KONA_PAGE_CHECKS
	bool nofault = (flags & FAULT_FLAG_READ)
		? kapi_is_page_mapped((unsigned long)address)
		: kapi_is_page_mapped_and_readonly((unsigned long)address);
#else
	bool nofault = (flags & FAULT_FLAG_READ)
		? is_page_mapped_vdso(address)
		: is_page_mapped_and_readonly_vdso(address);
#endif

	if (nofault) {
		/* Only do this for debugging, this will affect performance 
		 * of fastpath when running with multiple cores */
		STAT(PF_ANNOT_HITS)++;
		return;
	}

	/* fault path */
	int ret, posted = 0;
	struct kthread *k;
	bool yield;
	unsigned long start_tsc = 0;
#ifdef PAGE_FAULTS_SYNC
	struct kthread *l;
#endif

	thread_t* myth = thread_self();
	pgfault_t fault = {
		.channel = -1,	/* to be filled */
		.fault_addr = (unsigned long) address,
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
		log_debug("thread %p posting fault %p on channel %d", 
			myth, address, fault.channel);
		ret = fault_backend.post_async(fault.channel, &fault);
		posted = (ret == 0);
		if (posted) {
			if (start_tsc != 0)
				STAT(SCHED_CYCLES_IDLE) += (rdtscp(NULL) - start_tsc);
			break;
		}
#ifdef PAGE_FAULTS_SYNC
		BUG();	/* post shouldn't fail in sync case */
#endif

		/* nothing we can do except wait and try again later */
		log_debug("thread %p could not post", myth);
		spin_unlock(&k->pf_lock);

		/* count towards idle time as long as the we're waiting to post */
		if (start_tsc == 0)
			start_tsc = rdtsc();

		/* check if we should yield; its important that we yield 
		 * to resolve page fault responses to avoid livelocks. 
		 * currently we do not yield for external irqs like network 
		 * events */
		yield = timer_needed(k) || pgfault_response_ready(k);
		putk();

		if (yield) {
			log_debug("thread %p yielding", myth);
			/* record idle time before yielding */
			STAT(SCHED_CYCLES_IDLE) += (rdtscp(NULL) - start_tsc);
			thread_yield();
			start_tsc = rdtsc();	/* start idle time again */
		}

		cpu_relax();
	} while (!posted);
	k->pf_pending++;
	STAT(PF_POSTED)++;

#ifdef PAGE_FAULTS_SYNC
	spin_unlock(&k->pf_lock);
	putk();

	/* poll wait for the fault response */
	start_tsc = rdtsc();
	pgfault_t response = {0};
	do {
		l = getk();
		/* make sure we're running on the same kernel thread */
		assert(k->pf_channel == l->pf_channel);	
		ret = fault_backend.read_response_async(l->pf_channel, &response);
		l->pf_pending--;
		putk();
		cpu_relax();
	} while(ret != 0);

	/* sanity checks */
	// assert((response.fault_addr & PAGE_MASK) == ((unsigned long) address & PAGE_MASK));
	assert((thread_t*) response.tag == myth);
	STAT(PF_RETURNED)++;

	/* count the wait as idle time */
	STAT(SCHED_CYCLES_IDLE) += (rdtscp(NULL) - start_tsc);
#else 
	/* wait until woken up */
	thread_park_and_unlock_np(&k->pf_lock);
#endif

#ifdef DEBUG
	/* there should be no fault at this point */	
	log_debug("thread %p released after servicing %p", myth, address);
#ifdef KONA_PAGE_CHECKS
	nofault = (flags & FAULT_FLAG_READ)
		? kapi_is_page_mapped((unsigned long)address)
		: kapi_is_page_mapped_and_readonly((unsigned long)address);
#else
	nofault = (flags & FAULT_FLAG_READ)
		? is_page_mapped_vdso(address)
		: is_page_mapped_and_readonly_vdso(address);
#endif
	if (!nofault) {
		STAT(PF_FAILED)++;
		log_debug("thread %p pagefault serviced but still faults at %p", 
			myth, address);
	}
#endif

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