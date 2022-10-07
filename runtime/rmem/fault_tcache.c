
/*
 * fault_tcache.c - fault object tcache
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include <unistd.h>

#include "base/assert.h"
#include "rmem/fault.h"

/* fault tcache state */
static struct tcache *fault_tcache;
DEFINE_PERTHREAD(struct tcache_perthread, fault_pt);

static DEFINE_SPINLOCK(fault_lock);
static int fault_count = 0, free_fault_count = 0;
static struct fault *free_faults[RUNTIME_MAX_FAULTS];

static void fault_tcache_free(struct tcache *tc, int nr, void **items)
{
	/* save  for reallocation */
	int i;
	spin_lock(&fault_lock);
	for (i = 0; i < nr; i++) {
		BUG_ON(free_fault_count >= RUNTIME_MAX_FAULTS);
		free_faults[free_fault_count++] = items[i];
	}
	spin_unlock(&fault_lock);
}

static int fault_tcache_alloc(struct tcache *tc, int nr, void **items)
{
	int i = 0;

	spin_lock(&fault_lock);
	while (free_fault_count && i < nr) {
		items[i++] = free_faults[--free_fault_count];
	}

	for (; i < nr; i++) {
        /* allocate new */
        if(++fault_count > RUNTIME_MAX_FAULTS){
    		log_err_ratelimited("too many faults, cannot allocate more");
			goto fail;
		}
		items[i] = aligned_alloc(CACHE_LINE_SIZE, sizeof(fault_t));
		if (unlikely(!items[i])) {
			log_err_ratelimited("fault: failed to allocate fault memory");
			goto fail;
		}
	}
	spin_unlock(&fault_lock);
	return 0;
fail:
	spin_unlock(&fault_lock);
	fault_tcache_free(tc, i, items);
	return -ENOMEM;
}

static const struct tcache_ops fault_tcache_ops = {
	.alloc	= fault_tcache_alloc,
	.free	= fault_tcache_free,
};

/**
 * fault_init_thread - inits per-thread tcache for fault objects
 * Returns 0 (always successful).
 */
int fault_tcache_init_thread(void)
{
	tcache_init_perthread(fault_tcache, &perthread_get(fault_pt));
	return 0;
}

/**
 * fault_tcache_init - initializes the global fault allocator
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int fault_tcache_init(void)
{
	fault_tcache = tcache_create("rmem_faults_tcache", &fault_tcache_ops, 
		FAULT_TCACHE_MAG_SIZE, sizeof(fault_t));
	if (!fault_tcache)
		return -ENOMEM;
	return 0;
}