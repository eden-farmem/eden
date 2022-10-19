/*
 * sched.c - a scheduler for user-level threads
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <base/stddef.h>
#include <base/lock.h>
#include <base/list.h>
#include <base/hash.h>
#include <base/limits.h>
#include <base/tcache.h>
#include <base/slab.h>
#include <base/log.h>
#include <runtime/sync.h>
#include <runtime/thread.h>
#include <runtime/pgfault.h>
#include "rmem/eviction.h"

#include "defs.h"

/* the current running thread, or NULL if there isn't one */
__thread thread_t *__self;
/* a pointer to the top of the per-kthread (TLS) runtime stack */
static __thread void *runtime_stack;
/* a pointer to the bottom of the per-kthread (TLS) runtime stack */
static __thread void *runtime_stack_base;

/* Flag to prevent watchdog from running */
bool disable_watchdog;

/* fast allocation of struct thread */
static struct slab thread_slab;
static struct tcache *thread_tcache;
static DEFINE_PERTHREAD(struct tcache_perthread, thread_pt);

/* used to track cycle usage in scheduler */
static __thread uint64_t last_tsc;
/* used to force timer and network processing after a timeout */
static __thread uint64_t last_watchdog_tsc;

/**
 * In inc/runtime/thread.h, this function is declared inline (rather than static
 * inline) so that it is accessible to the Rust bindings. As a result, it must
 * also appear in a source file to avoid linker errors.
 */
thread_t *thread_self(void);

/**
 * jmp_thread - runs a thread, popping its trap frame
 * @th: the thread to run
 *
 * This function restores the state of the thread and switches from the runtime
 * stack to the thread's stack. Runtime state is not saved.
 */
static __noreturn void jmp_thread(thread_t *th)
{
	assert_preempt_disabled();
	assert(th->state == THREAD_STATE_RUNNABLE);

	__self = th;
	th->state = THREAD_STATE_RUNNING;
	if (unlikely(load_acquire(&th->stack_busy))) {
		/* wait until the scheduler finishes switching stacks */
		while (load_acquire(&th->stack_busy))
			cpu_relax();
	}

	RUNTIME_EXIT();
	__jmp_thread(&th->tf);
}

/**
 * jmp_thread_direct - runs a thread, popping its trap frame
 * @oldth: the last thread to run
 * @newth: the next thread to run
 *
 * This function restores the state of the thread and switches from the runtime
 * stack to the thread's stack. Runtime state is not saved.
 */
static void jmp_thread_direct(thread_t *oldth, thread_t *newth)
{
	assert_preempt_disabled();
	assert(newth->state == THREAD_STATE_RUNNABLE);

	__self = newth;
	newth->state = THREAD_STATE_RUNNING;
	if (unlikely(load_acquire(&newth->stack_busy))) {
		/* wait until the scheduler finishes switching stacks */
		while (load_acquire(&newth->stack_busy))
			cpu_relax();
	}
	__jmp_thread_direct(&oldth->tf, &newth->tf, &oldth->stack_busy);
}

/**
 * jmp_runtime - saves the current trap frame and jumps to a function in the
 *               runtime
 * @fn: the runtime function to call
 *
 * WARNING: Only threads can call this function.
 *
 * This function saves state of the running thread and switches to the runtime
 * stack, making it safe to run the thread elsewhere.
 */
static void jmp_runtime(runtime_fn_t fn)
{
	assert_preempt_disabled();
	assert(thread_self() != NULL);

	RUNTIME_ENTER();
	__jmp_runtime(&thread_self()->tf, fn, runtime_stack);
}

/**
 * jmp_runtime_nosave - jumps to a function in the runtime without saving the
 *			caller's state
 * @fn: the runtime function to call
 */
static __noreturn void jmp_runtime_nosave(runtime_fn_t fn)
{
	assert_preempt_disabled();

	RUNTIME_ENTER();
	__jmp_runtime_nosave(fn, runtime_stack);
}

static void drain_overflow(struct kthread *l)
{
	thread_t *th;

	assert_spin_lock_held(&l->lock);

	while (l->rq_head - l->rq_tail < RUNTIME_RQ_SIZE) {
		th = list_pop(&l->rq_overflow, thread_t, link);
		if (!th)
			break;
		l->rq[l->rq_head++ % RUNTIME_RQ_SIZE] = th;
		l->q_ptrs->rq_head++;
		l->rq_overflow_len--;
	}
}

/* do the remote memory work in the scheduler; returns true if there are threads 
 * whose remote memory needs are handled and are ready to run */
static inline bool do_remote_memory_work(struct kthread *k)
{
	int nready;

	/* we must be out of work to get here */
	assert(k->rq_head == k->rq_tail);

	/* currently, kthread holds a lock the entire time it is in the scheduler
	 * runtime but we should release the big lock during remote memory work as 
	 * it may take significant amount of time and hurt work stealing by other 
	 * kthreads. we will protect remote memory data structures with a different 
	 * lock (pf_lock) in a more fine-grained manner */
	assert_spin_lock_held(&k->lock);
	spin_unlock(&k->lock);

	/* check on stolen/owned completions and waiting faults, in that order */
	nready = 0;
	if (k->n_cq_steals_q > 0)
		nready += kthr_handle_stolen_completed_faults(k);
	nready += kthr_check_for_completions(k, RMEM_MAX_COMP_PER_OP);
	nready += kthr_handle_waiting_faults(k);

	/* set all these served faults as not-pending */
	spin_lock(&k->pf_lock);
    assert(k->pf_pending >= nready);
    k->pf_pending -= nready;
    spin_unlock(&k->pf_lock);

	/* re-take the big lock and check the ready queue once more */
	spin_lock(&k->lock);

	/* we may expect that "nready" to be equal to the length of the ready queue 
	 * but since we do not hold the big lock, they may get 
	 * stolen from the ready queue by the time we get here. After taking the 
	 * lock again, the ready_q should reflect the real count of ready threads 
	 * still waiting to be scheduled on the current kthread, not "nready" */
	log_debug("have %d ready threads after checking on rmem work",
		(k->rq_head - k->rq_tail));
	return (k->rq_head - k->rq_tail) > 0;
}

/* steal remote memory completions and waiting fault from other threads */
static inline bool steal_remote_memory_work(struct kthread *l, struct kthread *r)
{
	int nstolen = 0;

	assert_spin_lock_held(&l->lock);
	assert_spin_lock_held(&r->lock);
	assert(!spin_lock_held(&l->pf_lock));

	spin_lock(&l->pf_lock);
	nstolen += kthr_steal_completions(r, RMEM_MAX_COMP_PER_OP);
	nstolen += kthr_steal_waiting_faults(l, r);
	spin_unlock(&l->pf_lock);
	return (nstolen > 0);
}

/* steal ready threads from other threads */
static inline bool steal_ready_work(struct kthread *l, struct kthread *r)
{
	thread_t *th;
	uint32_t i, avail, rq_tail;

	assert_spin_lock_held(&l->lock);
	assert_spin_lock_held(&r->lock);

	/* check that local runqueue is empry and reset it. Note that this is 
	 * us helping avoid modulo-ing (rq_head % RUNTIME_RQ_SIZE) to index the 
	 * ready queue as long as we don't add more than RUNTIME_RQ_SIZE threads */
	assert(l->rq_head == l->rq_tail);
	l->rq_head = l->rq_tail = 0;

	/* try to steal directly from the runqueue */
	avail = load_acquire(&r->rq_head) - r->rq_tail;
	avail = div_up(avail, 2);
	if (avail) {
		/* steal half the tasks */
		assert(avail <= div_up(RUNTIME_RQ_SIZE, 2));
		rq_tail = r->rq_tail;
		for (i = 0; i < avail; i++)
			l->rq[i] = r->rq[rq_tail++ % RUNTIME_RQ_SIZE];
		store_release(&r->rq_tail, rq_tail);
		r->q_ptrs->rq_tail += avail;

		l->rq_head = avail;
		l->q_ptrs->rq_head += avail;
		STAT(THREADS_STOLEN) += avail;
		log_debug("%p stole %d threads from %p RQ", l, avail, r);
		return true;
	}

	/* check for overflow tasks */
	th = list_pop(&r->rq_overflow, thread_t, link);
	if (th) {
		r->rq_overflow_len--;
		l->rq[l->rq_head++ % RUNTIME_RQ_SIZE] = th;
		l->q_ptrs->rq_head++;
		STAT(THREADS_STOLEN)++;
		return true;
	}

	return false;
}

/* steal softirqs from other threads */
static inline bool steal_softirq_work(struct kthread *l, struct kthread *r)
{
	thread_t *th;

	assert_spin_lock_held(&l->lock);
	assert_spin_lock_held(&r->lock);

	/* check for softirqs */
	th = softirq_run_thread(r, RUNTIME_SOFTIRQ_BUDGET);

	/* enqueue the stolen work */
	if (th) {
		l->rq[l->rq_head++ % RUNTIME_RQ_SIZE] = th;
		l->q_ptrs->rq_head++;
		STAT(SOFTIRQS_STOLEN)++;
		return true;
	}

	return false;
}

/* steal work from other threads */
static bool steal_work(struct kthread *l, struct kthread *r)
{
	assert_spin_lock_held(&l->lock);
	assert(l->rq_head == l->rq_tail);

	/* reset the local runqueue since it's empty. Note that this is helping 
	 * us avoid */
	l->rq_head = l->rq_tail = 0;

	if (!spin_try_lock(&r->lock))
		return false;

	/* harmless race condition */
	if (unlikely(r->detached)) {
		spin_unlock(&r->lock);
		return false;
	}

	/* steal ready work first */
	if (steal_ready_work(l, r)) {
		spin_unlock(&r->lock);
		return true;
	}

#ifdef REMOTE_MEMORY_HINTS
	/* then steal remote memory work */
	if (steal_remote_memory_work(l ,r)) {
		spin_unlock(&r->lock);
		
		/* we have some stolen faults, however it is not ready to run as the 
		 * faults need further handling before releasing threads, and
		 * let's handle stolen completions immediately so we don't run out of 
		 * bkend_bufs; we also release locks on both l and r for stealing 
		 * while handling the faults */
		if (do_remote_memory_work(l)) {
			/* found ready work, return */
			return true;
		}

		/* stole work but none of it was ready just yet, let's return now and 
		 * come back here later */
		return false;
	}
#endif

	/* then steal other work */
	if (steal_softirq_work(l, r)) {
		spin_unlock(&r->lock);
		return true;
	}

	/* no ready work to steal. if the thread has no pending faults either, 
	 * detach it if it was already parked */
	if (r->parked && r->pf_pending == 0) {
		kthread_detach(r);
	}
	
	spin_unlock(&r->lock);
	return false;
}

static __noinline struct thread *do_watchdog(struct kthread *l)
{
	thread_t *th;

	assert_spin_lock_held(&l->lock);

	/* then check the network queues */
	th = softirq_run_thread(l, RUNTIME_SOFTIRQ_BUDGET);
	if (th) {
		STAT(SOFTIRQS_LOCAL)++;
		return th;
	}

	return NULL;
}

/* the main scheduler routine, decides what to run next */
static __noreturn __noinline void schedule(void)
{
	struct kthread *r = NULL, *l = myk();
	uint64_t start_tsc, end_tsc, duration;
	thread_t *th = NULL;
	unsigned int last_nrks;
	unsigned int iters = 0;
	int i, sibling;
	bool first_try = true;

	assert_spin_lock_held(&l->lock);
	assert(l->parked == false);
	assert(l->detached == false);

	/* unmark busy for the stack of the last uthread */
	if (__self != NULL) {
		store_release(&__self->stack_busy, false);
		__self = NULL;
	}

	/* detect misuse of preempt disable */
	BUG_ON((preempt_cnt & ~PREEMPT_NOT_PENDING) != 1);

	/* update entry stat counters */
	STAT(RESCHEDULES)++;
	start_tsc = rdtsc();
	STAT(PROGRAM_CYCLES) += start_tsc - last_tsc;

	/* increment the RCU generation number (even is in scheduler) */
	store_release(&l->rcu_gen, l->rcu_gen + 1);
	assert((l->rcu_gen & 0x1) == 0x0);

	/* if it's been too long, run the softirq handler */
	if (!disable_watchdog &&
	    unlikely(start_tsc - last_watchdog_tsc >
	             cycles_per_us * RUNTIME_WATCHDOG_US)) {
		last_watchdog_tsc = start_tsc;
		th = do_watchdog(l);
		if (th)
			goto done;
	}

	/* move overflow tasks into the runqueue */
	if (unlikely(!list_empty(&l->rq_overflow)))
		drain_overflow(l);

again:
	/* first try the local runqueue */
	if (l->rq_head != l->rq_tail)
		goto done;

	/* reset the local runqueue since it's empty */
	l->rq_head = l->rq_tail = 0;

	/* then handle remote memory */
#ifdef REMOTE_MEMORY_HINTS
	if(do_remote_memory_work(l))
		goto done;
#endif

	/* then check for local softirqs */
	th = softirq_run_thread(l, RUNTIME_SOFTIRQ_BUDGET);
	if (th) {
		STAT(SOFTIRQS_LOCAL)++;
		goto done;
	}

	last_nrks = load_acquire(&nrks);

	/* then try to steal from a sibling kthread */
	sibling = cpu_map[l->curr_cpu].sibling_core;
	r = cpu_map[sibling].recent_kthread;
	if (r && r != l && steal_work(l, r))
		goto done;

	/* then try to steal from a random kthread */
	r = ks[rand_crc32c((uintptr_t)l) % last_nrks];
	if (r != l && steal_work(l, r))
		goto done;

	/* finally try to steal from every kthread */
	for (i = 0; i < last_nrks; i++)
		if (ks[i] != l && steal_work(l, ks[i]))
			goto done;

	/* need to retry */
	first_try = false;

	/* keep trying to find work until the polling timeout expires */
	if (!preempt_needed() &&
	    (++iters < RUNTIME_SCHED_POLL_ITERS ||
	    rdtsc() - start_tsc < cycles_per_us * RUNTIME_SCHED_MIN_POLL_US ||
		l->pf_pending > 0))
		goto again;

	/* did not find anything to run, park this kthread */
	duration = rdtsc() - start_tsc;
	STAT(SCHED_CYCLES_IDLE) += duration;
	STAT(SCHED_CYCLES) += duration;
	/* we may have got a preempt signal before voluntarily yielding */
	kthread_park(!preempt_needed());
	start_tsc = rdtsc();

	goto again;

done:
	/* pop off a thread and run it */
	if (!th) {
		assert(l->rq_head != l->rq_tail);
		th = l->rq[l->rq_tail++ % RUNTIME_RQ_SIZE];
		l->q_ptrs->rq_tail++;
	}

	/* move overflow tasks into the runqueue */
	if (unlikely(!list_empty(&l->rq_overflow)))
		drain_overflow(l);

	spin_unlock(&l->lock);

	/* update exit stat counters */
	end_tsc = rdtsc();
	duration = end_tsc - start_tsc;
	STAT(SCHED_CYCLES) += duration;
	if (!first_try)
		/* if we didn't get here in the first try, count 
		 * all the time towards idling TODO: don't count the time spent in 
		 * fault handing towards this */
		STAT(SCHED_CYCLES_IDLE) += duration;
	last_tsc = end_tsc;

	/* increment the RCU generation number (odd is in thread) */
	store_release(&l->rcu_gen, l->rcu_gen + 1);
	assert((l->rcu_gen & 0x1) == 0x1);

	/* and jump into the next thread */
	jmp_thread(th);
}

/**
 * join_kthread - detaches a kthread immediately (rather than through stealing)
 * @k: the kthread to detach
 *
 * Can and must be called from thread context.
 */
void join_kthread(struct kthread *k)
{
	thread_t *waketh;
	struct list_head tmp;

	log_info_ratelimited("join_kthread() %p", k);

	list_head_init(&tmp);

	/* if the lock can't be acquired, the kthread is unparking */
	if (!spin_try_lock_np(&k->lock))
		return;

	/* harmless race conditions */
	if (k->detached || !k->parked || k == myk()) {
		spin_unlock_np(&k->lock);
		return;
	}

	/* drain the runqueue */
	for (; k->rq_tail < k->rq_head; k->rq_tail++) {
		list_add_tail(&tmp, &k->rq[k->rq_tail % RUNTIME_RQ_SIZE]->link);
		k->q_ptrs->rq_tail++;
	}
	k->rq_head = k->rq_tail = 0;

	/* drain the overflow runqueue */
	list_append_list(&tmp, &k->rq_overflow);
	k->rq_overflow_len = 0;

#ifdef REMOTE_MEMORY
	/* REMOTE MEMORY TODO: */
	/* also drain the remote memory waiting faults and stolen completions */
	BUG();
#endif

	/* detach the kthread */
	kthread_detach(k);
	spin_unlock_np(&k->lock);

	/* re-wake all the runnable threads belonging to the detached kthread */
	while (true) {
		waketh = list_pop(&tmp, thread_t, link);
		if (!waketh)
			break;
		waketh->state = THREAD_STATE_SLEEPING;
		thread_ready(waketh);
	}
}

static __always_inline void enter_schedule(thread_t *myth)
{
	struct kthread *k = myk();
	thread_t *th;
	bool visit_runtime;

	assert_preempt_disabled();
	spin_lock(&k->lock);

	/* slow path: switch from the uthread stack to the runtime stack 
	 * WHEN there are no ready threads or some time has passed if watchdog 
	 * or remote memory is enabled */
	visit_runtime = !disable_watchdog || (rmem_enabled && k->pf_pending > 0);
	if (k->rq_head == k->rq_tail || 
	    (visit_runtime && unlikely(rdtsc() - last_tsc > 
			cycles_per_us * RUNTIME_VISIT_US))) {
		jmp_runtime(schedule);
		RUNTIME_EXIT();
		return;
	}

	/* fast path: switch directly to the next uthread */

	/* pop the next runnable thread from the queue */
	th = k->rq[k->rq_tail++ % RUNTIME_RQ_SIZE];
	k->q_ptrs->rq_tail++;
	spin_unlock(&k->lock);

	/* increment the RCU generation number (odd is in thread) */
	store_release(&k->rcu_gen, k->rcu_gen + 2);
	assert((k->rcu_gen & 0x1) == 0x1);

	/* check for misuse of preemption disabling */
	BUG_ON((preempt_cnt & ~PREEMPT_NOT_PENDING) != 1);

	/* check if we're switching into the same thread as before */
	if (unlikely(th == myth)) {
		th->state = THREAD_STATE_RUNNING;
		th->stack_busy = false;
		preempt_enable();
		RUNTIME_EXIT();
		return;
	}

	/* switch stacks and enter the next thread */
	STAT(RESCHEDULES)++;
	RUNTIME_EXIT();
	jmp_thread_direct(myth, th);
}

/**
 * thread_park_and_unlock_np - puts a thread to sleep, unlocks the lock @l,
 * and schedules the next thread
 * @l: the lock to be released
 */
void thread_park_and_unlock_np(spinlock_t *l)
{
	thread_t *myth = thread_self();

	assert_preempt_disabled();
	assert_spin_lock_held(l);
	assert(myth->state == THREAD_STATE_RUNNING);

	myth->state = THREAD_STATE_SLEEPING;
	myth->stack_busy = true;
	spin_unlock(l);

	enter_schedule(myth);
}

/**
 * thread_yield - yields the currently running thread
 *
 * Yielding will give other threads a chance to run.
 */
void thread_yield(void)
{
	thread_t *myth = thread_self();

	/* check for softirqs */
	softirq_run(RUNTIME_SOFTIRQ_BUDGET);

	/* REMOTE MEMORY TODO: check for waitin faults and fault completions */

	preempt_disable();
	assert(myth->state == THREAD_STATE_RUNNING);
	myth->state = THREAD_STATE_SLEEPING;
	store_release(&myth->stack_busy, true);
	thread_ready(myth);

	enter_schedule(myth);
}

static __always_inline void enter_schedule_with_fault(thread_t *th, fault_t* f)
{
    struct kthread *k;
    struct region_t* mr;
    int nevicts_needed = 0, nevicts = 0;
    enum fault_status fstatus;

	/* my kthread */
	assert_preempt_disabled();
	k = myk();

	/* accounting */
    if (f->is_read)         RSTAT(FAULTS_R)++;
    if (f->is_write)        RSTAT(FAULTS_W)++;
    if (f->is_wrprotect)    RSTAT(FAULTS_WP)++;

    /* find region */
    mr = get_region_by_addr_safe(f->page);
    BUG_ON(!mr);  /* we dont do region deletions yet so it must exist */
    assert(mr->addr);
    f->mr = mr;

	/* start handling fault */
    fstatus = handle_page_fault(k->bkend_chan_id, f, &nevicts_needed, 
        &kthr_owner_cbs);
    switch (fstatus) {
        case FAULT_DONE:
			/* unlikely but we're done before we started */
            kthr_fault_done(f);
			goto schedule;
            break;
        case FAULT_IN_PROGRESS:
            /* add to wait and yield to run another thread */
            spin_lock(&k->pf_lock);
            list_add_tail(&k->fault_wait_q, &f->link);
            k->n_wait_q++;
            k->pf_pending++;
            spin_unlock(&k->pf_lock);
            log_debug("%s - added to wait", FSTR(f));
			goto schedule;
            break;
        case FAULT_READ_POSTED:
            /* nothing to do here, we check for completions later*/
            spin_lock(&k->pf_lock);
            k->pf_pending++;
            spin_unlock(&k->pf_lock);
            log_debug("%s - posted read", FSTR(f));
            if (nevicts_needed)
                goto eviction;
            goto schedule;
            break;
    }

eviction:
    /* start eviction; evict only as much as needed on shenango cores */
    while(nevicts < nevicts_needed)
        nevicts += do_eviction(k->bkend_chan_id, &kthr_owner_cbs, 
            min(nevicts_needed - nevicts, EVICTION_MAX_BATCH_SIZE));

schedule:
	enter_schedule(th);
}

/**
 * thread_park - puts a thread to sleep and yields to the scheduler with 
 * the information on the potential page å
 * @address: fault address
 * @write: whether the fault was due to a write operation
 * @rdahead: how many pages to read-ahead with the faulting page
 */
void thread_park_on_fault(void* address, bool write, int rdahead)
{
#ifndef REMOTE_MEMORY_HINTS
    log_err("%s not supported without remote memory", __func__);
    BUG();
#endif
    struct fault* fault;
	thread_t *myth;

	/* entering runtime */
	preempt_disable();
	RUNTIME_ENTER();

	/* park thread */
	myth = thread_self();
	assert(myth->state == THREAD_STATE_RUNNING);
	myth->state = THREAD_STATE_SLEEPING;
	myth->stack_busy = true;

	/* alloc fault object */
    fault = fault_alloc();
    if (unlikely(!fault)) {
        log_debug("couldn't get a fault object");
        BUG();
    }
    memset(fault, 0, sizeof(fault_t));
    fault->page = ((unsigned long) address) & ~CHUNK_MASK;
    fault->is_read = !write;
    fault->is_write = write;
    fault->from_kernel = false;
    fault->rdahead_max = rdahead;
	BUG_ON(1 + rdahead > RMEM_MAX_CHUNKS_PER_OP);	/* read ahead limit */
    fault->rdahead = 0;
    fault->thread = thread_self();
    log_debug("fault posted at %lx write %d", fault->page, write);

	/* enter scheduler with fault */
	enter_schedule_with_fault(myth, fault);

    /* fault serviced when we get back here */
    assert(!__is_fault_pending(address, write));
    ASSERT_NOT_IN_RUNTIME();
}

/**
 * __thread_ready_unsafe - marks a thread as a runnable
 * @th: the thread to mark runnable
 *
 * This function can only be called internally when releasing 
 * the threads from within the runtime, @th is 
 * sleeping and preempt is disabled.
 */
void thread_ready_np(thread_t *th)
{
	struct kthread *k;
	uint32_t rq_tail;

	assert_preempt_disabled();
	assert(th->state == THREAD_STATE_SLEEPING);
	th->state = THREAD_STATE_RUNNABLE;

	k = myk();
	rq_tail = load_acquire(&k->rq_tail);
	if (unlikely(k->rq_head - rq_tail >= RUNTIME_RQ_SIZE)) {
		assert(k->rq_head - rq_tail == RUNTIME_RQ_SIZE);
		spin_lock(&k->lock);
		list_add_tail(&k->rq_overflow, &th->link);
		k->rq_overflow_len++;
		spin_unlock(&k->lock);
		return;
	}

	k->rq[k->rq_head % RUNTIME_RQ_SIZE] = th;
	store_release(&k->rq_head, k->rq_head + 1);
	k->q_ptrs->rq_head++;
}

/**
 * thread_ready - marks a thread as a runnable
 * @th: the thread to mark runnable
 *
 * This function can only be called when @th is sleeping.
 */
void thread_ready(thread_t *th)
{
	getk();
	thread_ready_np(th);
	putk();
}

static void thread_finish_yield_kthread(void)
{
	struct kthread *k = myk();
	thread_t *myth = thread_self();

	assert(myth->state == THREAD_STATE_RUNNING);
	myth->state = THREAD_STATE_SLEEPING;
	thread_ready(myth);

	STAT(PROGRAM_CYCLES) += rdtsc() - last_tsc;

	store_release(&k->rcu_gen, k->rcu_gen + 1);
	spin_lock(&k->lock);
	clear_preempt_needed();
	kthread_park(false);
	last_tsc = rdtsc();
	store_release(&k->rcu_gen, k->rcu_gen + 1);

	schedule();
}

/**
 * thread_yield_kthread - yields the running thread and immediately parks
 */
void thread_yield_kthread(void)
{
	/* this will switch from the thread stack to the runtime stack */
	preempt_disable();
	jmp_runtime(thread_finish_yield_kthread);
}

static __always_inline thread_t *__thread_create(void)
{
	struct thread *th;
	struct stack *s;

	preempt_disable();
	th = tcache_alloc(&perthread_get(thread_pt));
	if (unlikely(!th)) {
		preempt_enable();
		return NULL;
	}

	s = stack_alloc();
	if (unlikely(!s)) {
		tcache_free(&perthread_get(thread_pt), th);
		preempt_enable();
		return NULL;
	}
	preempt_enable();

	th->stack = s;
	th->state = THREAD_STATE_SLEEPING;
	th->main_thread = false;

	return th;
}

/**
 * thread_create - creates a new thread
 * @fn: a function pointer to the starting method of the thread
 * @arg: an argument passed to @fn
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
thread_t *thread_create(thread_fn_t fn, void *arg)
{
	thread_t *th = __thread_create();
	if (unlikely(!th))
		return NULL;

	th->tf.rsp = stack_init_to_rsp(th->stack, thread_exit);
	th->tf.rdi = (uint64_t)arg;
	th->tf.rbp = (uint64_t)0; /* just in case base pointers are enabled */
	th->tf.rip = (uint64_t)fn;
	th->stack_busy = false;
	return th;
}

/**
 * thread_create_with_buf - creates a new thread with space for a buffer on the
 * stack
 * @fn: a function pointer to the starting method of the thread
 * @buf: a pointer to the stack allocated buffer (passed as arg too)
 * @buf_len: the size of the stack allocated buffer
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
thread_t *thread_create_with_buf(thread_fn_t fn, void **buf, size_t buf_len)
{
	void *ptr;
	thread_t *th = __thread_create();
	if (unlikely(!th))
		return NULL;

	th->tf.rsp = stack_init_to_rsp_with_buf(th->stack, &ptr,
						buf_len, thread_exit);
	th->tf.rdi = (uint64_t)ptr;
	th->tf.rbp = (uint64_t)0; /* just in case base pointers are enabled */
	th->tf.rip = (uint64_t)fn;
	th->stack_busy = false;
	*buf = ptr;
	return th;
}

/**
 * thread_spawn - creates and launches a new thread
 * @fn: a function pointer to the starting method of the thread
 * @arg: an argument passed to @fn
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
int thread_spawn(thread_fn_t fn, void *arg)
{
	thread_t *th = thread_create(fn, arg);
	if (unlikely(!th))
		return -ENOMEM;
	thread_ready(th);
	return 0;
}

/**
 * thread_spawn_main - creates and launches the main thread
 * @fn: a function pointer to the starting method of the thread
 * @arg: an argument passed to @fn
 *
 * WARNING: Only can be called once.
 *
 * Returns 0 if successful, otherwise -ENOMEM if out of memory.
 */
int thread_spawn_main(thread_fn_t fn, void *arg)
{
	static bool called = false;
	thread_t *th;

	BUG_ON(called);
	called = true;

	th = thread_create(fn, arg);
	if (!th)
		return -ENOMEM;
	th->main_thread = true;
	thread_ready(th);
	return 0;
}

static void thread_finish_exit(void)
{
	struct thread *th = thread_self();

	/* if the main thread dies, kill the whole program */
	if (unlikely(th->main_thread))
		init_shutdown(EXIT_SUCCESS);
	stack_free(th->stack);
	tcache_free(&perthread_get(thread_pt), th);
	__self = NULL;

	spin_lock(&myk()->lock);
	schedule();
}

/**
 * thread_exit - terminates a thread
 */
void thread_exit(void)
{
	/* can't free the stack we're currently using, so switch */
	preempt_disable();
	jmp_runtime_nosave(thread_finish_exit);
}

/**
 * immediately park each kthread when it first starts up, only schedule it once
 * the iokernel has granted it a core
 */
static __noreturn void schedule_start(void)
{
	struct kthread *k = myk();

	/*
	 * force kthread parking (iokernel assumes all kthreads are parked
	 * initially). Update RCU generation so it stays even after entering
	 * schedule().
	 */
	kthread_wait_to_attach();
	store_release(&k->rcu_gen, 1);

	spin_lock(&k->lock);
	schedule();
}

/**
 * sched_start - used only to enter the runtime the first time
 */
void sched_start(void)
{
	last_tsc = rdtsc();
	preempt_disable();
	jmp_runtime_nosave(schedule_start);
}

static void runtime_top_of_stack(void)
{
	panic("a thread returned to the top of the stack");
}

/**
 * sched_init_thread - initializes per-thread state for the scheduler
 *
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int sched_init_thread(void)
{
	struct stack *s;

	tcache_init_perthread(thread_tcache, &perthread_get(thread_pt));

	s = stack_alloc();
	if (!s)
		return -ENOMEM;

	runtime_stack_base = (void *)s;
	runtime_stack = (void *)stack_init_to_rsp(s, runtime_top_of_stack); 

	return 0;
}

/**
 * sched_init - initializes the scheduler subsystem
 *
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int sched_init(void)
{
	int ret, i, j, siblings;

	/*
	 * set up allocation routines for threads
	 */
	ret = slab_create(&thread_slab, "runtime_threads",
			  sizeof(struct thread), 0);
	if (ret)
		return ret;

	thread_tcache = slab_create_tcache(&thread_slab,
					   TCACHE_DEFAULT_MAG_SIZE);
	if (!thread_tcache) {
		slab_destroy(&thread_slab);
		return -ENOMEM;
	}

	for (i = 0; i < cpu_count; i++) {
		siblings = 0;
		bitmap_for_each_set(cpu_info_tbl[i].thread_siblings_mask,
				    cpu_count, j) {
			if (i == j)
				continue;
			BUG_ON(siblings++);
			cpu_map[i].sibling_core = j;
		}
	}

	return 0;
}
