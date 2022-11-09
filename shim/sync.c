
#include <dlfcn.h>
#include <pthread.h>

#include <runtime/sync.h>

BUILD_ASSERT(sizeof(pthread_barrier_t) >= sizeof(barrier_t));
BUILD_ASSERT(sizeof(pthread_mutex_t) >= sizeof(mutex_t));
BUILD_ASSERT(sizeof(pthread_spinlock_t) >= sizeof(spinlock_t));
BUILD_ASSERT(sizeof(pthread_cond_t) >= sizeof(condvar_t));
BUILD_ASSERT(sizeof(pthread_rwlock_t) >= sizeof(rwmutex_t));

int pthread_mutex_init(pthread_mutex_t *mutex,
		       const pthread_mutexattr_t *mutexattr)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_mutex_t*, const pthread_mutexattr_t *);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_mutex_init");
		return fn(mutex, mutexattr);
	}

	mutex_init((mutex_t *)mutex);
	return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_mutex_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_mutex_lock");
		return fn(mutex);
	}

	mutex_lock((mutex_t *)mutex);
	return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_mutex_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_mutex_trylock");
		return fn(mutex);
	}

	return mutex_try_lock((mutex_t *)mutex) ? 0 : EBUSY;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{

	if (unlikely(!__self)) {
		static int (*fn)(pthread_mutex_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_mutex_unlock");
		return fn(mutex);
	}

	mutex_unlock((mutex_t *)mutex);
	return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_mutex_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_mutex_destroy");
		return fn(mutex);
	}

	return 0;
}

int pthread_barrier_init(pthread_barrier_t *restrict barrier,
			 const pthread_barrierattr_t *restrict attr,
			 unsigned count)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_barrier_t * restrict,
				 const pthread_barrierattr_t *restrict,
				 unsigned);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_barrier_init");
		return fn(barrier, attr, count);
	}

	barrier_init((barrier_t *)barrier, count);

	return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_barrier_t *);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_barrier_wait");
		return fn(barrier);
	}

	if (barrier_wait((barrier_t *)barrier))
		return PTHREAD_BARRIER_SERIAL_THREAD;

	return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_barrier_t *);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_barrier_destroy");
		return fn(barrier);
	}

	return 0;
}

int pthread_spin_destroy(pthread_spinlock_t *lock)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_spinlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_spin_destroy");
		return fn(lock);
	}

	return 0;
}

int pthread_spin_init(pthread_spinlock_t *lock, int pshared)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_spinlock_t*, int);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_spin_init");
		return fn(lock, pshared);
	}

	spin_lock_init((spinlock_t *)lock);
	return 0;
}

int pthread_spin_lock(pthread_spinlock_t *lock)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_spinlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_spin_lock");
		return fn(lock);
	}

	spin_lock_np((spinlock_t *)lock);
	return 0;
}

int pthread_spin_trylock(pthread_spinlock_t *lock)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_spinlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_spin_trylock");
		return fn(lock);
	}

	return spin_try_lock_np((spinlock_t *)lock) ? 0 : EBUSY;
}

int pthread_spin_unlock(pthread_spinlock_t *lock)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_spinlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_spin_unlock");
		return fn(lock);
	}

	spin_unlock_np((spinlock_t *)lock);
	return 0;
}

int pthread_cond_init(pthread_cond_t *__restrict cond,
		      const pthread_condattr_t *__restrict cond_attr)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_cond_t *, const pthread_condattr_t *);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_cond_init");
		return fn(cond, cond_attr);
	}

	condvar_init((condvar_t *)cond);
	return 0;
}

int pthread_cond_signal(pthread_cond_t *cond)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_cond_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_cond_signal");
		return fn(cond);
	}

	condvar_signal((condvar_t *)cond);
	return 0;
}

int pthread_cond_broadcast(pthread_cond_t *cond)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_cond_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_cond_broadcast");
		return fn(cond);
	}

	condvar_broadcast((condvar_t *)cond);
	return 0;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_cond_t*, pthread_mutex_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_cond_wait");
		return fn(cond, mutex);
	}

	condvar_wait((condvar_t *)cond, (mutex_t *)mutex);
	return 0;
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
			   const struct timespec *abstime)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_cond_t*, pthread_mutex_t*,
				 const struct timespec*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_cond_timedwait");
		return fn(cond, mutex, abstime);
	}

	BUG();
}

int pthread_cond_destroy(pthread_cond_t *cond)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_cond_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_cond_destroy");
		return fn(cond);
	}

	return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *r)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_rwlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_rwlock_destroy");
		return fn(r);
	}

	return 0;
}

int pthread_rwlock_init(pthread_rwlock_t *r, const pthread_rwlockattr_t *attr)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_rwlock_t*, const pthread_rwlockattr_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_rwlock_init");
		return fn(r, attr);
	}

	rwmutex_init((rwmutex_t *)r);
	return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *r)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_rwlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_rwlock_rdlock");
		return fn(r);
	}

	rwmutex_rdlock((rwmutex_t *)r);
	return 0;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *r)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_rwlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_rwlock_tryrdlock");
		return fn(r);
	}

	return rwmutex_try_rdlock((rwmutex_t *)r) ? 0 : EBUSY;
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *r)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_rwlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_rwlock_trywrlock");
		return fn(r);
	}

	return rwmutex_try_wrlock((rwmutex_t *)r) ? 0 : EBUSY;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *r)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_rwlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_rwlock_wrlock");
		return fn(r);
	}

	rwmutex_wrlock((rwmutex_t *)r);
	return 0;
}

int pthread_rwlock_unlock(pthread_rwlock_t *r)
{
	if (unlikely(!__self)) {
		static int (*fn)(pthread_rwlock_t*);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "pthread_rwlock_unlock");
		return fn(r);
	}
	
	rwmutex_unlock((rwmutex_t *)r);
	return 0;
}
