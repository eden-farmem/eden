
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>

#include <base/time.h>
#include <rmem/common.h>
#include <runtime/thread.h>
#include <runtime/timer.h>

int usleep(useconds_t usec)
{
	if (unlikely(!__self || !preempt_enabled())) {
		static int (*fn)(useconds_t);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "usleep");
		return fn(usec);
	}

	timer_sleep(usec);
	return 0;
}

unsigned int sleep(unsigned int seconds)
{
	if (unlikely(!__self || !preempt_enabled())) {
		static int (*fn)(unsigned int);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "sleep");
		return fn(seconds);
	}

	timer_sleep(seconds * ONE_SECOND);
	return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
	if (unlikely(!__self || !preempt_enabled())) {
		static int (*fn)(const struct timespec *, struct timespec *);
		if (!fn)
			fn = dlsym(RTLD_NEXT, "nanosleep");
		return fn(req, rem);
	}

	timer_sleep(req->tv_sec * ONE_SECOND + req->tv_nsec / 1000);

	if (rem) {
		rem->tv_sec = 0;
		rem->tv_nsec = 0;
	}

	return 0;
}

void exit(int status)
{
	/* this means exit no matter where it is called from. we intercept it to 
	 * reset __self because we can get here from shenango threads without going 
	 * into runtime but exit() processing might require original std lib 
	 * functions */
	// __self = NULL;

	static void (*fn)(int);
	if (!fn)
		fn = dlsym(RTLD_NEXT, "exit");
	fn(status);
	unreachable();
}