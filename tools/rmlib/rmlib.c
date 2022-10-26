/**
 * rmlib.c - Memory interposition library to get all heap allocations
 * in UFFD/remote memory
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
#include <jemalloc/jemalloc.h>

#include "base/assert.h"
#include "base/atomic.h"
#include "base/log.h"
#include "base/mem.h"
#include "rmem/api.h"
#include "rmem/common.h"
#include "rmem/region.h"

#undef NDEBUG

/**
 * Defs 
 */
enum init_state {
    NOT_STARTED = 0,
    INITIALIZED = 1,
    INIT_STARTED = 2,
    INIT_FAILED = 3
};

/* State */
__thread bool __from_internal_jemalloc = false;
static volatile int rmem_state = NOT_STARTED;
static atomic_t rmlib_state = ATOMIC_INIT(NOT_STARTED);

/* Interposed alloc fn signatures */
static void *(*real_malloc)(size_t) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void (*real_free)(void *) = NULL;
static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
static int (*real_madvise)(void *, size_t, int) = NULL;
static int (*real_munmap)(void *, size_t) = NULL;
static void *libc6 = NULL;
int shm_id;

/**
 * Helpers 
 */
int parse_env_settings()
{
    char *memory_limit, *evict_thr; 
    

    /* set local memory */
    memory_limit = getenv("LOCAL_MEMORY");
    /* Hack: fix a bug wheren env variable has non-printable chars at start */
    if (memory_limit != NULL)
        while (!isalnum(memory_limit[0]) && memory_limit[0] != 0)
            memory_limit++;

    if (memory_limit == NULL) {
        log_err("set LOCAL_MEMORY (in bytes) env var to enable remote memory");
        return 1;
    }
    local_memory = atoll(memory_limit);

    /* set eviction threshold */
    evict_thr = getenv("EVICTION_THRESHOLD");
    if (evict_thr != NULL)
        eviction_threshold = atof(evict_thr);
    
    return 0;
}

/**
 * Alloclib wrappers for RMem API
 */
void *rmlib_rmalloc(size_t size)
{
    log_debug("[%s] size=%lu", __func__, size);
    void *p = rmalloc(size);
    return p;
}

void *rmlib_rmrealloc(void *ptr, size_t size, size_t old_size)
{
    log_debug("[%s] ptr=%p,size=%lu,old_size=%lu", 
        __func__, ptr, size, old_size);
    void *p = rmrealloc(ptr, size, old_size);
    return p;
}

void *rmlib_realloc(void *ptr, size_t size, size_t old_size)
{
    log_debug("[%s] ptr=%p,size=%lu,old_size=%lu", 
        __func__, ptr, size, old_size);
    void *p = rmalloc(size);
    if (ptr != NULL && old_size > 0) {
        memmove(p, ptr, old_size);
    }
    return p;
}

void *rmlib_rmmap(void *addr, size_t length, int prot, 
    int flags, int fd, off_t offset)
{
    void *p = NULL;
    if (!(flags & MAP_ANONYMOUS) || !(flags & MAP_ANON) || (prot & PROT_EXEC) 
            || (flags & (MAP_STACK | MAP_FIXED | MAP_DENYWRITE))
            || (addr && !within_memory_region(addr))) {
        p = real_mmap(addr, length, prot, flags, fd, offset);
    } else {
        /* we don't support these flags */
        assertz(prot & PROT_EXEC);
        assertz(flags & MAP_STACK);
        assertz(flags & MAP_FIXED);
        assertz(flags & MAP_DENYWRITE);
        assert(fd == -1);
        assert(length);
        log_debug("using rmlib_rmalloc'");
        p = rmlib_rmalloc(length);
    }
    return p;
}

int rmlib_rmunmap(void *ptr, size_t length)
{
    if (!ptr) return 0;
    if (!within_memory_region(ptr)) {
        return real_munmap(ptr, length);
    } else {
        return rmunmap(ptr, length);
    }
}

/**
 * Inits to save original alloc fns 
**/

static void init_malloc(void) {
    char *error;
    /* clear existing errors */
    dlerror();
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    if ((error = dlerror()) != NULL) {
        log_err("Error in dlsym: %s", error);
        exit(1);
    }
    log_debug("set real_malloc");
}

static void init_realloc(void) {
    char *error;
    /* clear existing errors */
    dlerror();
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    if ((error = dlerror()) != NULL) {
        log_err("Error in dlsym: %s", error);
        exit(1);
    }
    log_debug("set real_realloc");
}

static void init_free(void) {
    char *error;
    /* clear existing errors */
    dlerror();
    real_free = dlsym(RTLD_NEXT, "free");
    if ((error = dlerror()) != NULL) {
        log_err("Error in dlsym: %s", error);
        exit(1);
    }
    log_debug("set real_free");
}

static void init_libc6(void) {
    char *error;
    dlerror();
    libc6 = dlopen("libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
    if ((error = dlerror()) != NULL) {
        log_err("Error in dlopen: %s", error);
        exit(1);
    }
    log_debug("set libc6");
}

static void init_mmap() {
    if (NULL == libc6) {
        init_libc6();
    }
    char *error;
    /* clear existing errors */
    dlerror();
    real_mmap = dlsym(libc6, "mmap");
    if ((error = dlerror()) != NULL) {
        log_err("Error in `dlsym`: %s", error);
        exit(1);
    }
    log_debug("set real_mmap");
}

static void init_madvise() {
    if (NULL == libc6) {
        init_libc6();
    }
    char *error;
    /* clear existing errors */
    dlerror();
    real_madvise = dlsym(libc6, "madvise");
    if ((error = dlerror()) != NULL) {
        log_err("Error in `dlsym`: %s", error);
        exit(1);
    }
    log_debug("set real_madvise");
}

static void init_munmap() {
    if (NULL == libc6) {
        init_libc6();
    }
    char *error;
    /* clear existing errors */
    dlerror();
    real_munmap = dlsym(libc6, "munmap");
    if ((error = dlerror()) != NULL) {
        log_err("Error in `dlsym`: %s", error);
        exit(1);
    }
    log_debug("set real_munmap");
}

static void init_real_libs() {
    init_malloc();
    init_realloc();
    init_free();
    init_mmap();
    init_madvise();
    init_munmap();
}

/**
 *  Main AllocLib Initialization
 * We could initialize rmlib in a constructor, such as:
 * static __attribute__((constructor)) void __init__(void)
 * but that would be incorrect because the contructor is called
 * before main, but malloc can be called during other libraries 
 * initializations.
 * 
 * Note on jemalloc: jemalloc relies on libc mmap, which we interpose.
 * To initialize mmap, we call dlopen, which calls malloc.
 * Need to be extra careful during init to avoid infinite loops.
 */
static bool init(bool init_start_expected)
{
    bool ret;
    int r, oldval, shmid, initd;
    key_t key;

    /* check rmlib status */
    initd = atomic_read(&rmlib_state);
    switch (initd)
    {
        case NOT_STARTED:
            BUG_ON(init_start_expected);
            break;
        case INIT_STARTED:
        case INIT_FAILED:
            return false;
        case INITIALIZED:
            mb();
            assert(rmem_state == 1);
            break;
        default:
            BUG();  /*unknown*/
    }

    /* claim the one to be initing */
    oldval = atomic_cmpxchg_val(&rmlib_state, NOT_STARTED, INIT_STARTED);
    log_debug("CAS ret=%d", oldval);
    if (oldval != NOT_STARTED)
        /* someone else started, return & let them finish */
        return false;

    /* do this first to avoid relying on libc functions */
    init_real_libs();

    /* check for fork'ed processes that inherit LD_PRELOAD */
    key = ftok("rmem_rmlib", 65);
    shmid = shmget(key, 1024, 0666 | IPC_CREAT | IPC_EXCL);
    log_info("shm id for key %d: %d", key, shmid);

    if (shmid < 0) {
        log_warn("failed to create new shmid, some other process or parent" 
            "process may already be running with rmlib. errno: %d", errno);
        /* use libc for fork'ed processes */
        goto error;
    }

    /* just a hey! to whoever might be listening (aka debugging) */
    shm_id = shmid;
    char *str = (char *)shmat(shmid, (void *)0, 0);
    sprintf(str, "Hello World from %d %d", getpid(), shmid);
    log_debug("data in shared memory %s", str);
    shmdt(str);

    /* get settings from env */
    r = parse_env_settings();
    if (r) {
        log_err("failed to parse env settings");
        goto error;
    }

    /* init rmem (with local backend) */
    log_debug("calling rmem init");
    rmem_enabled = true;
    rmbackend_type = RMEM_BACKEND_LOCAL;
    r = rmem_common_init();
    if (r)
        goto error;

    /* done initializing */
    ret = atomic_cmpxchg(&rmlib_state, INIT_STARTED, INITIALIZED);
    BUG_ON(!ret);
    mb();
    rmem_state = 1;     /* only initialization thread executes this */
    return true;

error:
    ret = atomic_cmpxchg(&rmlib_state, INIT_STARTED, INIT_FAILED);
    BUG_ON(!ret);
    log_warn("couldn't init remote memory; reverting to libc");
    return false;
}

/**
 * Lib C Alloc Functions
 */

void *libc_malloc(size_t size)
{
    log_debug("size=%lu", size);
    // TODO: save pointers returned by libc malloc to use
    // libc_free on them later.
    extern void *__libc_malloc(size_t);
    void *ptr = __libc_malloc(size);
    log_debug("return=%p", ptr);
    return ptr;
}

void *libc_realloc(void *ptr, size_t size)
{
    log_debug("[%s] ptr=%p size=%lu", __func__, ptr, size);
    // TODO: save pointers returned by libc malloc to use
    // libc_free on them later.
    extern void *__libc_realloc(void *, size_t);
    void *newptr = __libc_realloc(ptr, size);
    log_debug("return=%p", newptr);
    return newptr;
}

void *libc_calloc(size_t nitems, size_t size)
{
    log_debug("nitems=%lu size=%lu", nitems, size);
    // TODO: save pointers returned by libc malloc to use
    // libc_free on them later.
    extern void *__libc_calloc(size_t, size_t);
    void *newptr = __libc_calloc(nitems, size);
    log_debug("return=%p", newptr);
    return newptr;
}

void *libc_memalign(size_t alignment, size_t size)
{
    log_debug("alignment=%lu size=%lu", alignment, size);
    extern void *__libc_memalign(size_t, size_t);
    void *ptr = __libc_memalign(alignment, size);
    log_debug("return=%p", ptr);
    return ptr;
}

void libc_free(void *ptr)
{
    log_debug("[%s] ptr=%p", __func__, ptr);
    extern void __libc_free(void *);
    __libc_free(ptr);
}

/**
 *  Interface functions
 */

void *malloc(size_t size)
{
    void *p;
    log_debug("[%s] size=%lu from-rlib=%d", __func__, size, IN_RUNTIME());

    /* rmlib status */
    if (!init(false)) {
        log_debug("%s not initialized, using libc", __func__);
        return libc_malloc(size);
    }
    
    if (IN_RUNTIME()) {
        log_debug("%s from runtime, using libc", __func__);
        return libc_malloc(size);
    }

    /* application malloc */
    __from_internal_jemalloc = true;
    log_debug("using je_malloc");
    p = rmlib_je_malloc(size);
    __from_internal_jemalloc = false;
    log_debug("[%s] return=%p", __func__, p);
    return p;
}

void free(void *ptr)
{
    int initd;
    log_debug("[%s] ptr=%p from-rlib=%d from-jemalloc=%d", __func__,
        ptr, IN_RUNTIME(), __from_internal_jemalloc);
    if (ptr == NULL)
        return;

    /* rmlib status */
    initd = atomic_read(&rmlib_state);
    BUG_ON(initd == NOT_STARTED);
    if (initd == INIT_FAILED) {
        log_debug("%s not initialized, using libc", __func__);
        return libc_free(ptr);
    }
    
    if (IN_RUNTIME()) {
        log_debug("%s from runtime, using libc", __func__);
        return libc_free(ptr);
    }

    /** FIXME: there may have been some non-runtime libc mallocs that occurred
     * between INIT_STARTED and INITIALIZED that we would be passing to 
     * jemalloc. We should keep track of these and use libc_free on them. */

    /* application free */
    __from_internal_jemalloc = true;
    rmlib_je_free(ptr);
    __from_internal_jemalloc = false;
    log_debug("[%s] return", __func__);
}

void *realloc(void *ptr, size_t size)
{
    void *p;
    log_debug("[%s] ptr=%p, size=%lu, from-rlib=%d from-jemalloc=%d",
        __func__, ptr, size, IN_RUNTIME(), __from_internal_jemalloc);

    if (ptr == NULL) 
        return malloc(size);

    /* rmlib status */
    if (!init(true)) {
        log_debug("%s not initialized, using libc", __func__);
        return libc_realloc(ptr, size);
    }
    
    if (IN_RUNTIME()) {
        log_debug("%s from runtime, using libc", __func__);
        return libc_realloc(ptr, size);
    }

    /* application realloc */
    __from_internal_jemalloc = true;
    p = rmlib_je_realloc(ptr, size);
    __from_internal_jemalloc = false;
    log_debug("[%s] return=%p", __func__, p);
    return p;
}

void *calloc(size_t nitems, size_t size)
{
    void *p;
    log_debug("[%s] number=%lu, size=%lu, from-rlib=%d", 
        __func__, nitems, size, IN_RUNTIME());

    /* rmlib status */
    if (!init(false)) {
        log_debug("%s not initialized, using libc", __func__);
        return libc_calloc(nitems, size);
    }
    
    if (IN_RUNTIME()) {
        log_debug("%s from runtime, using libc", __func__);
        return libc_calloc(nitems, size);
    }

    /* application calloc */
    __from_internal_jemalloc = true;
    p = rmlib_je_calloc(nitems, size);
    __from_internal_jemalloc = false;
    log_debug("return=%p", p);
    return p;
}

void *internal_aligned_alloc(size_t alignment, size_t size)
{
    void *p;
    log_debug("[%s] alignment=%lu, size=%lu, from-rlib=%d", 
        __func__, alignment, size, IN_RUNTIME());

    /* rmlib status */
    if (!init(false)) {
        log_debug("%s not initialized, using libc", __func__);
        return libc_memalign(alignment, size);
    }
    
    if (IN_RUNTIME()) {
        log_debug("%s from runtime, using libc", __func__);
        return libc_memalign(alignment, size);
    }

    /* application aligned alloc */
    __from_internal_jemalloc = true;
    p = rmlib_je_aligned_alloc(alignment, size);
    __from_internal_jemalloc = false;
    log_debug("return=%p", p);
    return p;
}

int posix_memalign(void **ptr, size_t alignment, size_t size)
{
    log_debug("[%s] ptr=%p, alignment=%lu, size=%lu, from-rlib=%d", 
         __func__, ptr, alignment, size, IN_RUNTIME());
    /* TODO: need to check alignment, check return values */
    *ptr = internal_aligned_alloc(alignment, size);
    log_debug("[%s] ptr=%p allocated=%p", __func__, ptr, *ptr);
    return 0;
}

void *memalign(size_t alignment, size_t size)
{
    log_debug("[%s] alignment=%lu, size=%lu, from-rlib=%d", 
        __func__, alignment, size, IN_RUNTIME());
    return internal_aligned_alloc(alignment, size);
}

void *aligned_alloc(size_t alignment, size_t size)
{
    log_debug("[%s] alignment=%lu, size=%lu, from-rlib=%d", 
        __func__, alignment, size, IN_RUNTIME());
    return internal_aligned_alloc(alignment, size);
}

/**
 * Memory management functions (sys/mman.h).
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    void *p;
    log_debug("[%s] addr=%p,length=%lu,prot=%d,flags=%d,fd=%d,offset=%ld,from-"
    "rlib=%d", __func__, addr, length, prot, flags, fd, offset, IN_RUNTIME());

    /* rmlib status */
    if (!init(false)) {
        /* we expect to be init'd by the time mmap is called (no libc mmap). It 
         * may very well be called before, but don't know how to handle yet */
        BUG_ON(!real_mmap);
        log_debug("%s not initialized, using real mmap", __func__);
        p = real_mmap(addr, length, prot, flags, fd, offset);
        log_debug("real mmap; return=%p", p);
        return p;
    }

    assert((fd == -1) || !(flags & MAP_ANONYMOUS));

    if (IN_RUNTIME()) {
        log_debug("%s from runtime, using real mmap", __func__);
        p = real_mmap(addr, length, prot, flags, fd, offset);
        log_debug("real mmap; return=%p", p);
    }
    
    /* We interpose all the calls and send to je_malloc but je_malloc itself 
     * calls mmap/munmap for backend pages so we need to forward these to 
     * remote memory */
    if (__from_internal_jemalloc) {
        log_debug("internal jemalloc mmap, fwd to RLib: addr=%p,length=%lu,"
            "prot=%d,flags=%d,fd=%d,offset=%ld,from-rlib=%d",
            addr, length, prot, flags, fd, offset, IN_RUNTIME());
        p = rmlib_rmmap(addr, length, prot, flags, fd, offset);
        log_debug("return=%p", p);
        return p;
    }

    /* directly from the app */
    log_debug("app mmap, fwd to RLib: addr=%p,length=%lu,prot=%d,flags=%d,"
        "fd=%d,offset=%ld,from-rlib=%d",
        addr, length, prot, flags, fd, offset, IN_RUNTIME());
    p = rmlib_rmmap(addr, length, prot, flags, fd, offset);
    log_debug("return=%p", p);
    return p;
}

int munmap(void *ptr, size_t length)
{
    int r, initd;
    log_debug("[%s] ptr=%p, length=%lu, from-rlib=%d", __func__, ptr, 
        length, IN_RUNTIME());

    if (!ptr) 
        return 0;

    /* rmlib status */
    initd = atomic_read(&rmlib_state);
    BUG_ON(initd == NOT_STARTED);
    if (initd == INIT_FAILED) {
        r = real_munmap(ptr, length);
        log_debug("child process; return=%d", r);
        return r;
    }

    if (IN_RUNTIME()) {
        log_debug("%s from runtime, using real munmap", __func__);
        r = real_munmap(ptr, length);
        log_debug("real mmap; return=%d", r);
    }

    /* We interpose all the calls and send to je_malloc but je_malloc itself 
     * calls mmap/munmap for backend pages so we need to forward these to 
     * remote memory */
    if (__from_internal_jemalloc) {
        log_debug("internal jemalloc munmap, fwd to RLib: ptr=%p,length=%lu,"
            "from-rlib=%d", ptr, length, IN_RUNTIME());
        r = rmlib_rmunmap(ptr, length);
        log_debug("return=%d", r);
        return r;
    }

    /* directly from the app */
    log_debug("app munmap, fwd to RLib: ptr=%p,length=%lu,from-rlib=%d", 
        ptr, length, IN_RUNTIME());
    r = rmlib_rmunmap(ptr, length);
    log_debug("return=%d", r);
    return r;
}

int madvise(void *addr, size_t length, int advice)
{
    int r;
    bool ret;

    log_debug("[%s] addr=%p, size=%lu, advice=%d, from-rlib=%d from-je=%d", 
        __func__, addr,length, advice, IN_RUNTIME(), __from_internal_jemalloc);
    if (advice == MADV_DONTNEED)    log_debug("MADV_DONTNEED flag");
    if (advice == MADV_HUGEPAGE)    log_debug("MADV_HUGEPAGE flag");
    if (advice == MADV_FREE)        log_debug("MADV_FREE flag");
    
    /* rmlib status */
    ret = init(false);
    BUG_ON(!real_madvise);

    if (ret && !IN_RUNTIME() && within_memory_region(addr)) {
        r = rmadvise(addr, length, advice);
    } else {
        r = real_madvise(addr, length, advice);
    }

    log_debug("return=%d", r);
    return r;
}

#if 0
/* others? */
void *mremap(void *old_addr, size_t old_size, size_t new_size, int flags,
                         ... /* void *new_address */) {
    log_debug("addr=%p,old_size=%lu,new_size=%lu,flags=%d,from-rlib=%d",
       old_addr, old_size, new_size, flags, IN_RUNTIME());
    return 0;
}
#endif

static __attribute__((constructor)) void __init__(void)
{
    log_debug("Alloclib Constructor!");
}

static __attribute__((destructor)) void finish(void)
{
    rmem_common_destroy();
    shmctl(shm_id, IPC_RMID, NULL);
    log_debug("Alloclib Destructor!");
}
