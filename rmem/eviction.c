/*
 * eviction.h - eviction helpers
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdatomic.h>
#include <sys/mman.h>

#include "base/cpu.h"
#include "base/log.h"
#include "rmem/backend.h"
#include "rmem/common.h"
#include "rmem/config.h"
#include "rmem/fault.h"
#include "rmem/handler.h"
#include "rmem/page.h"
#include "rmem/region.h"
#include "rmem/uffd.h"

/* eviction state */
__thread uint64_t last_seen_faults = 0;
__thread struct region_t *eviction_region_safe = NULL;
__thread uint64_t last_evict_try_count = 0;
__thread struct iovec madv_iov[EVICTION_MAX_BATCH_SIZE];
int madv_pidfd = -1;

/* lru lists */
page_list_t hot_pages;
page_list_t warm_pages;
page_list_t cold_pages;

/**
 * eviction_init - initializes eviction state
 */
int eviction_init(void)
{
    /* pid fd required for process madvise */
#ifdef VECTORED_MADVISE
    log_info("eviction using vectored madvise");
    madv_pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    assert(madv_pidfd >= 0);
#endif
    
    return 0;
}

/**
 * Page LRU lists support
 */
void lru_lists_init(void)
{
    list_head_init(&hot_pages.pages);
    hot_pages.max_pages = (local_memory * HOT_LRU_PERCENT / CHUNK_SIZE);
    hot_pages.npages = 0;
    spin_lock_init(&hot_pages.lock);

    list_head_init(&warm_pages.pages);
    warm_pages.max_pages = (local_memory * WARM_LRU_PERCENT / CHUNK_SIZE);
    warm_pages.npages = 0;
    spin_lock_init(&warm_pages.lock);

    list_head_init(&cold_pages.pages);
    cold_pages.max_pages = (size_t)-1;
    cold_pages.npages = 0;
    spin_lock_init(&cold_pages.lock);
}

/* get process memory from OS */
unsigned long long get_process_mem()
{
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) {
        return 0;
    }
    const int line_size = 512;
    char line[line_size];
    unsigned long long vmrss = 0;

    while (fgets(line, line_size, file) != NULL) {
        int i = strlen(line);
        assert(i > 6);
        if (strncmp(line, "VmRSS:", 6) == 0) {
            // This assumes that a digit will be found and the line ends in " Kb".
            const char *p = line;
            while (*p < '0' || *p > '9') p++;
            line[i - 3] = '\0';
            vmrss = atoi(p);
            break;
        }
    }
    fclose(file);

    // Convert to bytes
    vmrss *= 1024;
    return vmrss;
}

void verify_eviction()
{
    double over_allocated;

    /* Check after 1 million page faults? */
    if (RSTAT(FAULTS) - last_seen_faults > OS_MEM_PROBE_INTERVAL) {
        last_seen_faults = RSTAT(FAULTS);

        // Read the current memory from OS periodically
        uint64_t current_mem = get_process_mem();
        if (current_mem > 0) {
            over_allocated = (current_mem - local_memory) * 100 / local_memory;
            if (over_allocated > 1) {
                /* just warn for now */
                log_warn("OS memory probing found usage >1%% over limit");
            }
        }
    }
}

/* finds eviction candidates - returns the number of candidates found and 
 * passes out the list of page nodes */
static inline int find_candidate_pages(struct list_head* pglist,
    int batch_size)
{
    int ntmp, npages;
    pgflags_t flags, oldflags;
    struct rmpage_node *page, *next;
    struct list_head tmplist;

    /* quickly pop the first few pages off the cold list */
    npages = 0;
    assert(pglist && list_empty(pglist));
    spin_lock(&cold_pages.lock);
    do {
        page = list_pop(&cold_pages.pages, rmpage_node_t, link);
        if (page == NULL)
            break;
        assert(cold_pages.npages > 0);
        cold_pages.npages--;
        list_add_tail(pglist, &page->link);
        npages++;
    } while (npages < batch_size);
    spin_unlock(&cold_pages.lock);

    /* we cannot be asking for eviction when the cold list is empty */
    assert(npages > 0);

    /* see if they're available */
    list_head_init(&tmplist);
    ntmp = 0;
    list_for_each_safe(pglist, page, next, link)
    {
        flags = set_page_flags(page->mr, page->addr, PFLAG_WORK_ONGOING, 
            &oldflags);
        if (unlikely(!!(oldflags & PFLAG_WORK_ONGOING))) {
            /* page was locked by someone (presumbly for write-protect fault 
            * handling), add it tmp list so we can put it back */
            list_del_from(pglist, &page->link);
            list_add_tail(&tmplist, &page->link);
            ntmp++;
            npages--;
        }
        else {
            /* page is evictable (i.e., present and not hot) */
            assert(!!(flags & PFLAG_PRESENT));
            assert(!!(flags & PFLAG_REGISTERED));
            assert(!(flags & PFLAG_HOT_MARKER2));
            assert(is_in_memory_region_unsafe(page->mr, page->addr));
        }
    }

    /* put back the pages that we couldn't lock. adding to the tail should 
     * be ok as lock means they're being worked on so they're not immediately
     * evictible by anyone else either */
    if (!list_empty(&tmplist)) {
        spin_lock(&cold_pages.lock);
        list_append_list(&cold_pages.pages, &tmplist);
        cold_pages.npages += ntmp;
        spin_unlock(&cold_pages.lock);
    }

    return npages;
}

/* remove pages from virtual memory using madvise */
static inline int remove_pages(struct list_head* pglist, int npages) 
{
    int r, i;
    ssize_t ret;
    struct rmpage_node *page;
    log_debug("removing %d pages", npages);
    bool vectored_madv = false;

#ifdef REGISTER_MADVISE_REMOVE
    /* we don't support receiving madvise notifications for page 
     * deletions (which will lead to deadlocks as the notifications 
     * will need to be handled before we move on from here - something we 
     * cannot do if we expect to support a single handler core. I don't 
     * see a reason why we should use them if pages are being locked, as we do,
     * and only release them when the job is done */
    BUILD_ASSERT(0);
#endif
#ifdef VECTORED_MADVISE
    vectored_madv = true;
#endif

    i = 0;
    list_for_each(pglist, page, link)
    {
        if (vectored_madv) {
            /* prepare the io vector */
            madv_iov[i].iov_base = (void*)page->addr;
            madv_iov[i].iov_len = CHUNK_SIZE;
        }
        else {
            /* or issue madvise once per page */
            r = madvise((void*)page->addr, CHUNK_SIZE, MADV_DONTNEED);
            if (r != 0) {
                log_err("madvise for chunk %d failed: %s", i, strerror(errno));
                BUG();
            }
        }
        i++;
    }
    assert(i == npages);

    if (vectored_madv) {
        /* issue one madvise for all pages */
        assert(madv_pidfd >= 0);
        ret = syscall(440, madv_pidfd, madv_iov, npages, MADV_DONTNEED, 0);
        if(ret != npages * CHUNK_SIZE) {
            log_err("process_madvise returned %ld expected %d, errno %d", 
                ret, npages * CHUNK_SIZE, errno);
            BUG();
        }
    }

    RSTAT(EVICT_MADV) += npages;
    return 0;
}

/* checks if a page needs write-back */
static inline bool needs_write_back(pgflags_t flags) 
{
    /* page must be present at this point */
    assert(!!(flags & PFLAG_PRESENT));
#ifdef WP_ON_READ
    /* DIRTY bit is only valid when WP is enabled */
    return !!(flags & PFLAG_DIRTY);
#endif
    /* if the page was unmapped, no need to write-back */
    if (!(flags & PFLAG_REGISTERED))
        return false;
    return true;
}

/* write-back a region to the backend */
static unsigned int write_region_to_backend(int chan_id, struct region_t *mr, 
    unsigned long addr, size_t size, struct bkend_completion_cbs* cbs) 
{
    int r;
    int ncompletions, nwrites_done;
    uint64_t start_tsc, duration;
    log_debug("writing back contiguous region at [%lx, %lu)", addr, size);

    /* post the write-back */
    start_tsc = 0;
    ncompletions = 0;
    nwrites_done = 0;
    do {
        r = rmbackend->post_write(chan_id, mr, addr, size);
        if (r == EAGAIN) {
            /* start the timer the first time we are here */
            if (!start_tsc)
                start_tsc = rdtsc();

            /* write queue is full, nothing to do but repeat and keep 
             * checking for completions to free request slots; raising error
             * if we handled some write completions but still cannot post */
            assert (nwrites_done >= 1);
            ncompletions += rmbackend->check_for_completions(chan_id, cbs, 
                RMEM_MAX_COMP_PER_OP, NULL, &nwrites_done);
        }
    } while(r == EAGAIN);
    assertz(r);

    /* save wait time if any */
    if (start_tsc) {
        duration = rdtscp(NULL) - start_tsc;
        RSTAT(BACKEND_WAIT_CYCLES) += duration;
    }

    return 0;
}

/* flush pages (with write-back if necessary). 
 * Returns whether any of the pages were written to backend and should be 
 * monitored for completions */
static bool flush_pages(int chan_id, struct list_head* pglist, int npages,
    pgflags_t* pflags, bitmap_ptr write_map, struct bkend_completion_cbs* cbs)
{
    int i, r;
    pgflags_t flags;
    int nretries;
    struct rmpage_node *page;

    log_debug("flushing %d pages", npages);

    /* write back pages that are dirty */
    i = 0;
    bitmap_init(write_map, npages, false);
    list_for_each(pglist, page, link)
    {
        flags = pflags[i];
        if (!needs_write_back(flags)) {
            i++;
            continue;
        }
        
        /* protect the page first (we don't have a vectored op for wrprotect
         * but hopefully we will soon) */
        nretries = 0;
        r = uffd_wp_add(userfault_fd, page->addr, CHUNK_SIZE, false, true, 
                &nretries);
        assertz(r);
        RSTAT(EVICT_WP_RETRIES) += nretries;
        RSTAT(EVICT_WBACK)++;

        /* write to backend */
        write_region_to_backend(chan_id, page->mr, page->addr, CHUNK_SIZE, cbs);
        bitmap_set(write_map, i);
        i++;
    }
    assert(i == npages);

    /* remove pages from UFFD */
    r = remove_pages(pglist, npages);
    assertz(r);
    return npages;
}

/**
 * Eviction done for a page
 */
static inline void evict_page_done(struct region_t* mr, unsigned long pgaddr, 
    bool discarded)
{
    pgflags_t clrbits, oldflags;

    /* assert locked */
    assert(!!(get_page_flags(mr, pgaddr) & PFLAG_WORK_ONGOING));

    /* bits to clear */
    clrbits = 0;
    clrbits |= PFLAG_EVICT_ONGOING;
    clrbits |= PFLAG_PRESENT;
    clrbits |= PFLAG_DIRTY;
    clrbits |= PFLAG_HOT_MARKER;
    clrbits |= PFLAG_HOT_MARKER2;

    if (discarded) {
        /* for pages that were discarded and not written-back, we can just 
         * clear most bits, including the lock, and let them go */
        log_debug("evict done, unlocking page %lx", pgaddr);
        clear_page_flags(mr, pgaddr, clrbits | PFLAG_WORK_ONGOING, &oldflags);
        assert(!!(oldflags & PFLAG_PRESENT));
        goto evict_done;
    }
    else {
        /* For pages that were written-back, the story is more complicated. 
         * We can set them non-present at this point but cannot release 
         * those that are waiting for writes to complete. Because we don't 
         * want another fault to go on reading from remote memory while the
         * dirtied changes are waiting in the write queue. At the same time,
         * we cannot release after write completion because that might happen
         * before the madvise (due to completion stealing). So we try
         * and determine who went later than the other using the 
         * PFLAG_EVICT_ONGOING flag and clear the lock then */
        clear_page_flags(mr, pgaddr, clrbits, &oldflags);
        if (!!(oldflags & PFLAG_EVICT_ONGOING)) {
            /* first to get here, do not release */
            assert(!!(oldflags & PFLAG_PRESENT));
            log_debug("evict one step done for page %lx", pgaddr);
            return;
        }
        else {
            /* last one to get here, clear the lock as well */
            log_debug("evict done, unlocking page %lx", pgaddr);
            clear_page_flags(mr, pgaddr, PFLAG_WORK_ONGOING, &oldflags);
            goto evict_done;
        }
    }

evict_done:
    assert(!!(oldflags & PFLAG_WORK_ONGOING)); /*sanity check*/
    RSTAT(EVICT_PAGES_DONE)++;
    put_mr(mr);
}


/**
 * Called after backend write has completed
 */
int write_back_completed(struct region_t* mr, unsigned long addr, size_t size)
{
    unsigned long page;
    size_t covered;
    assert(addr % CHUNK_SIZE == 0 && size % CHUNK_SIZE == 0);
    
    covered = 0;
    while(covered < size) {
        page = addr + covered;
        evict_page_done(mr, page, false);
        covered += CHUNK_SIZE;
    }
    return 0;
}

/**
 * Main function for eviction. Returns number of pages evicted.
 */
int do_eviction(int chan_id, struct bkend_completion_cbs* cbs,
    int batch_size)
{
    size_t size;
    pgflags_t oldflags;
    pgidx_t pgidx;
    int npages, i, flushed;
    pgflags_t flags[batch_size];
    DEFINE_BITMAP(write_map, batch_size);
    unsigned long long pressure;
    struct rmpage_node *page;
    struct list_head pglist;
    bool discarded;
    struct region_t* mr;
    unsigned long addr;

    /* get eviction candidates */
    npages = 0;
    list_head_init(&pglist);
    assert(batch_size > 0 && batch_size <= EVICTION_MAX_BATCH_SIZE);
    do {
        npages = find_candidate_pages(&pglist, batch_size);
        if (npages)
            break;
        /* TODO: error out if we are stuck here */
        RSTAT(EVICT_RETRIES)++;
    } while(!npages);

    /* found page(s) */
    assert(list_empty(&pglist) || (npages > 0));

    /* flag them as evicting */
    assert(npages <= EVICTION_MAX_BATCH_SIZE);
    i = 0;
    list_for_each(&pglist, page, link) {
        flags[i] = set_page_flags(page->mr, page->addr, 
            PFLAG_EVICT_ONGOING, &oldflags);
        assert(!(oldflags & PFLAG_EVICT_ONGOING));
        log_debug("evicting page %lx from mr start %lx", 
            page->addr, page->mr->addr);
        i++;
    }
    assert(i == npages);

    RSTAT(EVICTS)++;
    RSTAT(EVICT_PAGES) += npages;

    /* flush pages */
    flushed = flush_pages(chan_id, &pglist, npages, flags, write_map, cbs);
    assert(npages == flushed);

    /* memory accounting */
    if (flushed > 0) {
        size = flushed * CHUNK_SIZE;
        pressure = atomic_fetch_sub_explicit(&memory_used, size, memory_order_acquire);
        log_debug("Freed %d page(s), pressure=%lld", npages, pressure - size);

        /* work for each removed page */
        i = 0;
        list_for_each(&pglist, page, link)
        {
            /* clear the page index and release the page node */
            mr = page->mr;
            addr = page->addr;
            pgidx = clear_page_index(page->mr, page->addr);
            assert(pgidx == rmpage_get_node_id(page));
            rmpage_node_free(page); /* don't use page after this point */
            log_debug("cleared index bits and page node for %lx", page->addr);

            /* eviction done */
            discarded = !bitmap_test(write_map, i);
            evict_page_done(mr, addr, discarded);
            i++;
        }
        assert(i == flushed);
        RSTAT(EVICT_DONE)++;
        log_debug("evict done for %d pages", flushed);
    }

#ifdef SAFEMODE
    /* see if eviction was going as expected*/
    verify_eviction();
#endif
    return flushed;
}
