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
__thread struct page_list tmp_lru_lists[EVICTION_MAX_LRU_GENS];
__thread struct iovec mprotect_iov[EVICTION_MAX_BATCH_SIZE];
__thread struct region_t* mprotect_mr[EVICTION_MAX_BATCH_SIZE];
int madv_pidfd = -1;

/* lru state */
page_list_t lru_lists[EVICTION_MAX_LRU_GENS];
int nr_lru_gen = 1;
int lru_gen_mask = 0;
unsigned long epoch_start_tsc;
unsigned long epoch_tsc_shift;

/**
 * All these are write-protected by the lock of the current LRU generation 
 * the pages are being evicted out of i.e., lru_list[lru_gen_now].lock
 * Place variables in a different cache line to avoid false sharing with 
 * constants.
 */
unsigned long epoch_now __aligned(CACHE_LINE_SIZE) = 0;
unsigned long epoch_min = 0;
int lru_gen_now = 0;

/* get process memory from OS */
unsigned long long get_process_mem()
{
    FILE *file = fopen("/proc/self/status", "r");
    if (!file)
        return 0;

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

/* checks if OS memory stats match our local memory accounting */
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
 * sends out the list of page nodes */
static inline int find_candidate_pages(struct list_head* evict_list,
    int batch_size)
{
    int ntmp, npages, npopped;
    int start_gen, gen_id, pg_gen_id;;
    pgflags_t flags, oldflags;
    struct rmpage_node *page, *next;
    struct page_list *lru_list;
    struct list_head locked;
    unsigned long epoch_tmp, slope, span;
    unsigned long pgepoch, pgepoch_oldest;
    bool out_of_gens = false;
    DEFINE_BITMAP(tmplists_map, nr_lru_gen);

    /* quickly pop the first few pages off current lru list */
    gen_id = start_gen = -1;
    npages = npopped = 0;
    bitmap_init(&tmplists_map, nr_lru_gen, 0);
    pgepoch_oldest = UINT64_MAX;
    do {
        /* get current lru gen */
        assert(gen_id != lru_gen_now);
        gen_id = lru_gen_now;
        assert(gen_id >= 0 && gen_id < nr_lru_gen);

        /* circled back to the started list */
        if (start_gen == gen_id) {
            out_of_gens = true;
            break;
        }
        
        if (start_gen < 0)
            start_gen = gen_id;
        
        /* calculate new epoch (outside the lock) */
        epoch_tmp = (rdtsc() - epoch_start_tsc) >> epoch_tsc_shift;

        /* lock current gen (make sure things move fast until we unlock) */
        lru_list = &lru_lists[gen_id];
        spin_lock(&lru_list->lock);

        /* update epoch */
        if (epoch_tmp > epoch_now)
            epoch_now = epoch_tmp;
        assert(epoch_now >= epoch_min);
        span = epoch_now - epoch_min;

        /* pop pages off the list */
        do {
            page = list_pop(&lru_list->pages, rmpage_node_t, link);
            if (page == NULL)
                break;

            /* removed a page */
            assert(lru_list->npages > 0);
            lru_list->npages--;
            npopped++;

            /* check and sort pages */
            assert(lru_gen_mask);
            assert(epoch_now > epoch_min);

            /* get page's epoch; this may get updated concurrently so 
             * just read it once */
            pgepoch = ACCESS_ONCE(page->epoch);
            assert(pgepoch == 0 || pgepoch <= epoch_now);

            /* reset the page's access epoch. we're either gonna evict it or 
             * bump it to higher list, either of which require resetting it */
            page->epoch = 0;

            pg_gen_id = 0;
            if (pgepoch && span) {
                /* page epoch was set by a hint, indicating a more recent 
                 * access after the page fault */
                slope = (epoch_now - pgepoch) * nr_lru_gen / span;
                pg_gen_id = slope & lru_gen_mask;
            }

            if (pg_gen_id == 0) {
                /* page never accessed or is old enough for eviction */
                list_add_tail(evict_list, &page->link);
                npages++;

                /* keep track of least epoch id that was set on an 
                 * evicting page */
                if (!pgepoch && pgepoch < pgepoch_oldest)
                    pgepoch_oldest = pgepoch;
            }
            else {
                /* page was accessed more recently, we need to bump 
                 * these up to later gens */
                assert(pg_gen_id > 0 && pg_gen_id < nr_lru_gen);
                assert(bitmap_test(&tmplists_map, pg_gen_id)
                    || (lru_lists[pg_gen_id].npages == 0
                        && list_empty(&lru_lists[pg_gen_id].pages)));

                list_add_tail(&tmp_lru_lists[pg_gen_id].pages, &page->link);
                tmp_lru_lists[pg_gen_id].npages++;
                bitmap_set(&tmplists_map, pg_gen_id);
            }

            /* enough searching for candidates so that we don't keep pulling 
             * too many pages out of the lists before we put them all back */
            if (npopped >= EVICTION_MAX_BUMPS_PER_OP)
                break;

        } while(npages < batch_size);

        /* got enough pages */
        if (npages == batch_size)
            goto found_enough;
        
        /* enough searching for candidates */
        if (npopped == EVICTION_MAX_BUMPS_PER_OP)
            goto found_enough;

        /* not enough candidates in this list, move to next list */
        assert(list_empty(&lru_list->pages) && !lru_list->npages);
        lru_gen_now = (gen_id + 1) % nr_lru_gen;
        spin_unlock(&lru_list->lock);
        continue;

found_enough:
        /* update epoch_min to the oldest evicted page */
        if (pgepoch_oldest != UINT64_MAX) {
            assert(pgepoch_oldest >= epoch_min && pgepoch_oldest <= epoch_now);
            epoch_min = pgepoch_oldest;
        }
        spin_unlock(&lru_list->lock);
        break;

    } while(1);

    /* unlock the last list we looked at */
    if (!out_of_gens)
        spin_unlock(&lru_list->lock);

    /* if we didn't get enough for a batch, introspect */
    if (npages < batch_size)
    {
        /* if the reason is that we were completely out of pages, 
         * get the remaining from the bump lists if they have any */
        if (unlikely(out_of_gens)) {
            /* start from the bottom */
            assert(nr_lru_gen > 0 && list_empty(tmp_lru_lists[0].pages));
            for (gen_id = 1; gen_id < nr_lru_gen; gen_id++) {
                if (tmp_lru_lists[gen_id].npages == 0)
                    continue;

                if (tmp_lru_lists[gen_id].npages <= (batch_size - npages)) {
                    /* move all pages in one go */
                    list_append_list(evict_list, &tmp_lru_lists[gen_id].pages);
                    assert(list_empty(&tmp_lru_lists[gen_id].pages));
                    npages += tmp_lru_lists[gen_id].npages;
                    tmp_lru_lists[gen_id].npages = 0;
                    bitmap_clear(&tmplists_map, gen_id);
                }
                else {
                    /* move as many as needed one-by-one */
                    while(npages < batch_size) {
                        page = list_pop(&tmp_lru_lists[gen_id].pages, 
                            rmpage_node_t, link);
                        list_add_tail(evict_list, &page->link);
                        npages++;
                        assert(tmp_lru_lists[gen_id].npages > 0);
                        tmp_lru_lists[gen_id].npages--;
                    }
                }
            }

            /* if we couldn't find anything anywhere */
            BUG_ON(npages == 0);
        }
        
        /* if the reason is that we had to give up the hunt after a while as 
         * most pages were non-evictible, then we either need to increase the 
         * epoch interval or decrease the number of generations to make more 
         * page evictible; for now, we won't do take any self-correcting 
         * measures here and let this overhead reflect in the EVICT_SUBOPTIMAL 
         * and evict effective batch size (EVICT_PAGES/EVICTS) metrics. 
         * We'll leave it to the developer to judge if this eviction overhead 
         * is worthwhile and tune the afforementioned parameters. */
        else if (npopped == EVICTION_MAX_BUMPS_PER_OP)
            RSTAT(EVICT_SUBOPTIMAL)++;

        /* expecting no other reason */
        else
            BUG();
    }

    /* add bumped pages back to the higher lists. note that lru_gen_now may 
     * be updated by other evictors in this process but adding pages in the 
     * wrong lists doesn't affect correctness, just performance. we will get 
     * to these pages sooner or later. */
    bitmap_for_each_set(&tmplists_map, nr_lru_gen, gen_id) {
        assert(tmp_lru_lists[gen_id].npages > 0);
        assert(gen_id != 0);
        lru_list = &lru_lists[(lru_gen_now + gen_id) & lru_gen_mask];
        spin_lock(&lru_list->lock);
        list_append_list(&lru_list->pages, &tmp_lru_lists[gen_id].pages);
        lru_list->npages += tmp_lru_lists[gen_id].npages;
        tmp_lru_lists[gen_id].npages = 0;
        spin_unlock(&lru_list->lock);
    }

#if defined(DEBUG) || defined(SAFEMODE)
    /* check that we didn't leak any pages */
    bitmap_for_each(&tmplists_map, nr_lru_gen, gen_id)
        assert(list_empty(tmp_lru_lists[gen_id].pages) && 
            tmp_lru_lists[gen_id].npages == 0);
#endif

    /* couldn't find anything evictible this time around */
    if (npages == 0)
        return 0;

    /* found some candidates, lock them for eviction */
    list_head_init(&locked);
    ntmp = 0;
    list_for_each_safe(evict_list, page, next, link)
    {
        flags = set_page_flags(page->mr, page->addr, PFLAG_WORK_ONGOING, 
            &oldflags);
        if (unlikely(!!(oldflags & PFLAG_WORK_ONGOING))) {
            /* page was locked by someone (presumbly for write-protect fault 
            * handling), add it the locked list so we can put it back */
            list_del_from(evict_list, &page->link);
            list_add_tail(&locked, &page->link);
            ntmp++;
            npages--;
        }
        else {
            /* page is evictable (i.e., present and not hot) */
            assert(!!(flags & PFLAG_PRESENT));
            assert(!!(flags & PFLAG_REGISTERED));
            assert(!(flags & PFLAG_EVICT_ONGOING));
            assert(is_in_memory_region_unsafe(page->mr, page->addr));
        }
    }

    /* put back the locked pages into lru lists; adding them to the farthest 
     * lru list is fine as these pages are currently being worked on and 
     * they deserve to be on the latest list anyway */
    if (!list_empty(&locked)) {
        gen_id = (lru_gen_now + nr_lru_gen - 1) & lru_gen_mask;
        lru_list = &lru_lists[gen_id];
        spin_lock(&lru_list->lock);
        list_append_list(&lru_list->pages, &locked);
        lru_list->npages += ntmp;
        spin_unlock(&lru_list->lock);
    }

    return npages;
}

/* remove pages from virtual memory using madvise */
static inline int remove_pages(struct list_head* pglist, int npages) 
{
    int r, i;
    ssize_t ret;
    struct rmpage_node *page;
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
    /* process_madvise supported. This always flushes the TLB so we may only 
     * want to use it on very big batches. Although, UFFD_WRITEPROTECT currently
     * flushes TLB on every op so if we write-protected pages before getting 
     * here, we don't have to think twice about flushing again */
    vectored_madv = wrprotected || npages >= EVICTION_TLB_FLUSH_MIN;
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
    int i, r, niov;
    int nretries;
    struct rmpage_node *page;
    bool vectored_mprotect = false;
    size_t wpbytes;

#ifdef VECTORED_MPROTECT
    /* process_mprotect supported. mprotect operations flush the TLB always 
     * so batching multiple mprotects is always a strict win */
    vectored_mprotect = (npages > 1);
#endif

    log_debug("flushing %d pages", npages);

    /* write back pages that are dirty */
    i = 0;
    niov = 0;
    bitmap_init(write_map, npages, false);
    list_for_each(pglist, page, link)
    {
        /* check dirty */
        if (!needs_write_back(pflags[i])) {
            i++;
            continue;
        }

        /* prepare the io vector */
        mprotect_mr[niov] = page->mr;
        mprotect_iov[niov].iov_base = (void*) page->addr;
        mprotect_iov[niov].iov_len = CHUNK_SIZE;
        niov++;
        assert(niov <= EVICTION_MAX_BATCH_SIZE);

        bitmap_set(write_map, i);
        i++;
    }
    assert(i == npages);

    /* protect and write-back dirty pages */
    if (niov > 0)
    {
        if (vectored_mprotect) {
            /* if batch mprotect is available, use it to mprotect all at once */
            nretries = 0;
            r = uffd_wp_add_vec(userfault_fd, mprotect_iov, niov, 
                false, true, &nretries, &wpbytes);
            assertz(r);
            assert(wpbytes == niov * CHUNK_SIZE);
            RSTAT(EVICT_WP_RETRIES) += nretries;
        }
       
        /* for each page */
        for (i = 0; i < niov; i++) {
            if (!vectored_mprotect) {
                /* batch mprotect is not available, mprotect individually */
                nretries = 0;
                r = uffd_wp_add(userfault_fd, 
                    (unsigned long) mprotect_iov[i].iov_base, 
                    mprotect_iov[i].iov_len, false, true, &nretries);
                assertz(r);
                RSTAT(EVICT_WP_RETRIES) += nretries;
            }

            /* write-back. TODO: there is an optimization here we can do 
             * using backend scatter-gather op to write all at once */
            write_region_to_backend(chan_id, mprotect_mr[i], 
                (unsigned long) mprotect_iov[i].iov_base, 
                mprotect_iov[i].iov_len, cbs);
            RSTAT(EVICT_WBACK)++;
        }
    }

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
    struct list_head evict_list;
    bool discarded;
    struct region_t* mr;
    unsigned long addr;

    /* get eviction candidates */
    npages = 0;
    list_head_init(&evict_list);
    assert(batch_size > 0 && batch_size <= EVICTION_MAX_BATCH_SIZE);
    do {
        npages = find_candidate_pages(&evict_list, batch_size);
        if (npages)
            break;
        RSTAT(EVICT_NONE)++;
        /* TODO: error out if we are stuck here */
    } while(!npages);

    /* found page(s) */
    assert(list_empty(&evict_list) || (npages > 0));

    /* flag them as evicting */
    assert(npages <= EVICTION_MAX_BATCH_SIZE);
    i = 0;
    list_for_each(&evict_list, page, link) {
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
    flushed = flush_pages(chan_id, &evict_list, npages, flags, write_map, cbs);
    assert(npages == flushed);

    /* memory accounting */
    if (flushed > 0) {
        size = flushed * CHUNK_SIZE;
        pressure = atomic_fetch_sub_explicit(&memory_used, size, memory_order_acquire);
        log_debug("Freed %d page(s), pressure=%lld", npages, pressure - size);

        /* work for each removed page */
        i = 0;
        list_for_each(&evict_list, page, link)
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

/**
 * eviction_init - initializes eviction state
 */
int eviction_init(void)
{
    int i;
    unsigned long interval_tsc;

    /* init LRU mask and page lists */
    BUG_ON(nr_lru_gen & (nr_lru_gen - 1));  /* power of 2 */
    lru_gen_mask = nr_lru_gen - 1;
    for(i = 0; i < nr_lru_gen; i++) {
        list_head_init(&lru_lists[i].pages);
        lru_lists[i].npages = 0;
        spin_lock_init(&lru_lists[i].lock);
        tmp_lru_lists[i].npages = 0;
        spin_lock_init(&tmp_lru_lists[i].lock);
    }
    log_info("inited %d LRU lists. lru mask: %x", nr_lru_gen, lru_gen_mask);

    /* init epoch */
    epoch_start_tsc = rdtsc();
    interval_tsc = EVICTION_EPOCH_LEN_MUS * cycles_per_us;
    epoch_tsc_shift = 1;
    while(interval_tsc > 0) {
        epoch_tsc_shift++;
        interval_tsc >>= 1;
    }
    log_info("eviction epoch length: %d mus, closest bit shift: %d", 
        EVICTION_EPOCH_LEN_MUS, epoch_tsc_shift);

    /* pid fd required for process madvise */
#ifdef VECTORED_MADVISE
    log_info("eviction using vectored madvise");
    madv_pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    assert(madv_pidfd >= 0);
#endif
    
    return 0;
}
