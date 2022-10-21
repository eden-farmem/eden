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

#include "../defs.h"

/* eviction state */
__thread uint64_t last_seen_faults = 0;
__thread struct region_t *eviction_region_safe = NULL;
__thread uint64_t last_evict_try_count = 0;

/* lru lists */
page_list_t hot_pages;
page_list_t warm_pages;
page_list_t cold_pages;

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

/**
 * Gets a safe reference to one of the memory regions to evict from. Trying to
 * switch regions frequently might be costly as we need to get/put safe 
 * references every time, so we try and rotate less frequently, holding on to 
 * the safe reference till we rotate 
 */
static inline struct region_t* get_evictable_region_safe() {
    if (eviction_region_safe == NULL)
        eviction_region_safe = get_next_evictable_region();
    else if (RSTAT(EVICT_RETRIES) > last_evict_try_count + 
            EVICTION_REGION_SWITCH_THR) {
        put_mr(eviction_region_safe);
        /* NOTE: we're gonna hold this safe reference until we switch again 
            * which may be too long in some cases. Not gonna handle now! */
        eviction_region_safe = get_next_evictable_region();
        last_evict_try_count = RSTAT(EVICT_RETRIES);
    }
    return eviction_region_safe;
}

/* get process memory from OS */
unsigned long long get_process_mem() {
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

void verify_eviction() {
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

/* checks if a page can be evicted */
static inline bool is_evictable(pflags_t flags)
{
    if (!(flags & PFLAG_PRESENT))
        /* not present, can't evict */
        return false;

    if (!(flags & PFLAG_REGISTERED))
        /* present but not registered means they were unmapped. 
            * best candidate! */
        return true;
    
    if (!!(flags & PFLAG_WORK_ONGOING))
        /* work in progress */
        return false;

#ifdef SECOND_CHANCE_EVICTION
    if (!!(flags & PFLAG_HOT_MARKER))
        /* marked hot, give it another chance */
        return false;
#endif

    /* otherwise good */
    return true;
}

/* get eviction candidate in a region */
static inline rmpage_node_t* find_candidate_chunks(struct list_head* more_pages,
    int* nchunks, int max_batch_size) 
{
    int i;
    unsigned long addr;
    pflags_t flags, oldflags, pgidx;
    struct rmpage_node *page, *tmp;

    *nchunks = 0;

    /* get the first page from cold list */
    spin_lock(&cold_pages.lock);
    page = list_pop(&cold_pages.pages, rmpage_node_t, link);
    cold_pages.npages--;
    flags = set_page_flags(page->mr, page->addr, PFLAG_WORK_ONGOING, &oldflags);
    if (unlikely(!!(oldflags & PFLAG_WORK_ONGOING))) {
        /* page was locked by someone, move it to tail and return */
        list_add_tail(&cold_pages.pages, &page->link);
        cold_pages.npages++;
        page = NULL;
    }
    spin_unlock(&cold_pages.lock);

    if (!page)
        return NULL;
    
    /* claimed new page, see if we can batch some later pages */
    assert(is_evictable(flags));
    (*nchunks)++;

    for (i = 0; i < (max_batch_size - 1); i++)
    {
        addr = page->addr + i * CHUNK_SIZE;
        if (!is_in_memory_region_unsafe(page->mr, addr))
            break;

        flags = get_page_flags(page->mr, addr);
        if (!is_evictable(flags))
            break;

        /* TODO: must be in COLD LRU for batching */

        /* take a lock */
        flags = set_page_flags(page->mr, addr, PFLAG_WORK_ONGOING, &oldflags);
        if (!!(oldflags & PFLAG_WORK_ONGOING))
            /* some other thread took it */
            break;

        /* got another page, remove it from LRU */
        pgidx = get_page_index_from_flags(flags);
        tmp = rmpage_get_node_by_id(pgidx);
        
        assert(&cold_pages == tmp->listhead);  /* must be in COLD LRU for now */
        spin_lock(&cold_pages.lock);
        list_del_from(&cold_pages.pages, &tmp->link);
        cold_pages.npages--;
        spin_unlock(&cold_pages.lock);

        /* save the removed nodes (to free later) */
        list_add_tail(more_pages, &tmp->link);
        (*nchunks)++;
    }

    return page;
}

/* remove pages from virtual memory using madvise */
static int remove_pages(struct region_t *mr, unsigned long addr, size_t size) 
{
    int r;
    log_debug("remove memory range: addr=%lx, size=%ld", addr, size);

#ifdef REGISTER_MADVISE_REMOVE
    /* we don't support receiving madvise notifications for page 
     * deletions (which will lead to deadlocks as the notifications 
     * will need to be handled before we move on from here - something we 
     * cannot do if we expect to support a single handler core. I don't 
     * see a reason why we should use them if pages are being locked, as we do,
     * and only release them when the job is done */
    BUILD_ASSERT(0);
#endif

    r = madvise((void *)addr, size, MADV_DONTNEED);
    if (r < 0) {
        log_err("madvise MADV_DONTNEED failed for addr [%lx, %lu)", addr, size);
        BUG();
    }
    return 0;
}

/* checks if a page needs write-back */
bool needs_write_back(pflags_t flags) 
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

/* write-back a region of pages to the backend */
static unsigned int write_pages_to_backend(int chan_id, struct region_t *mr, 
    unsigned long addr, int nchunks, struct bkend_completion_cbs* cbs) 
{
    int r, n_retries;
    int ncompletions, nwrites_done;
    uint64_t start_tsc, duration;
    log_debug("writing back contiguous region at [%lx, %d)", addr, nchunks);

    /* protect the region first */
    n_retries = 0;
    r = uffd_wp_add(userfault_fd, addr, nchunks * CHUNK_SIZE, false, true, &n_retries);
    assertz(r);
    RSTAT(EVICT_WP_RETRIES) += n_retries;
    RSTAT(EVICT_WBACK)++;

    /* post the write-back */
    start_tsc = 0;
    ncompletions = 0;
    nwrites_done = 0;
    do {
        r = rmbackend->post_write(chan_id, mr, addr, nchunks * CHUNK_SIZE);
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

            /* TODO: we may want to count idle cycles here */
            cpu_relax();
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
static bool flush_pages(int chan_id, struct region_t *mr, 
    unsigned long base_addr, int nchunks, pflags_t* pflags, 
    bitmap_ptr write_map, bool remove, struct bkend_completion_cbs* cbs)
{
    int i, r;
    pflags_t flags;
    int dirty_chunks;
    unsigned long addr, new_base_addr;

    assert(is_in_memory_region_unsafe(mr, base_addr));
    assert(is_in_memory_region_unsafe(mr, base_addr + (nchunks - 1) * CHUNK_SIZE));
    log_debug("flushing pages: %p, number %d", (void *)base_addr, nchunks);

    /* write back in sub-chunks that are dirty */
    dirty_chunks = 0;
    bitmap_init(write_map, nchunks, false);
    new_base_addr = base_addr;
    for (i = 0; i < nchunks; i++) {
        addr = base_addr + i * CHUNK_SIZE;
        flags = (pflags != NULL) ? pflags[i] : get_page_flags(mr, addr);
        if (needs_write_back(flags)) {
            dirty_chunks++;
            bitmap_set(write_map, i);
            continue;
        }

        if (dirty_chunks > 0) {
            /* write the last contiguous subset of dirty chunks */
            write_pages_to_backend(chan_id, mr, new_base_addr, dirty_chunks, cbs);

            /* start of a new subset */
            new_base_addr = addr + CHUNK_SIZE;
            dirty_chunks = 0;
        }
    }
    /* last subset */
    if (dirty_chunks > 0)
        write_pages_to_backend(chan_id, mr, new_base_addr, dirty_chunks, cbs);

    /* remove pages from UFFD */
    if (remove) {
        log_debug("removing pages at region at [%lx, %d)", base_addr, nchunks);
        r = remove_pages(mr, base_addr, nchunks * CHUNK_SIZE);
        assertz(r);
        RSTAT(EVICT_MADV) += nchunks;
    }
    return nchunks;
}

/**
 * Called after backend write has completed
 */
int write_back_completed(struct region_t* mr, unsigned long addr, size_t size)
{
    unsigned long page;
    pflags_t oldflags;
    size_t covered;
    assert(addr % CHUNK_SIZE == 0 && size % CHUNK_SIZE == 0);
    
    covered = 0;
    while(covered < size) {
        page = addr + covered;
        clear_page_flags(mr, page, PFLAG_EVICT_ONGOING, &oldflags);
        if (!(oldflags & PFLAG_EVICT_ONGOING)) {
            /* I'm the last one to reach here, unlock the page. See 
             * do_eviction() for a comment on what we're doing here. */
            log_debug("evict done at wrback, unlocking page %lx", addr);
            clear_page_flags(mr, page, PFLAG_WORK_ONGOING, &oldflags);
            assert(!!(oldflags & PFLAG_WORK_ONGOING)); /*sanity check*/
            RSTAT(EVICT_PAGES_DONE)++;
        }
        covered += CHUNK_SIZE;
    }
    return 0;
}

/**
 * Main function for eviction. Returns number of pages evicted.
 */
int do_eviction(int chan_id, struct bkend_completion_cbs* cbs, int max_batch_size) 
{
    unsigned long base_addr, addr, size;
    pflags_t oldflags, pgidx;
    int nchunks, i, flushed;
    pflags_t flags[max_batch_size];
    DEFINE_BITMAP(write_map, max_batch_size);
    unsigned long long pressure;
    struct region_t* mr;
    struct rmpage_node *page, *tmp;
    struct list_head more_pages;

    /* get eviction candidate */
    list_head_init(&more_pages);
    do {
        page = find_candidate_chunks(&more_pages, &nchunks, max_batch_size);
        if (!page) {
            /* TODO: error out if we are stuck here */
            assert(nchunks == 0);
            RSTAT(EVICT_RETRIES)++;
        }
    } while(!page);

    /* found page(s) */
    assert(list_empty(&more_pages) || (nchunks > 1));
    mr = page->mr;
    base_addr = page->addr;

    /* flag them as evicting */
    log_debug("evicting pages at %lx, number: %d\n", base_addr, nchunks);
    assert(nchunks <= EVICTION_MAX_BATCH_SIZE);
    for (i = 0; i < nchunks; i++) {
        addr = base_addr + i * CHUNK_SIZE;
        flags[i] = set_page_flags(mr, addr, PFLAG_EVICT_ONGOING, &oldflags);
        assert(!(oldflags & PFLAG_EVICT_ONGOING));
    }
    RSTAT(EVICTS)++;
    RSTAT(EVICT_PAGES) += nchunks;

    /* flush pages */
    flushed = flush_pages(chan_id, mr, base_addr, nchunks, flags, 
        write_map, true, cbs);
    assert(nchunks == flushed);

    /* memory accounting */
    if (flushed > 0) {
        size = flushed * CHUNK_SIZE;
        atomic_fetch_sub_explicit(&memory_booked, size, memory_order_acquire);
        pressure = atomic_fetch_sub_explicit(&memory_used, size, memory_order_acquire);
        log_debug("Freed %d page(s), pressure=%lld", nchunks, pressure - size);
    
        /* set flushed pages non-present */
        nchunks = clear_page_flags_range(mr, base_addr, size, PFLAG_PRESENT);
        assert(nchunks == flushed);     /*sanity check*/

        /* For everyone, clear the page index and release the page nodes */
        pgidx = set_page_index_atomic(page->mr, page->addr, 0);
        assert(pgidx == rmpage_get_node_id(page));
        rmpage_node_free(page);
        log_debug("cleared index bits and page node for %lx", page->addr);
        list_for_each(&more_pages, tmp, link) {
            pgidx = set_page_index_atomic(tmp->mr, tmp->addr, 0);
            assert(pgidx == rmpage_get_node_id(tmp));
            rmpage_node_free(tmp);
            log_debug("cleared index bits and page node for %lx", tmp->addr);
        }

        /* For pages that were discarded and not written-back, we can just 
         * clear most bits, including the lock, and let them go */
        bitmap_for_each_cleared(write_map, nchunks, i) {
            addr = base_addr + i * CHUNK_SIZE;
            log_debug("evict done at flush, unlocking page %lx", addr);
            clear_page_flags(mr, addr, PFLAG_PRESENT | PFLAG_DIRTY |
                PFLAG_WORK_ONGOING | PFLAG_EVICT_ONGOING | PFLAG_HOT_MARKER, 
                &oldflags);
            assert(!!(oldflags & PFLAG_WORK_ONGOING)); /*sanity check*/
            RSTAT(EVICT_PAGES_DONE)++;
        }

        /* For pages that were written-back, the story is more complicated. 
         * We can set them non-present at this point but cannot release those 
         * that are waiting for writes to complete. Because we don't want 
         * another fault to go on reading from remote memory while the dirtied 
         * changes are waiting in the write queue. At the same time, we cannot
         * clear after write completion because that might happen before the 
         * madvise here (due to completion stealing). So we try and determine 
         * who goes before the other using the PFLAG_EVICT_ONGOING flag */
        bitmap_for_each_set(write_map, nchunks, i) {
            addr = base_addr + i * CHUNK_SIZE;
            clear_page_flags(mr, addr, PFLAG_EVICT_ONGOING | PFLAG_PRESENT | 
                PFLAG_DIRTY | PFLAG_HOT_MARKER, &oldflags);
            if (!(oldflags & PFLAG_EVICT_ONGOING)) {
                /* I'm the last one to reach here, clear the lock as well */
                log_debug("evict done at mdv, unlocking page %lx", addr);
                clear_page_flags(mr, addr, PFLAG_WORK_ONGOING, &oldflags);
                assert(!!(oldflags & PFLAG_WORK_ONGOING)); /*sanity check*/
                RSTAT(EVICT_PAGES_DONE)++;
            }
        }
        RSTAT(EVICT_DONE)++;
    }

#ifdef SAFEMODE
    /* see if eviction was going as expected*/
    verify_eviction();
#endif
    return flushed;
}
