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
#include "rmem/pflags.h"
#include "rmem/region.h"
#include "rmem/uffd.h"

#include "../defs.h"

/* eviction state */
__thread uint64_t last_seen_faults = 0;
__thread struct region_t *eviction_region_safe = NULL;
__thread uint64_t last_evict_try_count = 0;

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
    
    if (!!(flags & PFLAG_NOEVICT))
        /* recently brought in */
        return false;
    
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
static inline unsigned long find_candidate_chunks(struct region_t *mr, 
    int *nchunks, int max_batch_size) 
{
    unsigned long addr, base_addr = 0;
    int tries = 0;
    pflags_t flags;

    *nchunks = 0;
    while(tries < 10) {
        tries++;

        /* for each MR, keep track of MR offset we last evicted from */
        if (mr->evict_offset >= mr->current_offset) {
            log_debug("restarting offset=%llx to offset=0 for mr:%p", 
                mr->evict_offset, mr);
            mr->evict_offset = 0;
        }

        /* we're doing simple clocking over the region to find candidates! */
        assert(mr->evict_offset < mr->current_offset);
        addr = mr->addr + atomic_fetch_add(&mr->evict_offset, PAGE_SIZE);

        /* check if the page is evictable */
        flags = get_page_flags(mr, addr);
        if (!is_evictable(flags)) {
            /* have we already found some evictible pages? then break! */
            if (base_addr) break;
            else continue;
        }

        /* found something evictable */
        (*nchunks)++;
        if (!base_addr) 
            base_addr = addr;
        if (*nchunks > max_batch_size)
            break;
    }

    return base_addr;
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
#if defined(WP_ON_READ)
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
    int r, n_retries, ncompletions = 0;    
    log_debug("writing back contiguous region at [%lx, %d)", addr, nchunks);

    /* protect the region first */
    n_retries = 0;
    r = uffd_wp_add(userfault_fd, addr, nchunks * CHUNK_SIZE, false, true, &n_retries);
    assertz(r);
    RSTAT(EVICT_WP_RETRIES) += n_retries;
    RSTAT(EVICT_WBACK)++;

    /* post the write-back */
    do {
        r = rmbackend->post_write(chan_id, mr, addr, nchunks * CHUNK_SIZE);
        if (r == EAGAIN) {
            /* write queue is full, nothing to do but repeat and keep 
             * checking for completions to free request slots; raising error
             * if we handled completions but still cannot post */
            assert (ncompletions >= 1);
            ncompletions += rmbackend->check_for_completions(chan_id, cbs, 
                RMEM_MAX_COMP_PER_OP, NULL, NULL);

            /* TODO: we may want to count idle cycles here */
            cpu_relax();
        }
    } while(r == EAGAIN);
    assertz(r);
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
        clear_page_flags(mr, page, PFLAG_EVICT_ONGOING | PFLAG_PRESENT | 
            PFLAG_DIRTY | PFLAG_HOT_MARKER, &oldflags);
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
    unsigned long base_addr, new_base_addr, addr, size;
    pflags_t oldflags;
    int nchunks_found, nchunks_locked, i, flushed, nchunks;
    pflags_t flags[max_batch_size];
    DEFINE_BITMAP(write_map, max_batch_size);
    unsigned long long pressure;
    struct region_t* mr;

    /* get region */
    mr = get_evictable_region_safe();

    /* get eviction candidate */
    do {
        new_base_addr = 0;
        base_addr = find_candidate_chunks(mr, &nchunks_found, max_batch_size);
        if (!base_addr) {
            RSTAT(EVICT_RETRIES)++;
            /* TODO: error out if we are stuck here */
            continue;
        }

        /* get the longest contiguous sub-chunk that we manage to lock! */
        assert(nchunks_found < max_batch_size);
        nchunks_locked = 0;
        for (i = 0; i < nchunks_found; i++) {
            addr = base_addr + i * CHUNK_SIZE;
            set_page_flags(mr, addr, PFLAG_WORK_ONGOING, &oldflags);
            if (!!(oldflags & PFLAG_WORK_ONGOING)) {
                /* some other thread took it */
                if (nchunks_locked == 0)
                    /* didn't start the locked sub-chunk yet, keep looking */
                    continue;
                else
                    /* already locked some, can't have non-contiguous chunk */
                    break;
            }
            if (nchunks_locked == 0)
                new_base_addr = addr;
            nchunks_locked++;
        }
        base_addr = new_base_addr;

        /* locked some! go for eviction */
        if (nchunks_locked > 0)
            break;
    } while(nchunks_locked == 0);

    /* flag them as evicting. TODO: is this necessary? */
    log_debug("evicting pages at %lu, number: %d\n", base_addr, nchunks_locked);
    assert(nchunks_locked < EVICTION_MAX_BATCH_SIZE);
    for (i = 0; i < nchunks_locked; i++) {
        addr = base_addr + i * CHUNK_SIZE;
        flags[i] = set_page_flags(mr, addr, PFLAG_EVICT_ONGOING, &oldflags);
    }
    RSTAT(EVICTS)++;
    RSTAT(EVICT_PAGES) += nchunks_locked;

    /* flush pages */
    flushed = flush_pages(chan_id, mr, base_addr, nchunks_locked, flags, 
        write_map, true, cbs);
    assert(nchunks_locked == flushed);

    /* memory accounting */
    if (flushed > 0) {
        size = flushed * CHUNK_SIZE;
        atomic_fetch_sub_explicit(&memory_booked, size, memory_order_acquire);
        pressure = atomic_fetch_sub_explicit(&memory_used, size, memory_order_acquire);
        log_debug("Freed %d page(s), pressure=%lld", nchunks_locked, pressure - size);
    
        /* set flushed pages non-present */
        nchunks = clear_page_flags_range(mr, addr, size, PFLAG_PRESENT);
        assert(nchunks == flushed);     /*sanity check*/

        /* For pages that were discarded and not written-back, we can just 
         * clear most bits, including the lock, and let them go */
        bitmap_for_each_cleared(write_map, nchunks_locked, i) {
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
         * madvise here. So we try and determine who goes before the other
         * using the PFLAG_EVICT_ONGOING flag */
        bitmap_for_each_set(write_map, nchunks_locked, i) {
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
