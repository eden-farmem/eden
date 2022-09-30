
/*
 * fault.c - fault handling common
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include <unistd.h>

#include "rmem/fault.h"
#include "rmem/pflags.h"

/* fault handling common state */
__thread void* zero_page = NULL;
__thread char fstr[__FAULT_STR_LEN];

struct dne_fifo_head dne_q;
unsigned int n_dne_fifo;
__thread dne_q_item_t dne_q_items[DNE_QUEUE_SIZE];

/**
 * Per-thread zero page support
 */

void zero_page_init_thread() {
    zero_page = aligned_alloc(CHUNK_SIZE, CHUNK_SIZE);
    assert(zero_page);
    memset(zero_page, 0, CHUNK_SIZE);
}

void zero_page_free_thread() {
    assert(zero_page);
    free(zero_page);
}

/**
 * Per-thread DNE support
 * Keeps recently fetched pages for a while before leaving then open for 
 * eviction */

void dne_q_init_thread() {
    TAILQ_INIT(&dne_q);
    n_dne_fifo = 0;
}

void dne_q_free_thread() {
    /* nothing to do */
}

void dne_on_new_fault(struct region_t *mr, unsigned long addr, bool exists) 
{
    dne_q_item_t *q_item = NULL;
    if (n_dne_fifo >= DNE_QUEUE_SIZE) {
        // Queue is full. Remove oldest entry from head
        q_item = TAILQ_FIRST(&dne_q);
        TAILQ_REMOVE(&dne_q, q_item, link);

        log_debug("DNE FIFO pop and clearing DNE flag: %lx", q_item->addr);
        clear_page_flags(q_item->mr, q_item->addr, PFLAG_NOEVICT);
    } else {
        // Queue is not full yet, just use the next item.
        q_item = &dne_q_items[n_dne_fifo];
        n_dne_fifo++;
        log_debug("Increaing DNE FIFO size: %u", n_dne_fifo);
    }

    // Prepare the q_item for new insertion.
    q_item->addr = addr;
    q_item->mr = mr;

    // Actually add q_item to tail of queue
    log_debug("DNE FIFO push: %lx", q_item->addr);
    TAILQ_INSERT_TAIL(&dne_q, q_item, link);
    return;
}
