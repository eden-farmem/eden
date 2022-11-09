
/*
 * page.c -  TCache for remote memory page nodes
 */

#include <sys/mman.h>

#include "base/mem.h"
#include "rmem/page.h"
#include "rmem/common.h"

/* common state */
static struct tcache *rmpage_node_tcache;
DEFINE_PERTHREAD(struct tcache_perthread, rmpage_node_pt);
static DEFINE_SPINLOCK(rmpage_node_lock);
rmpage_node_t* rmpage_nodes = NULL;
size_t rmpage_node_count = 0;
static size_t max_rmpage_nodes = 0;
static size_t free_rmpage_node_count = 0;
static rmpage_node_t** free_rmpage_nodes;

static void rmpage_node_tcache_free(struct tcache *tc, int nr, void **items)
{
    /* save for reallocation */
    int i;
    spin_lock(&rmpage_node_lock);
    for (i = 0; i < nr; i++) {
        /* make sure the items returned are proper */
        BUG_ON(free_rmpage_node_count >= rmpage_node_count);
        assert(rmpage_is_node_valid(items[i]));
        free_rmpage_nodes[free_rmpage_node_count++] = items[i];
    }
    spin_unlock(&rmpage_node_lock);
}

static int rmpage_node_tcache_alloc(struct tcache *tc, int nr, void **items)
{
    int i = 0;

    spin_lock(&rmpage_node_lock);
    while (free_rmpage_node_count && i < nr)
        items[i++] = free_rmpage_nodes[--free_rmpage_node_count];

    for (; i < nr; i++) {
        /* allocate new */
        log_debug("allocing new page node buf: %ld", rmpage_node_count);
        if(rmpage_node_count >= max_rmpage_nodes){
            log_err_ratelimited("too many rmem pages, cannot allocate more");
            goto fail;
        }
        items[i] = &rmpage_nodes[rmpage_node_count];
        rmpage_node_count++;
    }
    spin_unlock(&rmpage_node_lock);
    return 0;
fail:
    spin_unlock(&rmpage_node_lock);
    rmpage_node_tcache_free(tc, i, items);
    return -ENOMEM;
}

static const struct tcache_ops rmpage_node_tcache_ops = {
    .alloc	= rmpage_node_tcache_alloc,
    .free	= rmpage_node_tcache_free,
};

/**
 * rmpage_is_node_valid - checks if a given address points to a valid node
 */
bool rmpage_is_node_valid(rmpage_node_t* pgnode)
{
    assert(rmpage_nodes && max_rmpage_nodes);  /* check inited */
    log_debug("%s: node %p, base %p, len %ld", 
        __func__, pgnode, rmpage_nodes, rmpage_node_count);
    return pgnode >= rmpage_nodes
        && (unsigned long)(pgnode - rmpage_nodes) < rmpage_node_count
        && ((char*)pgnode - (char*)rmpage_nodes) % sizeof(rmpage_node_t) == 0;
}

/**
 * rmpage_node_tcache_init_thread - inits per-thread tcache for fault objects
 * Returns 0 (always successful).
 */
void rmpage_node_tcache_init_thread(void)
{
    tcache_init_perthread(rmpage_node_tcache, &perthread_get(rmpage_node_pt));
}

/**
 * rmpage_node_tcache_init - initializes the global rmem page node pool
 * Returns 0 if successful, or -ENOMEM if out of memory.
 */
int rmpage_node_tcache_init(void)
{
    /* check if we can support local memory */
    max_rmpage_nodes = (1ULL << PAGE_INDEX_LEN);
    if (local_memory > max_rmpage_nodes * CHUNK_SIZE) {
        log_err("can't support %lu B local memory with current page "
            "index size %lu", local_memory, PAGE_INDEX_LEN);
        BUG();
    }

    /* create backing region with huge pages on current numa node */
    rmpage_nodes = mem_map_anom(NULL, max_rmpage_nodes * sizeof(rmpage_node_t),
        PGSIZE_2MB, NUMA_NODE);
    if(!rmpage_nodes) {
        log_err("out of huge pages for rmpage_nodes");
        return -ENOMEM;
    }
    
    /* allocate free page tracker */
    free_rmpage_nodes = mem_map_anom(NULL, max_rmpage_nodes * 
        sizeof(rmpage_node_t*), PGSIZE_2MB, NUMA_NODE);
    if(!free_rmpage_nodes) {
        log_err("out of huge pages for free_rmpage_nodes");
        return -ENOMEM;
    }

    /* create pool */
    rmpage_node_tcache = tcache_create("rmpage_node_tcache", 
        &rmpage_node_tcache_ops, TCACHE_MAX_MAG_SIZE, sizeof(rmpage_node_t));
    if (!rmpage_node_tcache)
        return -ENOMEM;

    log_info("inited rmem page node pool with %lu max nodes", max_rmpage_nodes);
    return 0;
}

/**
 * rmpage_node_tcache_destroy - destroys the global rmem page node pool
 */
int rmpage_node_tcache_destroy(void)
{
	munmap(free_rmpage_nodes, max_rmpage_nodes * sizeof(rmpage_node_t*));
	munmap(rmpage_nodes, max_rmpage_nodes * sizeof(rmpage_node_t));
}