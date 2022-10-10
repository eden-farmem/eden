/*
 * rmem_local.c - Local memory-based remote memory backend
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <sys/mman.h>

#include "rmem/backend.h"
#include "rmem/fault.h"

/* state */
struct local_request {
    volatile int busy;
    int index;
    int chan_id;
    struct fault* fault;
    struct region_t* mr;
    unsigned long orig_local_addr;
    unsigned long local_addr;
    unsigned long remote_addr;
    unsigned long size;
    unsigned long start_tsc;
    rw_mode_t mode;
};
struct local_channel {
    volatile int read_req_idx;
    volatile int write_req_idx;
    struct local_request read_reqs[MAX_R_REQS_PER_CHAN];
    struct local_request write_reqs[MAX_W_REQS_PER_CHAN]; 
};
struct local_channel* chans[RMEM_MAX_CHANNELS];

/* backend init */
int local_init()
{
    int i;
    log_info("setting up local backend for remote memory");
    for(i = 0; i < RMEM_MAX_CHANNELS; i++) {
        chans[i] = aligned_alloc(CACHE_LINE_SIZE, sizeof(struct local_channel));
        memset(chans[i], 0, sizeof(struct local_channel));
        assert(chans[i]);
    }
    return 0;
}

/* returns the next available channel (id) for datapath */
int local_get_data_channel()
{
    BUG();  /* not supported yet */
    return -1;
}

/* backend destroy */
int local_destroy()
{
    int i;
    for(i = 0; i < RMEM_MAX_CHANNELS; i++)
        free(chans[i]);
    return 0;
}

/* add more backend memory (in slabs) and return new regions */
int local_add_regions(struct region_t **regions, int nslabs)
{
    struct region_t *reg;
    void* ptr;
    size_t size;
    int r;

    /* alloc backing memory */
    size = nslabs * RMEM_SLAB_SIZE;
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        log_err("memory alloc failed for local backend - %s", strerror(errno));
        BUG();
    }

    /* init & register region */
    reg = (struct region_t *)mmap(NULL, sizeof(struct region_t), 
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    reg->size = 0;
    reg->remote_addr = (unsigned long) ptr; /* remote from client perspective */
    reg->server = NULL;
    reg->size = size;
    r = register_memory_region(reg, 1);
    assertz(r);
    assert(reg->addr);
    log_debug("%s: local region added at address %p", __func__, ptr);

    /* TODO: return the region in **regions */
    return 1;
}

/* remove a memory region from backend */
int local_free_region(struct region_t *reg)
{
    assert(reg->server == NULL);
    assert(reg->remote_addr);
    munmap((void*) reg->remote_addr, reg->size);
    return 0;
}


/* post read on a channel */
int local_post_read(int chan_id, fault_t* f) 
{
    BUG();  /* not supported yet */
    return 0;
}

/* post write on a channel */
int local_post_write(int chan_id, struct region_t* mr, unsigned long addr, 
    size_t size) 
{
    BUG();  /* not supported yet */
    return 0;
}

/* backend check for read & write completions on a channel */
int local_check_cq(int chan_id, struct bkend_completion_cbs* cbs, int max_cqe, 
    int* nread, int* nwrite)
{
    BUG();  /* not supported yet */
    return 0;
}

/* ops for RDMA */
struct rmem_backend_ops local_backend_ops = {
    .init = local_init,
    .get_new_data_channel = backend_get_data_channel,
    .destroy = local_destroy,
    .add_memory = local_add_regions,
    .remove_region = local_free_region,
    .post_read = local_post_read,
    .post_write = local_post_write,
    .check_for_completions = local_check_cq,
};