/*
 * rmem_local.c - Local memory-based remote memory backend
 */

#include "rmem/backend.h"
#include "rmem/fault.h"

/* backend init */
int local_init() {
    log_info("setting up local backend for remote memory");
    BUG();  /* not supported yet */
    return 0;
}

/* returns the next available channel (id) for datapath */
int local_get_data_channel() {
    BUG();  /* not supported yet */
    return -1;
}

/* backend destroy */
int local_destroy() {
    BUG();  /* not supported yet */
    return 0;
}

/* add more backend memory (in slabs) and return new regions */
int local_add_regions(struct region_t **reg, int nslabs) {
    BUG();  /* not supported yet */
    return 1;
}

/* add more backend memory (in slabs) and return new regions */
int local_free_region(struct region_t *reg) {
    BUG();  /* not supported yet */
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
int local_check_cq(int chan_id, struct completion_cbs* cbs, int max_cqe, 
    int* nread, int* nwrite)
{
    BUG();  /* not supported yet */
    return 0;
}

/* ops for RDMA */
struct rmem_backend_ops local_backend_ops = {
    .init = local_init,
    .get_new_data_channel = local_get_data_channel,
    .destroy = local_destroy,
    .add_memory = local_add_regions,
    .remove_region = local_free_region,
    .post_read = local_post_read,
    .post_write = local_post_write,
    .check_for_completions = local_check_cq,
};