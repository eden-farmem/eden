/*
 * rmem_local.c - Local memory-based remote memory backend
 */

#include "rmem/backend.h"

/* backend init */
int local_init() {
    log_info("setting up local backend for remote memory");
    BUG();  /* not supported yet */
    return 0;
}

/* backend per-thread init */
int local_perthread_init() {
    BUG();  /* not supported yet */
    return 0;
}

/* backend per-thread deinit */
int local_perthread_destroy() {
    BUG();  /* not supported yet */
    return 0;
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

/* ops for RDMA */
struct rmem_backend_ops local_backend_ops = {
    .init = local_init,
    .perthread_init = local_perthread_init,
    .perthread_destroy = local_perthread_destroy,
    .destroy = local_destroy,
    .add_memory = local_add_regions,
    .remove_region = local_free_region,
};