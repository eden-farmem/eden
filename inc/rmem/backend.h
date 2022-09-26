/*
 * backend.h - abstract remote memory backend
 */

#ifndef __BACKEND_H__
#define __BACKEND_H__

#include "rmem/config.h"
#include "rmem/region.h"

struct region_t;    /*forward declaration, defined in region.h*/

/* define and register backend */
struct rmem_backend_ops {
    /**
     * init - global backend init
     * returns 0 if success, 1 otherwise
     */
    int (*init)();

    /**
     * perthread_init - backend init per each kthread
     * returns 0 if success, 1 otherwise
     */
    int (*perthread_init)();

    /**
     * perthread_destroy - backend destroy per each kthread
     * returns 0 if success, 1 otherwise
     */
    int (*perthread_destroy)();

    /**
     * destroy - backend destroy
     * returns 0 if success, 1 otherwise
     */
    int (*destroy)();

    /**
     * add_memory - request more memory (in slabs) from the backend. New regions 
     * (there may be more than one e.g., from multiple remote servers) are 
     * added to `reg` and the count is returned.
     */
    int (*add_memory)(struct region_t **reg, int nslabs);

    /**
     * remove_region - inform the backend to remove/free a memory region
     * returns 0 if success, 1 otherwise
     */
    int (*remove_region)(struct region_t *reg);
    
    // int read(struct region_t *reg, unsigned long fault_addr, ...);
    // int write(struct region_t *reg, unsigned long addr, size_t size);
    // int read_from_rdma_write_q(int fd, struct region_t *mr, addr ...);
    // int poller_on_completion(struct ibv_wc *wc);
    // int drain_write_reqs();
};

/* available backends */
extern struct rmem_backend_ops local_backend_ops;
extern struct rmem_backend_ops rdma_backend_ops;

/* current backend */
extern struct rmem_backend_ops* rmbackend;

#endif    // __BACKEND_H__