/*
 * backend.h - abstract remote memory backend
 */

#ifndef __BACKEND_H__
#define __BACKEND_H__

#include "rmem/config.h"
#include "rmem/fault.h"
#include "rmem/region.h"

/* forward declarations */
struct region_t;
struct fault;
struct completion_cbs;

/**
 * Backend suppported ops
 * Provides read/write page ops on multiple channels, each of which can be
 * used independently (e.g., by each core). Note that channels are not 
 * thread-safe i.e., each channel op must be explicitly locked if called by 
 * multiple threads
 */
struct rmem_backend_ops {
    /**
     * init - global backend init
     * returns 0 if success, 1 otherwise
     */
    int (*init)();

    /**
     * get_new_data_channel - next available channel for read/write pages
     * returns channel id if available, -1 otherwise
     */
    int (*get_new_data_channel)();

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
    
    /**
     * post_read - post read request for the pages needed by the fault from 
     * the backend. returns 0 if posted, EAGAIN if busy
     */
    int (*post_read)(int chan_id, struct fault* f);

    /**
     * post_write - post write request for the page range pointed by addr and 
     * size to the backend. returns 0 if posted, EAGAIN if busy
     */
    int (*post_write)(int chan_id, struct region_t* mr, unsigned long addr, 
        size_t size);

    /**
     * check_for_completions - check with backend for read/write completions
     * for the posted ones. One can also specify max events it is allowed to
     * check before. Returns the number of events addressed (including the 
     * read/write split if required) or -1 on error.
     */
    int (*check_for_completions)(int chan_id, struct completion_cbs* cbs,
        int max_cqe, int* nread, int* nwrite);
};

/* callbacks for backend read/write completions */
struct completion_cbs {
    int (*read_completion)(struct fault* fault, unsigned long buf_addr, size_t size);
    int (*write_completion)(struct region_t* mr, unsigned long addr, size_t size);
};

/* available backends */
extern struct rmem_backend_ops local_backend_ops;
extern struct rmem_backend_ops rdma_backend_ops;

/* current backend */
extern struct rmem_backend_ops* rmbackend;

#endif    // __BACKEND_H__