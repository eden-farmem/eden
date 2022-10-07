
/*
 * backend.c - common backend functions
 */

#include <stdatomic.h>
#include "rmem/backend.h"

/* common state */
atomic_int nchans_bkend = ATOMIC_VAR_INIT(0);

/**
 * Returns the next available channel (id) for datapath communication
 **/
int backend_get_data_channel()
{
    int nchan;
    do {
        nchan = atomic_load(&nchans_bkend);
        BUG_ON(nchan > RMEM_MAX_CHANNELS);
        if (nchan == RMEM_MAX_CHANNELS) {
            log_warn("out of rdma channels!");
            return -1;
        }
        nchan++;
    } while(atomic_compare_exchange_strong(&nchans_bkend, &nchan, nchan+1));
    log_debug("channel %d taken", nchan);
    return nchan;
}