/*
 * handler.h - dedicated handler core for remote memory
 */

#ifndef __HANDLER_H__
#define __HANDLER_H__

#include <stddef.h>
#include <poll.h>
#include <pthread.h>

#include "base/assert.h"
#include "base/types.h"
#include "rmem/fault.h"
#include "rmem/stats.h"

#define MAX_EVENT_FD 100

/* Handler thread def */
typedef struct hthread {
    volatile bool stop;
    pthread_t thread;
    int bkend_chan_id;
    struct fault_wait_q_head fault_wait_q;
    int n_wait_q;
    uint64_t rstats[RSTAT_NR];
} hthread_t __aligned(CACHE_LINE_SIZE);
extern __thread struct hthread *my_hthr;

/* methods */
hthread_t* new_rmem_handler_thread(int pincore_id);
int stop_rmem_handler_thread(hthread_t* hthr);

#endif  // __HANDLER_H__