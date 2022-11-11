/*
 * dump.c - remote memory state dump
 * 
 * dumps remote memory state into a file and exits the program (becauses it 
 * makes irreversible changes to the state).
 * Only use it in deadlock/livelock situations where the program hangs, by
 * setting the "dump_rmem_state_and_exit" global variable through GDB. This 
 * can be done in the stats thread which is most likely to be running during 
 * a deadlock than the handler threads but only handler threads have the 
 * required thread local state (rmem_init_thread()) that is needed to walk 
 * the remote memory state for all threads, like the completion queues. 
 */

#include "rmem/dump.h"
#include "../runtime/defs.h"

/* state */
bool dump_rmem_state_and_exit = false;
const char* dumpfile = "rmem-dump.out";
FILE* dumpfp = NULL;
static DEFINE_SPINLOCK(dump_lock);

/* write backend read completion to dump file */
int rmem_dump_read_comp(fault_t* f)
{
    assert(dumpfp);
    fprintf(dumpfp, "read completion for %s\n", FSTR(f));
    return 0;
}

/* write backend write completion to dump file */
int rmem_dump_write_comp(struct region_t* mr, unsigned long addr, size_t size)
{
    assert(dumpfp);
    fprintf(dumpfp, "write completion for [%lx, %lu)\n", addr, size);
    return 0;
}

/* dummy callbacks to dump completion queue contents */
struct bkend_completion_cbs bkend_dump_cbs = {
    .read_completion = rmem_dump_read_comp,
    .write_completion = rmem_dump_write_comp
};

/* collect remote memory state and dump into a file */
void dump_rmem_state()
{
    int i;
    hthread_t* h;
    struct fault* f;

    /* only one handler should attend to this */
    spin_lock(&dump_lock);
    dumpfp = fopen(dumpfile, "w");

#ifndef RMEM_STANDALONE
    /* dump kthreads */
    struct kthread* k;
    for (i = 0; i < maxks; i++) {
        k = allks[i];

        fprintf(dumpfp, "kthread %d - pending: %d, waitq: %d\n",
            i, k->pf_pending, k->n_wait_q);

        /* dump waiting faults */
        spin_lock(&k->pf_lock);
        fprintf(dumpfp, "wait queue:\n");
        list_for_each(&k->fault_wait_q, f, link)
            fprintf(dumpfp, "found fault %s\n", FSTR(f));
        spin_unlock(&k->pf_lock);

        /* dump completions (this discards faults from CQ) */
        fprintf(dumpfp, "completion queue:\n");
        rmbackend->check_for_completions(k->bkend_chan_id, 
            &bkend_dump_cbs, RMEM_MAX_COMP_PER_OP, NULL, NULL);
    }
#endif

    /* dump handlers */
    assert(nhandlers > 0);
    for (i = 0; i < nhandlers; i++) {
        h = handlers[i];
        assert(h);

        fprintf(dumpfp, "hthread %d - waitq: %d\n", i, h->n_wait_q);

        /* dump waiting faults. NOTE: no lock! */
        fprintf(dumpfp, "wait queue:\n");
        list_for_each(&h->fault_wait_q, f, link)
            fprintf(dumpfp, "found fault %s\n", FSTR(f));

        /* dump completions */
        fprintf(dumpfp, "completion queue:\n");
        rmbackend->check_for_completions(h->bkend_chan_id, 
            &bkend_dump_cbs, RMEM_MAX_COMP_PER_OP, NULL, NULL);
    }

    /* exit the program */
    fflush(dumpfp);
    fclose(dumpfp);
    BUG();
    spin_unlock(&dump_lock);
}