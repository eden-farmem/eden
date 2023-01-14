/*
 * stat.c - statistics thread for tracing tool
 */

#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>

#include <base/atomic.h>
#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <rmem/common.h>
#include <runtime/thread.h>
#include <runtime/udp.h>
#include <runtime/timer.h>

#define STAT_INTERVAL_SECS  1
#define MAX_STAT_STR_LEN    1500

static inline int append_stat(char *pos, size_t len, 
    const char *name, uint64_t val)
{
    return snprintf(pos, len, "%s:%ld,", name, val);
}

/* gather all rmem stats and write to the buffer */
static inline int rstat_write_buf(char *buf, size_t len)
{
    uint64_t rstats[RSTAT_NR];
    char *pos, *end;
    int i, j, ret;

    memset(rstats, 0, sizeof(rstats));

    /* gather also from each rmem handler thread */
    assert(nhandlers > 0);
    for (i = 0; i < nhandlers; i++) {
        assert(handlers[i]);
        /* ensure 64bit-alignment as gcc O3 is going to vectorize these loops 
         * and non-alignment results in segfaults (see gcc -ftree-vectorize) */
        assert(((unsigned long) handlers[i]->rstats & 7) == 0);
        for (j = 0; j < RSTAT_NR; j++) {
            rstats[j] += handlers[i]->rstats[j];
        }
    }

    /* write out all thr stats to the buffer */
    pos = buf;
    end = buf + len;
    for (j = 0; j < RSTAT_NR; j++) {
        ret = append_stat(pos, end - pos, rstat_names[j], rstats[j]);
        if (ret < 0) {
            return -EINVAL;
        } else if (ret >= end - pos) {
            return -E2BIG;
        }
        pos += ret;
    }

    /* report memory used */
    ret = append_stat(pos, end - pos,
        "memory_used", atomic64_read(&memory_used));
    if (ret < 0) {
        return -EINVAL;
    } else if (ret >= end - pos) {
        return -E2BIG;
    }
    pos += ret;

    /* report memory allocd */
    ret = append_stat(pos, end - pos,
        "memory_allocd", atomic64_read(&memory_allocd));
    if (ret < 0) {
        return -EINVAL;
    } else if (ret >= end - pos) {
        return -E2BIG;
    }
    pos += ret;

    /* report memory freed */
    ret = append_stat(pos, end - pos,
        "memory_freed", atomic64_read(&memory_freed));
    if (ret < 0) {
        return -EINVAL;
    } else if (ret >= end - pos) {
        return -E2BIG;
    }
    pos += ret;

    pos[-1] = '\0'; /* clip off last ',' */
    return 0;
}

static void* stats_worker(void *arg)
{
    /* stats thread always part of runtime */
    RUNTIME_ENTER();

    char buf[MAX_STAT_STR_LEN];
    char fname[100];
    unsigned long now;
    FILE* fp;
    int ret;
    
    sprintf(fname, "fault-stats-%d.out", getpid());
    fp = fopen(fname, "w");
    assert(fp);

    while (true)
    {
        sleep(STAT_INTERVAL_SECS);
        now = time(NULL);

        /* print remote memory stats */
        ret = rstat_write_buf(buf, MAX_STAT_STR_LEN);
        if (ret < 0) {
            log_err("rstat err %d: couldn't generate stat buffer", ret);
            continue;
        }
        fprintf(fp, "%lu %s\n", now, buf);
        fflush(fp);
    }

    fclose(fp);
    RUNTIME_EXIT();
    return NULL;
}

/**
 * start_stats_thread - starts the stats thread
 */
int start_stats_thread(int pincore_id)
{
    pthread_t stats_thread;
    int ret;

    /* start stats thread */
    ret = pthread_create(&stats_thread, NULL, stats_worker, NULL);
    assertz(ret);

    /* pin thread */
    if (pincore_id >= 0) {
        ret = cpu_pin_thread(stats_thread, pincore_id);
        assertz(ret);
    }

    return 0;
}
