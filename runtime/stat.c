/*
 * stat.c - support for statistics and counters
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

#include "defs.h"

/* port 40 is permanently reserved, so should be fine for now */
#define STAT_PORT			40
#ifdef STATS_CORE
#define STAT_REPORT_LOCAL
#define STAT_INTERVAL_SECS 	1
static const char statsfile[] = "runtime.out";
static const char rstatsfile[] = "rmem-stats.out";
#endif

static const char *stat_names[] = {
	/* scheduler counters */
	"reschedules",
	"sched_cycles",
	"sched_cycles_idle",
	"program_cycles",
	"threads_stolen",
	"softirqs_stolen",
	"softirqs_local",
	"parks",
	"preemptions",
	"preemptions_stolen",
	"core_migrations",

	/* network stack counters */
	"rx_bytes",
	"rx_packets",
	"tx_bytes",
	"tx_packets",
	"drops",
	"rx_tcp_in_order",
	"rx_tcp_out_of_order",
	"rx_tcp_text_cycles",
};

/* must correspond exactly to STAT_* enum definitions in defs.h */
BUILD_ASSERT(ARRAY_SIZE(stat_names) == STAT_NR);

static inline int append_stat(char *pos, size_t len, 
	const char *name, uint64_t val)
{
	return snprintf(pos, len, "%s:%ld,", name, val);
}

/* save latest process memory map information to a local file */
void save_process_maps()
{
    char ch, fname[25];
    FILE *source, *target;

    /* we could use system("cp") to copy the file but it creates a new 
     * process and causes issues with inherited LD_PRELOAD */
    sprintf(fname, "procmaps-%d", getpid());
    source = fopen("/proc/self/maps", "r");
    target = fopen(fname, "w");
    while ((ch = fgetc(source)) != EOF)
        fputc(ch, target);
    fclose(source);
    fclose(target);
}

/* get value of the process virt mem counter from /proc/self/status file */
unsigned long long get_process_vm_counter(const char* name)
{
    const int line_size = 512;
    char line[line_size];
    unsigned long long value;
    FILE *file;
    bool found;
    
    file = fopen("/proc/self/status", "r");
    if (!file)
        return 0;

    found = false;
    while (fgets(line, line_size, file) != NULL) {
        int i = strlen(line);
        assert(i > 6);
        if (strncmp(line, name, strlen(name)) == 0) {
            /* assumes that a digit will be found and the line ends in " Kb" */
            const char *p = line;
            while (*p < '0' || *p > '9') p++;
            line[i - 3] = '\0';
            value = atoi(p);
            found = true;
            break;
        }
    }
    fclose(file);
    BUG_ON(!found);

    value *= 1024;  /* to bytes */
    return value;
}

/* gather all kthr sched stats and write to the buffer */
static ssize_t stat_write_buf(char *buf, size_t len)
{
	uint64_t stats[STAT_NR];
	char *pos = buf, *end = buf + len;
	int i, j, ret;

	memset(stats, 0, sizeof(stats));

	/* gather stats from each kthread */
	/* FIXME: not correct when parked kthreads removed from @ks */
	for (i = 0; i < maxks; i++) {
		for (j = 0; j < STAT_NR; j++)
			stats[j] += allks[i]->stats[j];
	}

	/* write out the stats to the buffer */
	for (j = 0; j < STAT_NR; j++) {
		ret = append_stat(pos, end - pos, stat_names[j], stats[j]);
		if (ret < 0) {
			return -EINVAL;
		} else if (ret >= end - pos) {
			return -E2BIG;
		}

		pos += ret;
	}

	/* report the clock rate */
	ret = append_stat(pos, end - pos, "cycles_per_us", cycles_per_us);
	if (ret < 0) {
		return -EINVAL;
	} else if (ret >= end - pos) {
		return -E2BIG;
	}

	pos += ret;
	pos[-1] = '\0'; /* clip off last ',' */
	return pos - buf;
}

/* gather all rmem stats and write to the buffer */
static inline int rstat_write_buf(char *buf, char *buf_hthr, size_t len)
{
	uint64_t rstats_all[RSTAT_NR];
	uint64_t rstats_hthr[RSTAT_NR];
	char *pos, *end;
	int i, j, ret;

	memset(rstats_all, 0, sizeof(rstats_all));
	memset(rstats_hthr, 0, sizeof(rstats_hthr));

	/* gather rstats from each kthread */
	/* FIXME: not correct when parked kthreads removed from @ks */
	for (i = 0; i < maxks; i++) {
		for (j = 0; j < RSTAT_NR; j++)
			rstats_all[j] += allks[i]->rstats[j];
	}

	/* gather also from each rmem handler thread */
	assert(nhandlers > 0);
	for (i = 0; i < nhandlers; i++) {
		assert(handlers[i]);
		/* ensure 64bit-alignment as gcc O3 is going to vectorize these loops 
		 * and non-alignment results in segfaults (see gcc -ftree-vectorize) */
		assert(((unsigned long) handlers[i]->rstats & 7) == 0);
		for (j = 0; j < RSTAT_NR; j++) {
			rstats_all[j] += handlers[i]->rstats[j];
			rstats_hthr[j] += handlers[i]->rstats[j];
		}
	}

#define APPEND_STAT(name,val)   \
    ret = append_stat(pos, end - pos, name, val); \
    if (ret < 0) { \
        return -EINVAL; \
    } else if (ret >= end - pos) { \
        return -E2BIG; \
    } \
    pos += ret;

	/* write out all thr stats to the buffer */
	pos = buf;
	end = buf + len;
	for (j = 0; j < RSTAT_NR; j++) {
        APPEND_STAT(rstat_names[j], rstats_all[j]);
	}

	/* report additional stats at the end */
    APPEND_STAT("memory_used", atomic64_read(&memory_used));

    /* report process vm stats from the status file */
    APPEND_STAT("vm_peak", get_process_vm_counter("VmPeak"));
    APPEND_STAT("vm_size", get_process_vm_counter("VmSize"));
    APPEND_STAT("vm_lock", get_process_vm_counter("VmLck"));
    APPEND_STAT("vm_pin", get_process_vm_counter("VmPin"));
    APPEND_STAT("vm_hwm", get_process_vm_counter("VmHWM"));
    APPEND_STAT("vm_rss", get_process_vm_counter("VmRSS"));
    APPEND_STAT("vm_data", get_process_vm_counter("VmData"));
    APPEND_STAT("vm_stk", get_process_vm_counter("VmStk"));
    APPEND_STAT("vm_exe", get_process_vm_counter("VmExe"));
    APPEND_STAT("vm_lib", get_process_vm_counter("VmLib"));
    APPEND_STAT("vm_pte", get_process_vm_counter("VmPTE"));
    APPEND_STAT("vm_swap", get_process_vm_counter("VmSwap"));
	pos[-1] = '\0'; /* clip off last ',' */

	/* write out just handler hthr stats to hthr buffer */
	pos = buf_hthr;
	end = buf_hthr + len;
	for (j = 0; j < RSTAT_NR; j++) {
        APPEND_STAT(rstat_names[j], rstats_hthr[j]);
	}
	pos[-1] = '\0'; /* clip off last ',' */

	return 0;
}

// static ssize_t thread_state_buf(char *buf, size_t len) {
// 	char *pos = buf, *end = buf + len;
// 	int i, ret;
// 	char name[100];
// 	char* field;

// 	/* gather stats from each kthread */
// 	/* FIXME: not correct when parked kthreads removed from @ks */
// 	field = "pf_pending";
// 	for (i = 0; i < maxks; i++) {
// 		sprintf(name, "%s_%d", field, i);
// 		ret = append_stat(pos, end - pos, name, allks[i]->pf_pending);
// 		if (ret < 0)	return -EINVAL;
// 		else if (ret >= end - pos)	return -E2BIG;
// 		pos += ret;
// 	}

// 	field = "rq_overflow";
// 	for (i = 0; i < maxks; i++) {
// 		sprintf(name, "%s_%d", field, i);
// 		ret = append_stat(pos, end - pos, name, allks[i]->rq_overflow_len);
// 		if (ret < 0)	return -EINVAL;
// 		else if (ret >= end - pos)	return -E2BIG;
// 		pos += ret;
// 	}

// 	pos[-1] = '\0'; /* clip off last ',' */
// 	return pos - buf;
// }

#ifdef STAT_REPORT_LOCAL
static void* stat_worker_local(void *arg)
{
	log_info("pinning stats worker to core %d", STATS_CORE);
	int ret = cpu_pin_thread(pthread_self(), STATS_CORE);
	if (ret) {
		log_err("stat: couldn't pin thread to core %d", STATS_CORE);
		return NULL;
	}

	char buf[UDP_MAX_PAYLOAD];
	char buf_hthr[UDP_MAX_PAYLOAD];
	ssize_t len;
	unsigned long now;
	FILE* fp = fopen(statsfile, "w");
	FILE* rfp = fopen(rstatsfile, "w");

	while (true) {
		__time_delay_us(STAT_INTERVAL_SECS * 1000000);

		/* print scheduler stats */
		now = time(NULL);
		len = stat_write_buf(buf, UDP_MAX_PAYLOAD);
		if (len < 0) {
			log_err("stat: couldn't generate stat buffer");
			continue;
		}
		fprintf(fp, "%lu %s\n", now, buf);
		fflush(fp);

		/* print remote memory stats */
		/* TODO BUG: enabling stats core with this method is causing the 
		 * runtime to fail WHEN multiple handler cores are present AND
		 * stdout/stderr are being redirected to a file */
		if (rmem_enabled) {
			ret = rstat_write_buf(buf, buf_hthr, UDP_MAX_PAYLOAD);
			if (ret < 0) {
				log_err("rstat err %d: couldn't generate rstat buffer", ret);
				continue;
			}
			fprintf(rfp, "%lu total-%s\n", now, buf);
			fprintf(rfp, "%lu handler-%s\n", now, buf_hthr);
			fflush(rfp);
		}

		// /* print thread state */
		// len = thread_state_buf(buf, UDP_MAX_PAYLOAD);
		// if (len < 0) {
		// 	log_err("stat: couldn't generate thread state buffer");
		// 	continue;
		// }
		// fprintf("%s\n", buf);

#ifdef FAULT_SAMPLER
        /* save latest process maps if recording fault trace because 
		 * we will need this data to look up code locations */
        save_process_maps();
#endif
	}

	fclose(fp);
	fclose(rfp);
	return NULL;
}
#endif

static void stat_worker_udp(void *arg)
{
	const size_t cmd_len = strlen("stat");
	char buf[UDP_MAX_PAYLOAD];
	struct netaddr laddr, raddr;
	udpconn_t *c;
	ssize_t ret, len;

	laddr.ip = 0;
	laddr.port = STAT_PORT;

	ret = udp_listen(laddr, &c);
	if (ret) {
		log_err("stat: udp_listen failed, ret = %ld", ret);
		return;
	}

	while (true) {
		ret = udp_read_from(c, buf, UDP_MAX_PAYLOAD, &raddr);
		if (ret < cmd_len)
			continue;
		if (strncmp(buf, "stat", cmd_len) != 0)
			continue;

		len = stat_write_buf(buf, UDP_MAX_PAYLOAD);
		if (len < 0) {
			log_err("stat: couldn't generate stat buffer");
			continue;
		}
		assert(len <= UDP_MAX_PAYLOAD);

		ret = udp_write_to(c, buf, len, &raddr);
		WARN_ON(ret != len);
	}
}

/**
 * stat_init_late - starts the stat responder thread
 *
 * Returns 0 if succesful.
 */
int stat_init_late(void)
{
#ifdef STAT_REPORT_LOCAL
	pthread_t stats_thread;		/* TODO: should we save this somewhere? */
	int ret = pthread_create(&stats_thread, NULL, stat_worker_local, NULL);
	if (ret) {
		log_err("pthread_create for stat worker failed: %d", errno);
		return ret;
	}
#endif
	return thread_spawn(stat_worker_udp, NULL);
}
