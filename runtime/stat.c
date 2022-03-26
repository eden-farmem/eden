/*
 * stat.c - support for statistics and counters
 */

#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <runtime/thread.h>
#include <runtime/udp.h>
#include <runtime/timer.h>

#include "defs.h"

/* port 40 is permanently reserved, so should be fine for now */
#define STAT_PORT			40
#ifdef STATS_CORE
#define STAT_REPORT_LOCAL
#endif
#define STAT_INTERVAL_SECS 	1

static const char *stat_names[] = {
	/* scheduler counters */
	"reschedules",
	"sched_cycles",
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

	/* page fault counters */
	"pf_posted",
	"pf_returned",
	"pf_retries",
	"pf_failed",
};

/* must correspond exactly to STAT_* enum definitions in defs.h */
BUILD_ASSERT(ARRAY_SIZE(stat_names) == STAT_NR);

static int append_stat(char *pos, size_t len, const char *name, uint64_t val)
{
	return snprintf(pos, len, "%s:%ld,", name, val);
}

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

/* pin this thread to a particular core */
static int pin_thread(int core) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);
  int retcode = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
  if (retcode) { 
      errno = retcode;
      perror("pthread_setaffinitity_np");
  }
  return retcode;
}

static ssize_t thread_state_buf(char *buf, size_t len) {
	char *pos = buf, *end = buf + len;
	int i, ret;
	char name[100];
	char* field;

	/* gather stats from each kthread */
	/* FIXME: not correct when parked kthreads removed from @ks */
	field = "pf_pending";
	for (i = 0; i < maxks; i++) {
		sprintf(name, "%s_%d", field, i);
		ret = append_stat(pos, end - pos, name, allks[i]->pf_pending);
		if (ret < 0)	return -EINVAL;
		else if (ret >= end - pos)	return -E2BIG;
		pos += ret;
	}

	field = "rq_overflow";
	for (i = 0; i < maxks; i++) {
		sprintf(name, "%s_%d", field, i);
		ret = append_stat(pos, end - pos, name, allks[i]->rq_overflow_len);
		if (ret < 0)	return -EINVAL;
		else if (ret >= end - pos)	return -E2BIG;
		pos += ret;
	}

	pos[-1] = '\0'; /* clip off last ',' */
	return pos - buf;
}

#ifdef STAT_REPORT_LOCAL
static void* stat_worker_local(void *arg)
{
	log_info("pinning stats worker to core %d", STATS_CORE);
	int ret = pin_thread(STATS_CORE);
	if (ret) {
		log_err("stat: couldn't pin thread to core %d", STATS_CORE);
		return NULL;
	}

	char buf[UDP_MAX_PAYLOAD];
	ssize_t len;

	while (true) {
		sleep(STAT_INTERVAL_SECS);

		len = stat_write_buf(buf, UDP_MAX_PAYLOAD);
		if (len < 0) {
			log_err("stat: couldn't generate stat buffer");
			continue;
		}
		log_info("STATS>%s\n", buf);

		len = thread_state_buf(buf, UDP_MAX_PAYLOAD);
		if (len < 0) {
			log_err("stat: couldn't generate thread state buffer");
			continue;
		}
		log_info("STATE>%s\n", buf);
	}
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
