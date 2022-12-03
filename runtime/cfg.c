/*
 * cfg.c - configuration file support
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <base/stddef.h>
#include <base/bitmap.h>
#include <base/log.h>
#include <base/cpu.h>

#include "defs.h"

int arp_static_count = 0;
struct cfg_arp_static_entry static_entries[MAX_ARP_STATIC_ENTRIES];

/*
 * Configuration Options
 */

static int str_to_ip(const char *str, uint32_t *addr)
{
	uint8_t a, b, c, d;
	if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
		return -EINVAL;
	}

	*addr = MAKE_IP_ADDR(a, b, c, d);
	return 0;
}

static int str_to_mac(const char *str, struct eth_addr *addr)
{
	int i;
	static const char *fmts[] = {
		"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		"%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
		"%hhx%hhx%hhx%hhx%hhx%hhx"
	};

	for (i = 0; i < ARRAY_SIZE(fmts); i++) {
		if (sscanf(str, fmts[i], &addr->addr[0], &addr->addr[1],
			   &addr->addr[2], &addr->addr[3], &addr->addr[4],
			   &addr->addr[5]) == 6) {
			return 0;
		}
	}
	return -EINVAL;
}

static int str_to_long(const char *str, long *val)
{
	char *endptr;

	*val = strtol(str, &endptr, 10);
	if (endptr == str || (*endptr != '\0' && *endptr != '\n') ||
	    ((*val == LONG_MIN || *val == LONG_MAX) && errno == ERANGE))
		return -EINVAL;
	return 0;
}

static int parse_host_ip(const char *name, const char *val)
{
	uint32_t *addr;
	int ret;

	if (!strcmp(name, "host_addr"))
		addr = &netcfg.addr;
	else if (!strcmp(name, "host_netmask"))
		addr = &netcfg.netmask;
	else if (!strcmp(name, "host_gateway"))
		addr = &netcfg.gateway;
	else
		return -EINVAL;

	if (!val)
		return -EINVAL;

	ret = str_to_ip(val, addr);
	if (ret)
		return ret;

	if (!strcmp(name, "host_netmask") &&
	    (!*addr || ((~*addr + 1) & ~*addr))) {
		log_err("invalid netmask");
		return -EINVAL;
	}

	if (*addr >> 24 == 127) {
		log_err("IP address can't be local subnet");
		return -EINVAL;
	}

	return 0;
}

static int parse_runtime_kthreads(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret)
		return ret;

	if (tmp < 1 || tmp > cpu_count - 1) {
		log_err("invalid number of kthreads requested, '%ld'", tmp);
		log_err("must be > 0 and < %d (number of CPUs)", cpu_count);
		return -EINVAL;
	}

	maxks = tmp;
	return 0;
}

static int parse_runtime_spinning_kthreads(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret)
		return ret;

	if (tmp < 0) {
		log_err("invalid number of spinning kthreads requests, '%ld', "
			"must be > 0", tmp);
		return -EINVAL;
	}

	spinks = tmp;
	return 0;
}

static int parse_runtime_guaranteed_kthreads(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret)
		return ret;

	if (tmp > cpu_count - 1) {
		log_err("invalid number of guaranteed kthreads requested, '%ld'", tmp);
		log_err("must be < %d (number of CPUs)", cpu_count);
		return -EINVAL;
	} else if (tmp < 1) {
		log_warn("< 1 guaranteed kthreads is not recommended for networked apps");
	}

	guaranteedks = tmp;
	return 0;
}

static int parse_mac_address(const char *name, const char *val)
{
	int ret = str_to_mac(val, &netcfg.mac);
	if (ret)
		log_err("Could not parse mac address: %s", val);
	return ret;
}

static int parse_watchdog_flag(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret) {
		log_err("Expecting 0 or 1 for %s", name);
		return ret;
	}
	disable_watchdog = (tmp != 0);
	return 0;
}

static int parse_remote_memory_flag(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret || (tmp != 0 && tmp != 1)) {
		log_err("Expecting 0 or 1 for %s", name);
		return ret;
	}
	rmem_enabled = (tmp != 0);
	return 0;
}

static int parse_rmem_hints_flag(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret || (tmp != 0 && tmp != 1)) {
		log_err("Expecting 0 or 1 for %s", name);
		return ret;
	}
	rmem_hints_enabled = (tmp != 0);
	return 0;
}

static int parse_rmem_backend_flag(const char *name, const char *val)
{
	if (strcmp("local", val) == 0)
		rmbackend_type = RMEM_BACKEND_LOCAL;
	else if (strcmp("rdma", val) == 0)
		rmbackend_type = RMEM_BACKEND_RDMA;
	else {
		log_err("Invalid rmem backend: %s. Allowed: local, rdma", val);
		return 1;
	}

	return 0;
}

static int parse_rmem_local_memory_flag(const char *name, const char *val)
{
	int ret;
	long tmp;

	ret = str_to_long(val, &tmp);
	if (ret || tmp <= 0) {
		log_err("Expecting a positive number for %s", name);
		return ret;
	}

	local_memory = tmp;
	return 0;
}

static int parse_rmem_evict_thr_flag(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret || !(tmp >= 0 && tmp <= 100)) {
		log_err("Expecting 0 to 100 for %s", name);
		return -EINVAL;
	}
	eviction_threshold = tmp * 1.0 / 100;
	return 0;
}

static int parse_rmem_evict_batch_size_flag(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret || !(tmp > 0 && tmp <= EVICTION_MAX_BATCH_SIZE)) {
		log_err("Expecting [1, %d) for %s", EVICTION_MAX_BATCH_SIZE, name);
		return -EINVAL;
	}

	evict_batch_size = tmp;
	return 0;
}

static int parse_rmem_evict_ngens_flag(const char *name, const char *val)
{
	int ret;
	long tmp;
	
	ret = str_to_long(val, &tmp);
	if (ret || !(tmp > 0 && tmp <= EVICTION_MAX_GENS && (tmp & (tmp - 1)) == 0))
	{
		log_err("%s must be in [1,%d] and a power of 2; " 
			"provided: %ld", name, EVICTION_MAX_GENS, tmp);
		return -EINVAL;
	}

	evict_ngens = tmp;
	return 0;
}

static int parse_rmem_evict_nprio_flag(const char *name, const char *val)
{
	int ret;
	long tmp;
	
	ret = str_to_long(val, &tmp);
	if (ret || !(tmp > 0 && tmp <= EVICTION_MAX_PRIO)) {
		log_err("%s must be in [1,%d]; provided: %ld", 
			name, EVICTION_MAX_GENS, tmp);
		return -EINVAL;
	}

	evict_nprio = tmp;
	return 0;
}

static int parse_static_arp_entry(const char *name, const char *val)
{
	int ret;

	ret = str_to_ip(val, &static_entries[arp_static_count].ip);
	if (ret) {
		log_err("Could not parse ip: %s", val);
		return ret;
	}

	ret = str_to_mac(strtok(NULL, " "),
			 &static_entries[arp_static_count].addr);
	if (ret) {
		log_err("Could not parse mac: %s", val);
		return ret;
	}

	arp_static_count++;

	return 0;
}

static int parse_log_level(const char *name, const char *val)
{
	long tmp;
	int ret;

	ret = str_to_long(val, &tmp);
	if (ret)
		return ret;

	if (tmp < LOG_EMERG || tmp > LOG_DEBUG) {
		log_err("log level must be between %d and %d",
			LOG_EMERG, LOG_DEBUG);
		return -EINVAL;
	}

	max_loglevel = tmp;
	return 0;
}


/*
 * Parsing Infrastructure
 */

typedef int (*cfg_fn_t)(const char *name, const char *val);

struct cfg_handler {
	const char	*name;
	cfg_fn_t	fn;
	bool		required;
};

static const struct cfg_handler cfg_handlers[] = {
	{ "host_addr", parse_host_ip, true },
	{ "host_netmask", parse_host_ip, true },
	{ "host_gateway", parse_host_ip, true },
	{ "host_mac", parse_mac_address, false },
	{ "runtime_kthreads", parse_runtime_kthreads, true },
	{ "runtime_spinning_kthreads", parse_runtime_spinning_kthreads, false },
	{ "runtime_guaranteed_kthreads", parse_runtime_guaranteed_kthreads, false },
	{ "static_arp", parse_static_arp_entry, false },
	{ "log_level", parse_log_level, false },
	{ "disable_watchdog", parse_watchdog_flag, false },
	{ "remote_memory", parse_remote_memory_flag, false },
	{ "rmem_hints", parse_rmem_hints_flag, false },
	{ "rmem_backend", parse_rmem_backend_flag, false },
	{ "rmem_local_memory", parse_rmem_local_memory_flag, false },
	{ "rmem_evict_threshold", parse_rmem_evict_thr_flag, false },
	{ "rmem_evict_batch_size", parse_rmem_evict_batch_size_flag, false },
	{ "rmem_evict_ngens", parse_rmem_evict_ngens_flag, false },
	{ "rmem_evict_nprio", parse_rmem_evict_nprio_flag, false },
};

/**
 * cfg_load - loads the configuration file
 * @path: a path to the configuration file
 *
 * Returns 0 if successful, otherwise fail.
 */
int cfg_load(const char *path)
{
	FILE *f;
	char buf[BUFSIZ];
	DEFINE_BITMAP(parsed, ARRAY_SIZE(cfg_handlers));
	const char *name, *val;
	int i, ret = 0, line = 0;

	bitmap_init(parsed, ARRAY_SIZE(cfg_handlers), 0);

	log_info("loading configuration from '%s'", path);

	f = fopen(path, "r");
	if (!f)
		return -errno;

	while (fgets(buf, sizeof(buf), f)) {
		if (buf[0] == '#' || buf[0] == '\n') {
			line++;
			continue;
		}
		name = strtok(buf, " \n");
		if (!name)
			break;
		val = strtok(NULL, " \n");

		for (i = 0; i < ARRAY_SIZE(cfg_handlers); i++) {
			const struct cfg_handler *h = &cfg_handlers[i];
			if (!strncmp(name, h->name, BUFSIZ)) {
				ret = h->fn(name, val);
				if (ret) {
					log_err("bad config option on line %d",
						line);
					goto out;
				}
				bitmap_set(parsed, i);
				break;
			}
		}

		line++;
	}

	for (i = 0; i < ARRAY_SIZE(cfg_handlers); i++) {
		const struct cfg_handler *h = &cfg_handlers[i];
		if (h->required && !bitmap_test(parsed, i)) {
			log_err("missing required config option '%s'", h->name);
			ret = -EINVAL;
			goto out;
		}
	}

	if (guaranteedks > maxks) {
		log_err("invalid number of guaranteed kthreads requested, '%d'",
				guaranteedks);
		log_err("must be <= %d (number of kthreads)", maxks);
		ret = -EINVAL;
		goto out;
	}

out:
	fclose(f);
	return ret;
}
