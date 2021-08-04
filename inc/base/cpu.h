/*
 * cpu.h - detection for CPU topology
 */

#pragma once

#include <base/stddef.h>
#include <base/limits.h>
#include <base/bitmap.h>

#ifndef NUMA_NODE
#define NUMA_NODE 0		/* Ideally should be a runtime parameter */
#endif

extern int cpu_count; /* the number of available CPUs */
extern int numa_count; /* the number of NUMA nodes */

struct cpu_info {
	DEFINE_BITMAP(thread_siblings_mask, NCPU);
	DEFINE_BITMAP(core_siblings_mask, NCPU);
	int package;
};

extern struct cpu_info cpu_info_tbl[NCPU];
