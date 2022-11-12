/*
 * Default remote memory settings
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "asm/atomic.h"
#include "base/assert.h"
#include "base/log.h"
#include "base/mem.h"

/* Default configs */
#define WP_ON_READ          /* not available on kernel v < 5.0? */
#define NO_DYNAMIC_REGIONS  /* regions added/deleted only at startup/exit */

/* memory backend */
typedef enum {
    RMEM_BACKEND_LOCAL = 0,
    RMEM_BACKEND_RDMA = 1
} rmem_backend_t;
#define RMEM_BACKEND_DEFAULT    RMEM_BACKEND_LOCAL
#define RMEM_SLAB_SIZE          (128 * 1024L)
#define RMEM_MAX_CHANNELS       32
#define RMEM_MAX_CHUNKS_PER_OP  64
#define RMEM_MAX_COMP_PER_OP    16
#define RMEM_MAX_LOCAL_GB       64

/********* Cluster *******************************************/
#define VRG_SC2             // Intel Skylake - CX5
// #define CLOUDLAB_R320    // Deprecated. Use C6220 instead
// #define CLOUDLAB_D6515   // AMD EPYC Rome - CX5
// #define CLOUDLAB_XL170   // Intel Broadwell - CX4
/*************************************************************/

/********* Config for RDMA backend ***************************/
/* for RCNTRL */
#define RDMA_RACK_CNTRL_IP      "192.168.0.40"
#define RDMA_RACK_CNTRL_PORT    9202
#define RCNTRL_ENV_IP           "RDMA_RACK_CNTRL_IP"
#define RCNTRL_ENV_PORT         "RDMA_RACK_CNTRL_PORT"

/* other */
#define RDMA_SERVER_IP          "192.168.0.40"
#define RDMA_SERVER_PORT        9200
#define DEBUG_MSG_MAXLEN        10000
#define MAX_SERVERS             128
#define TIMEOUT_IN_MS           500 /* ms */
#define MAX_LINKED_WRS          64
#define RDMA_SERVER_SLAB_SIZE   RMEM_SLAB_SIZE
#define MAX_QPS_PER_REGION      (RMEM_MAX_CHANNELS+1)

/* settings for different machines */
#ifdef CLOUDLAB_R320
/* Single NUMA nodes for both machines.
 * R320: CPU(s): 16 
 * 16Gb Memory */
#define RDMA_SERVER_MEMORY_GB       12
#define RMEM_HANDLER_CORE_HIGH      12
#define RMEM_HANDLER_CORE_LOW       12
#define PIN_SERVER_CORE             14
#define PIN_SERVER_POLLER_CORE      13
#define PIN_RACK_CNTRL_CORE         12
#define PIN_RACK_CNTRL_POLLER_CORE  11

#elif defined(CLOUDLAB_C6220)
/* NUMA node0 CPU(s):   0-7,16-23
 * NUMA node1 CPU(s):   8-15,24-31
 * RNIC NUMA node = 1
 * 64 GB Memory */
#define RDMA_SERVER_MEMORY_GB       32
#define RMEM_HANDLER_CORE_HIGH      31
#define RMEM_HANDLER_CORE_LOW       31
#define PIN_SERVER_CORE             30
#define PIN_SERVER_POLLER_CORE      29
#define PIN_RACK_CNTRL_CORE         28
#define PIN_RACK_CNTRL_POLLER_CORE  27

#elif defined(VRG_SC2)
/* NUMA node0 CPU(s):   0-13,28-41
 * NUMA node1 CPU(s):   14-27,42-55
 * RNIC NUMA node = 1
 * 176 GB Memory */
#define RDMA_SERVER_MEMORY_GB       64
#define RMEM_HANDLER_CORE_HIGH      55
#define RMEM_HANDLER_CORE_LOW       52
#define PIN_SERVER_CORE             51
#define PIN_SERVER_POLLER_CORE      50
#define PIN_RACK_CNTRL_CORE         49
#define PIN_RACK_CNTRL_POLLER_CORE  48

#else
#pragma GCC error "Specify memory size for selected machine"
#endif
#define RDMA_SERVER_NSLABS (RDMA_SERVER_MEMORY_GB * 1073741824L / RMEM_SLAB_SIZE)
BUILD_ASSERT(RMEM_HANDLER_CORE_LOW <= RMEM_HANDLER_CORE_HIGH);
/*************************************************************/

/* Chunk size for remote memory handling (must be a power of 2 (KB)). */
#define PAGE_SIZE   PGSIZE_4KB
#define CHUNK_SHIFT PGSHIFT_4KB
#define CHUNK_SIZE  PGSIZE_4KB
#define CHUNK_MASK  PGMASK_4KB
BUILD_ASSERT(CHUNK_SIZE >= PGSIZE_4KB);

/* Eviction core settings */
#define LOCAL_MEMORY_SIZE           (4 * 1024 * 1024 * 1024L)
#define EVICTION_THRESHOLD          0.95
#define EVICTION_MAX_BATCH_SIZE     64
#define EVICTION_REGION_SWITCH_THR  1000
#define EVICTION_MAX_GENS           8
#define EVICTION_EPOCH_LEN_MUS      100
#define EVICTION_TLB_FLUSH_MIN      2       /* TODO: must be 32 or something */
#define EVICTION_MAX_BUMPS_PER_OP   (5*EVICTION_MAX_BATCH_SIZE)
BUILD_ASSERT(EVICTION_MAX_BATCH_SIZE <= RMEM_MAX_CHUNKS_PER_OP);

/* Eviction policy (default is none) */
// #define SC_EVICTION     /* second-chance eviction */
// #define LRU_EVICTION    /* LRU eviction */
#if (defined(SC_EVICTION) && defined(LRU_EVICTION))
#pragma GCC error "Only one policy (SC_EVICTION/LRU_EVICTION) can be defined"
#endif

/* Fault handling */
#define RUNTIME_MAX_FAULTS          2048
#define FAULT_TCACHE_MAG_SIZE       64
#define OS_MEM_PROBE_INTERVAL       1e6
#define FAULT_MAX_RDAHEAD_SIZE      1
BUILD_ASSERT((1 + FAULT_MAX_RDAHEAD_SIZE) <= RMEM_MAX_CHUNKS_PER_OP);

/* Region settings  */
#define RMEM_MAX_REGIONS            1

#endif  // __CONFIG_H__