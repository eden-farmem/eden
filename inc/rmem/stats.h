/*
 * stats.h - remote memory stats
 */

#ifndef __RMEM_STATS_H__
#define __RMEM_STATS_H__

/*
 * Remote memory stat counters. 
 * Don't use these enums directly. Instead, use the RSTAT() macro in defs.h
 */
enum {
    RSTAT_FAULTS = 0,
    RSTAT_FAULTS_R,
    RSTAT_FAULTS_W,
    RSTAT_FAULTS_WP,
    RSTAT_WP_UPGRADES,
    RSTAT_FAULTS_ZP,
    RSTAT_FAULTS_DONE,
    RSTAT_UFFD_NOTIF,
    RSTAT_UFFD_COPY_RETRIES,

    RSTAT_EVICTS,
    RSTAT_EVICT_PAGES,
    RSTAT_EVICT_RETRIES,
    RSTAT_EVICT_WBACK,
    RSTAT_EVICT_WP_RETRIES,
    RSTAT_EVICT_WRITE_FAIL,
    RSTAT_EVICT_MADV,
    RSTAT_EVICT_DONE,
    RSTAT_NR,   /* total number of counters */
};

#endif  // __RMEM_STATS_H__