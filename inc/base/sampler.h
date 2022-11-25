/*
 * sampler.h - event sampling
 */

#pragma once

#include <math.h>
#include <stdio.h>
#include <time.h>

#include "base/atomic.h"
#include "base/lock.h"
#include "base/log.h"
#include "base/rand.h"

/**
 * Sampler type
 */
enum sampler_type {
    SAMPLER_TYPE_UNIFORM = 0,
    SAMPLER_TYPE_POISSON,
};

/**
 * Sampler interface
 */
struct sampler_ops {
    void (*add_sample)(void* buffer, void* sample);
    void (*sample_to_str)(void* sample, char* sbuf, int max_len);
};
typedef struct sampler_ops sampler_ops_t;

/**
 * Sampler
 */
struct sampler {
    /* params */
    enum sampler_type type;
    int max_samples;
    int samples_per_sec;
    int dumps_per_sec;
    int sample_size;
    sampler_ops_t* ops;
    /* state */
    FILE* outfile;
    spinlock_t lock;
    int sq_head;
    int sq_tail;
    void* samples;
    unsigned long next_sample_tsc;
    unsigned long next_dump_tsc;
    struct rand_state randst;
};
typedef struct sampler sampler_t;

/**
 * Sampler internal
 */
void __add_sample_update_tsc(sampler_t* s, void* sample, unsigned long now_tsc);
void __dump_samples_update_tsc(sampler_t* s, int max_str_len, 
    unsigned long now_tsc);

/**
 * Sampler API
 */

void sampler_init(sampler_t* s, const char* fname, enum sampler_type stype, 
    sampler_ops_t* ops, int sample_size, int max_samples, int samples_per_sec, 
    int dumps_per_sec);
void sampler_destroy(sampler_t* s);

/**
 * Record a given sample when it is time (tsc for current time provided)
 */
static inline void sampler_add_tsc_provided(sampler_t* s, void* sample,
    unsigned long now_tsc)
{
    assert(s && s->ops && s->ops->add_sample);

    /* check if it is time and wait for a lock */
    do {
        if (now_tsc <= s->next_sample_tsc)
            return;
        cpu_relax();
    } while(!spin_try_lock(&s->lock));
    
    /* record sample */
    __add_sample_update_tsc(s, sample, now_tsc);

    /* ensure next_sample_tsc updated */
    assert(now_tsc < s->next_sample_tsc);
    spin_unlock(&s->lock);
}

/**
 * Record a given sample when it is time
 */
static inline void sampler_add(sampler_t* s, void* sample)
{
    sampler_add_tsc_provided(s, sample, rdtsc());
}

/**
 * Dump samples collected since last time to the file
 * This should be called periodically (more often than dump interval) 
 * to empty out the samples queue.
 */ 
static inline void sampler_dump_provide_tsc(sampler_t* s, 
    int max_str_len, unsigned long now_tsc)
{
    assert(s && s->ops && s->ops->sample_to_str);

    /* check if it is time and wait for a lock */
    do {
        if (now_tsc <= s->next_dump_tsc)
            return;
        cpu_relax();
    } while(!spin_try_lock(&s->lock));

    /* dump samples */
    __dump_samples_update_tsc(s, max_str_len, now_tsc);
    
    /* ensure next_dump_tsc updated */
    log_debug("next_dump_tsc %lu, now_tsc %lu", s->next_dump_tsc, now_tsc);
    assert(now_tsc < s->next_dump_tsc);
    spin_unlock(&s->lock);
}

/**
 * Dump samples collected since last time to the file
 */
static inline void sampler_dump(sampler_t* s, int max_str_len)
{
    sampler_dump_provide_tsc(s, max_str_len, rdtsc());
}