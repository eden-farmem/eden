/**
 * sampler.c - low-overhead event sampling
 */

#include "base/sampler.h"

/**
 * Sampler next sample time with poisson sampling
 * (For internal usage)
 */
static inline double __next_poisson_time(double rate, unsigned long randomness)
{
    return -logf(1.0f - ((double)(randomness % UINT64_MAX)) 
        / (double)(UINT64_MAX)) 
        / rate;
}

/**
 * Record a given sample assuming that it is time and the lock is held
 * Find the next sampling time and save it
 */
void __add_sample_update_tsc(sampler_t* s, void* sample,
    unsigned long now_tsc)
{
    int newtail;
    unsigned long next_sample_tsc;
    assert(s && s->ops && s->ops->add_sample);
    assert_spin_lock_held(&s->lock);

    /* update next sample time first so that other threads trying to 
     * do the same can give up and leave */
    next_sample_tsc = 0;
    switch (s->type) {
        case SAMPLER_TYPE_NONE:
            /* no sampling, record everything */
            next_sample_tsc = now_tsc + 1;
            break;
        case SAMPLER_TYPE_UNIFORM:
            next_sample_tsc = now_tsc + 
                (cycles_per_us * 1000000ULL / s->samples_per_sec);
            break;
        case SAMPLER_TYPE_POISSON:
            next_sample_tsc = now_tsc + 
                (__next_poisson_time(s->samples_per_sec, 
                    rand_next(&s->randst)) * 1000000 * cycles_per_us);
            break;
        default:
            BUG();
    }
    assert(next_sample_tsc);
    store_release(&s->next_sample_tsc, next_sample_tsc);

    /* record this sample */
    newtail = (s->sq_tail + 1) % s->max_samples;
    if (newtail == s->sq_head)
        /* queue full */
        return;

    log_debug("adding sample at %lu: head - %d, tail - %d, next: %lu", 
        now_tsc, s->sq_head, s->sq_tail, next_sample_tsc);
    s->sq_tail = newtail;
    s->ops->add_sample(s->samples + newtail * s->sample_size, sample);
}

/**
 * Dump samples collected since last time to the file, assuming that it is time
 * and the lock is held
 * Find the next dump time and save it
 */ 
void __dump_samples_update_tsc(sampler_t* s, int max_str_len, 
    unsigned long now_tsc)
{
    char sbuf[max_str_len];
    int newhead, count;
    assert(s && s->ops && s->ops->sample_to_str);
    assert_spin_lock_held(&s->lock);

    /* update next dump time first so that other threads trying to 
     * do the same can give up and leave */
    s->next_dump_tsc = now_tsc + 
        (cycles_per_us * 1000000ULL / s->dumps_per_sec);
    
    /* dump */
    count = 0;
    log_debug("dumping samples at %lu: head - %d, tail - %d, next: %lu", 
        now_tsc, s->sq_head, s->sq_tail, s->next_dump_tsc);
    while (s->sq_head != s->sq_tail) {
        newhead = (s->sq_head + 1) % s->max_samples;
        s->ops->sample_to_str(s->samples + newhead * s->sample_size,
            sbuf, max_str_len);
        fprintf(s->outfile, "%s\n", sbuf);
        s->sq_head = newhead;
        count++;
    }
    if (count > 0) {
        fflush(s->outfile);
        log_info("dumped %d samples", count);
    }
}

/**
 * Sampler init
 */
void sampler_init(sampler_t* s,   /* sampler instance */
    const char* fname,            /* output file name */
    enum sampler_type stype,      /* sampling type */
    sampler_ops_t* ops,           /* base sampler ops */
    int sample_size,              /* size of each sample object */
    int max_samples,              /* max sample queue entries */
    int samples_per_sec,          /* samples per second */
    int dumps_per_sec,            /* min buffer dump to file every sec */
    bool dump_on_full             /* dump on full queue without waiting */)
{
    s->type = stype;
    s->ops = ops;
    s->sample_size = sample_size;
    s->max_samples = max_samples;
    s->samples_per_sec = samples_per_sec;
    s->dumps_per_sec = dumps_per_sec;
    s->sq_head = s->sq_tail = 0;
    s->next_sample_tsc = 0;
    s->dump_on_full = dump_on_full;

    spin_lock_init(&s->lock);
    rand_seed(&s->randst, time(NULL));

    /* samples storage */
    s->samples = aligned_alloc(CACHE_LINE_SIZE, max_samples * s->sample_size);

    /* create outfile */
    assert(fname);
    s->outfile = fopen(fname, "w");
    BUG_ON(!s->outfile);

    log_info("sampler initialized: %s, type: %d, %d samples/sec, %d max samples,"
        " %d sample size, %d dumps/sec", fname, stype, samples_per_sec,
        max_samples, sample_size, dumps_per_sec);
}

/**
 * Sampler destroy
 */
void sampler_destroy(sampler_t* s)
{
    assert(s->outfile && s->samples);
    fclose(s->outfile);
    free(s->samples);
}