/*
 * fsampler.h - fault sampling (with stacktrace support) for the handler threads
 */

#ifndef __FSAMPLER_H__
#define __FSAMPLER_H__

int fsampler_init(void);
int fsampler_get_sampler();
void fsampler_add_fault_sample(int fsid, int kind, unsigned long addr, pid_t tid);
void fsampler_dump(int fsid);
int fsampler_destroy(void);

#endif  // __FSAMPLER_H__