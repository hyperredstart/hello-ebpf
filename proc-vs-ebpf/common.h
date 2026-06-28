#ifndef __COMMON_H
#define __COMMON_H

/* Shared layout between the eBPF (kernel) side and the user-space collectors.
 * Both collectors snapshot the SAME thing — per-CPU kernel CPU times — so the
 * comparison is "same metric, same machine, same interval". We deliberately use
 * plain `unsigned long long` / `unsigned int` (not __u64) so this one header
 * compiles identically under vmlinux.h (BPF) and glibc (user space). */

#define MAX_CPUS 128

/* The CPU-time columns we snapshot, mirroring the first fields of a
 * /proc/stat `cpuN` line. (eBPF reports nanoseconds; /proc reports USER_HZ
 * ticks — irrelevant to this benchmark, which measures *collection overhead*,
 * not metric values.) */
enum { ST_USER, ST_NICE, ST_SYSTEM, ST_IDLE, ST_IOWAIT, NR_FIELDS };

struct cpu_sample {
	unsigned long long ts_ns;                 /* when this snapshot was taken */
	unsigned int       nr_cpus;               /* how many cpu[] rows are valid */
	unsigned long long kern_ns;               /* cumulative softirq ns spent in the BPF timer callback */
	unsigned long long cpu[MAX_CPUS][NR_FIELDS];
};

#endif /* __COMMON_H */
