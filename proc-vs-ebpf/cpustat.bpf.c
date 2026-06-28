// SPDX-License-Identifier: GPL-2.0
//
// The eBPF (kernel) side — the "BPF timer -> map" gauge pattern from the article.
//
// A BPF timer fires every `interval_ns` *in softirq context* and snapshots the
// kernel's per-CPU CPU times by reading the `kernel_cpustat` percpu variable
// directly in-kernel (this is the same data /proc/stat serializes to text).
// No /proc, no syscalls per file, no text parsing. User space just drains one
// map entry per interval.
//
// Why this matters for the benchmark: the timer runs in softirq, so its CPU is
// NOT charged to the reader process/cgroup. (And bpf_timer callbacks don't update
// run_time_ns/bpf_stats — the kernel calls them directly.) So the callback
// *self-times* with bpf_ktime_get_ns() and accumulates into sample.kern_ns; the
// harness adds that to the reader's CPU. Counting only the reader would undercount
// eBPF. See README + the article ("the trap").
//
// Needs: BTF, bpf_timer (Linux 5.15+), bpf_per_cpu_ptr (5.13+), SEC("syscall")
// (5.14+). Ubuntu 24.04 / kernel 6.8 (the Lima dev VM) is fine.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* vmlinux.h (BTF) doesn't define this; bpf_timer_init() wants the clock id. */
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

char LICENSE[] SEC("license") = "GPL";   /* bpf_per_cpu_ptr + timers are GPL-only */

/* The kernel's per-CPU CPU-time accounting — what /proc/stat is built from. */
extern const struct kernel_cpustat kernel_cpustat __ksym;

/* Set from user space (skeleton rodata) before the program is loaded. */
const volatile __u64 interval_ns = 1000000000ULL;   /* 1s default */

struct timer_val {
	struct bpf_timer t;
};

/* The timer lives in its own map... */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct timer_val);
} timers SEC(".maps");

/* ...and the snapshot the timer writes (and user space reads) lives in another,
 * so the user side never has to know about the opaque bpf_timer layout. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cpu_sample);
} samples SEC(".maps");

/* The timer callback: runs in softirq every interval. */
static int snapshot(void *map, __u32 *key, struct timer_val *tv)
{
	__u64 t0 = bpf_ktime_get_ns();
	const struct kernel_cpustat *kcs;
	struct cpu_sample *s;
	__u32 zero = 0, i;

	s = bpf_map_lookup_elem(&samples, &zero);
	if (!s)
		return 0;

	s->ts_ns = t0;

	/* Written field-by-field with no lock, so user space can observe a torn
	 * snapshot. That's immaterial here: the benchmark measures collection
	 * *cost*, not metric values. (A real collector would use a seqlock.) */

	/* Bounded loop over CPUs; bpf_per_cpu_ptr() returns NULL past the last
	 * online/possible CPU, which is our stop condition. */
	for (i = 0; i < MAX_CPUS; i++) {
		kcs = bpf_per_cpu_ptr(&kernel_cpustat, i);
		if (!kcs)
			break;
		/* kcs is a trusted PTR_TO_BTF_ID from bpf_per_cpu_ptr(); the verifier
		 * relocates these direct reads (CO-RE) — no bpf_probe_read needed. */
		s->cpu[i][ST_USER]   = kcs->cpustat[CPUTIME_USER];
		s->cpu[i][ST_NICE]   = kcs->cpustat[CPUTIME_NICE];
		s->cpu[i][ST_SYSTEM] = kcs->cpustat[CPUTIME_SYSTEM];
		s->cpu[i][ST_IDLE]   = kcs->cpustat[CPUTIME_IDLE];
		s->cpu[i][ST_IOWAIT] = kcs->cpustat[CPUTIME_IOWAIT];
		s->nr_cpus = i + 1;
	}

	/* Self-time this softirq callback so user space can account the kernel-side
	 * cost (bpf_timer callbacks don't update run_time_ns / bpf_stats). */
	s->kern_ns += bpf_ktime_get_ns() - t0;

	/* Re-arm for the next interval. */
	bpf_timer_start(&tv->t, interval_ns, 0);
	return 0;
}

/* User space calls this once (via BPF_PROG_TEST_RUN) to arm the timer. */
SEC("syscall")
int arm(void *ctx)
{
	struct timer_val *tv;
	__u32 zero = 0;

	tv = bpf_map_lookup_elem(&timers, &zero);
	if (!tv)
		return 1;

	bpf_timer_init(&tv->t, &timers, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&tv->t, snapshot);
	bpf_timer_start(&tv->t, interval_ns, 0);
	return 0;
}
