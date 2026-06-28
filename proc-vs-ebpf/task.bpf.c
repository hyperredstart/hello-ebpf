// SPDX-License-Identifier: GPL-2.0
//
// Per-process on-CPU time, accumulated in-kernel from sched_switch.
//
// This is the eBPF way to do what monitoring agents do by scanning hundreds of
// /proc/<pid>/stat files every scrape: hook the scheduler, and on each context
// switch add the outgoing task's on-CPU nanoseconds to a per-PID hash map. User
// space then drains that map once per interval — no per-process file opens.
//
// Because sched_switch is a *tracepoint*, its CPU IS captured by bpf_stats
// (run_time_ns), unlike a bpf_timer callback. The user-space loader reads that
// and reports it as the kernel-side cost. This program's cost scales with the
// context-switch rate; the /proc poller's scales with the process count.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* per-CPU: timestamp when the currently-running task was scheduled in */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} last_ts SEC(".maps");

/* pid -> cumulative on-CPU ns (drained + cleared by user space each interval) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u64);
} cpu_ns SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int on_switch(struct trace_event_raw_sched_switch *ctx)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 zero = 0;
	__u64 *last = bpf_map_lookup_elem(&last_ts, &zero);

	if (last) {
		if (*last) {
			__u64 dt = now - *last;
			__u32 prev = (__u32)ctx->prev_pid;
			__u64 *acc = bpf_map_lookup_elem(&cpu_ns, &prev);

			if (acc)
				*acc += dt;
			else
				bpf_map_update_elem(&cpu_ns, &prev, &dt, BPF_ANY);
		}
		*last = now;
	}
	return 0;
}
