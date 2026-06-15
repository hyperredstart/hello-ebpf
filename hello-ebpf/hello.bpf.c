// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// The kernel side. This tiny program is attached to the execve() tracepoint,
// so it runs every time any process on the machine launches a new program.
// It grabs a few fields and pushes them to user space via a ring buffer.

#include "vmlinux.h"          /* generated from the running kernel's BTF (CO-RE) */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "hello.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* A ring buffer: the modern, low-overhead way to stream events kernel -> user. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task;
	const char *filename;
	struct event *e;

	/* Reserve space in the ring buffer. If it's full, drop this event. */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* pid (upper 32 bits of pid_tgid) */
	e->pid = bpf_get_current_pid_tgid() >> 32;

	/* parent pid — read through kernel pointers using CO-RE (BTF-relocatable) */
	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	/* current process name */
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* execve's 1st argument is the program path (a user-space pointer) */
	filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	/* Hand the event to user space. */
	bpf_ringbuf_submit(e, 0);
	return 0;
}
