// SPDX-License-Identifier: GPL-2.0
//
// User side of the per-PID eBPF collector. sched_switch accumulates per-task
// on-CPU ns in a hash map (task.bpf.c); every interval this drains the map
// (enumerate + sum + clear) — O(active pids) map ops, no per-process file opens.
//
// Kernel-side cost: sched_switch is a tracepoint, so bpf_stats DOES capture it.
// We enable stats and read this program's own run_time_ns via the prog fd, then
// publish it to --kern-ns-file for the harness to add to the reader's CPU.
//
//   sudo ./ebpf_pids --interval-ms 1000          # prints pid count each second
//   sudo ./ebpf_pids --interval-ms 1000 --quiet  # collect silently (benchmark mode)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "task.skel.h"

#define MAX_PIDS 16384

static volatile bool exiting;
static void on_signal(int sig) { exiting = true; }

int main(int argc, char **argv)
{
	unsigned long interval_ms = 1000;
	bool quiet = false;
	const char *kern_ns_file = NULL;
	struct task_bpf *skel = NULL;
	FILE *kf = NULL;
	int sfd = -1, err = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--interval-ms") && i + 1 < argc)
			interval_ms = strtoul(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--quiet"))
			quiet = true;
		else if (!strcmp(argv[i], "--kern-ns-file") && i + 1 < argc)
			kern_ns_file = argv[++i];
		else { fprintf(stderr, "usage: %s [--interval-ms N] [--quiet] [--kern-ns-file PATH]\n", argv[0]); return 2; }
	}

	if (!getenv("PVB_VERBOSE"))
		libbpf_set_print(NULL);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	skel = task_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed (need root? kernel with BTF?)\n"); return 1; }
	if (task_bpf__attach(skel)) { fprintf(stderr, "attach failed (need root?)\n"); err = 1; goto out; }

	/* Keep run-time accounting on for as long as this fd is held. */
	sfd = bpf_enable_stats(BPF_STATS_RUN_TIME);
	if (sfd < 0)
		fprintf(stderr, "warning: bpf_enable_stats failed (%d); kernel ns may read 0\n", sfd);

	int map_fd  = bpf_map__fd(skel->maps.cpu_ns);
	int prog_fd = bpf_program__fd(skel->progs.on_switch);

	if (kern_ns_file) {
		kf = fopen(kern_ns_file, "w");
		if (!kf) fprintf(stderr, "warning: cannot open %s for kern-ns\n", kern_ns_file);
	}
	if (!quiet)
		printf("# eBPF per-PID collector: sched_switch -> hash map every %lu ms. Ctrl-C to stop.\n", interval_ms);

	while (!exiting) {
		usleep(interval_ms * 1000);

		/* Drain the map: enumerate keys, then sum + delete each. */
		__u32 keys[MAX_PIDS]; int n = 0;
		__u32 cur, nk, *pk = NULL;
		while (n < MAX_PIDS && bpf_map_get_next_key(map_fd, pk, &nk) == 0) {
			keys[n++] = nk; cur = nk; pk = &cur;
		}
		unsigned long long total = 0; int alive = 0;
		for (int i = 0; i < n; i++) {
			__u64 v;
			if (bpf_map_lookup_elem(map_fd, &keys[i], &v) == 0) { total += v; alive++; }
			bpf_map_delete_elem(map_fd, &keys[i]);
		}

		/* Publish cumulative kernel-side run_time_ns for the harness. */
		if (kf) {
			struct bpf_prog_info info; __u32 len = sizeof(info);
			unsigned long long kns = 0;
			memset(&info, 0, sizeof(info));
			if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) == 0)
				kns = info.run_time_ns;
			rewind(kf); fprintf(kf, "%llu\n", kns); fflush(kf);
		}

		if (!quiet)
			printf("pids=%d total_oncpu_ms=%.1f\n", alive, (double)total / 1e6);
	}

out:
	if (kf) fclose(kf);
	if (sfd >= 0) close(sfd);
	task_bpf__destroy(skel);
	return err ? 1 : 0;
}
