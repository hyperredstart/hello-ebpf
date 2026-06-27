// SPDX-License-Identifier: GPL-2.0
//
// User side of the eBPF collector. It loads the BPF object, arms the timer,
// then every interval drains the latest snapshot from the `samples` map and
// (unless --quiet) prints aggregate CPU busy %. The kernel does the sampling
// in a softirq timer; this loop is just the cheap "drain the map" half.
//
//   sudo ./ebpf_collector --interval-ms 1000          # print busy% each second
//   sudo ./ebpf_collector --interval-ms 1000 --quiet  # collect silently (benchmark mode)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "cpustat.skel.h"
#include "common.h"

static volatile bool exiting;
static void on_signal(int sig) { exiting = true; }

static unsigned long long busy_of(const struct cpu_sample *s, unsigned int c)
{
	/* everything except idle+iowait counts as "busy" */
	return s->cpu[c][ST_USER] + s->cpu[c][ST_NICE] + s->cpu[c][ST_SYSTEM];
}

int main(int argc, char **argv)
{
	unsigned long interval_ms = 1000;
	bool quiet = false;
	struct cpustat_bpf *skel = NULL;
	struct cpu_sample cur, prev;
	bool have_prev = false;
	__u32 zero = 0;
	int err;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--interval-ms") && i + 1 < argc)
			interval_ms = strtoul(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--quiet"))
			quiet = true;
		else { fprintf(stderr, "usage: %s [--interval-ms N] [--quiet]\n", argv[0]); return 2; }
	}

	libbpf_set_print(NULL);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	skel = cpustat_bpf__open();
	if (!skel) { fprintf(stderr, "open skeleton failed (need root?)\n"); return 1; }

	skel->rodata->interval_ns = (unsigned long long)interval_ms * 1000000ULL;

	err = cpustat_bpf__load(skel);
	if (err) { fprintf(stderr, "load failed: %d (need root? kernel 5.15+ with BTF?)\n", err); goto out; }

	/* Arm the timer by running the SEC("syscall") program once. */
	struct bpf_test_run_opts topts = { .sz = sizeof(topts) };
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.arm), &topts);
	if (err || topts.retval) {
		fprintf(stderr, "arming timer failed: err=%d retval=%u\n", err, topts.retval);
		err = err ? err : -1;
		goto out;
	}

	if (!quiet)
		printf("# eBPF collector: BPF timer -> map every %lu ms. Ctrl-C to stop.\n", interval_ms);

	while (!exiting) {
		usleep(interval_ms * 1000);

		err = bpf_map__lookup_elem(skel->maps.samples, &zero, sizeof(zero),
					   &cur, sizeof(cur), 0);
		if (err) { fprintf(stderr, "map lookup failed: %d\n", err); break; }

		if (have_prev && !quiet) {
			unsigned long long busy = 0, total = 0;
			for (unsigned int c = 0; c < cur.nr_cpus && c < MAX_CPUS; c++) {
				unsigned long long db = busy_of(&cur, c) - busy_of(&prev, c);
				unsigned long long di = (cur.cpu[c][ST_IDLE] + cur.cpu[c][ST_IOWAIT])
						      - (prev.cpu[c][ST_IDLE] + prev.cpu[c][ST_IOWAIT]);
				busy += db; total += db + di;
			}
			printf("cpus=%u busy=%.1f%%\n", cur.nr_cpus,
			       total ? 100.0 * (double)busy / (double)total : 0.0);
		}
		prev = cur;
		have_prev = true;
	}

	err = 0;
out:
	cpustat_bpf__destroy(skel);   /* destroying the map cancels the timer */
	return err ? 1 : 0;
}
