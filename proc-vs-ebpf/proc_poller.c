// SPDX-License-Identifier: GPL-2.0
//
// The "old way": collect the same per-CPU CPU stats by polling /proc/stat.
// Every interval it open()s /proc/stat, read()s the whole thing, and parses
// each `cpuN` line out of text — the syscall round-trips + text serialization
// + user-space parsing the article describes. Same metric, same interval as
// the eBPF collector, so the only thing that differs is the collection cost.
//
//   ./proc_poller --interval-ms 1000           # print busy% each second
//   ./proc_poller --interval-ms 1000 --quiet   # collect silently (benchmark mode)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "common.h"

static volatile bool exiting;
static void on_signal(int sig) { exiting = true; }

/* Read /proc/stat into buf, parse the per-CPU lines into `s`. Returns 0 on ok. */
static int read_proc_stat(struct cpu_sample *s)
{
	char buf[64 * 1024];
	int fd, n;
	char *line, *save;

	fd = open("/proc/stat", O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';

	s->nr_cpus = 0;
	for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		unsigned int c;
		unsigned long long user, nice, sys, idle, iowait;

		/* only the per-CPU lines: "cpu0 ...", "cpu1 ..." (skip the "cpu " total) */
		if (strncmp(line, "cpu", 3) != 0 || line[3] < '0' || line[3] > '9')
			continue;
		if (sscanf(line, "cpu%u %llu %llu %llu %llu %llu",
			   &c, &user, &nice, &sys, &idle, &iowait) != 6)
			continue;
		if (c >= MAX_CPUS)
			continue;
		s->cpu[c][ST_USER]   = user;
		s->cpu[c][ST_NICE]   = nice;
		s->cpu[c][ST_SYSTEM] = sys;
		s->cpu[c][ST_IDLE]   = idle;
		s->cpu[c][ST_IOWAIT] = iowait;
		if (c + 1 > s->nr_cpus)
			s->nr_cpus = c + 1;
	}
	return s->nr_cpus ? 0 : -1;
}

static unsigned long long busy_of(const struct cpu_sample *s, unsigned int c)
{
	return s->cpu[c][ST_USER] + s->cpu[c][ST_NICE] + s->cpu[c][ST_SYSTEM];
}

int main(int argc, char **argv)
{
	unsigned long interval_ms = 1000;
	bool quiet = false;
	struct cpu_sample cur, prev;
	bool have_prev = false;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--interval-ms") && i + 1 < argc)
			interval_ms = strtoul(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--quiet"))
			quiet = true;
		else { fprintf(stderr, "usage: %s [--interval-ms N] [--quiet]\n", argv[0]); return 2; }
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	if (!quiet)
		printf("# /proc poller: read+parse /proc/stat every %lu ms. Ctrl-C to stop.\n", interval_ms);

	while (!exiting) {
		usleep(interval_ms * 1000);

		if (read_proc_stat(&cur) != 0)
			continue;

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
	return 0;
}
