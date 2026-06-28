// SPDX-License-Identifier: GPL-2.0
//
// The "old way" for per-process CPU: every interval, scan /proc, and for each
// PID open()/read()/parse /proc/<pid>/stat to pull utime+stime. This is the
// O(number-of-processes) file-I/O + text-parsing pattern that node-exporter /
// cAdvisor pay on every scrape — the cost the eBPF collector avoids.
//
//   ./proc_pids --interval-ms 1000          # prints pid count each second
//   ./proc_pids --interval-ms 1000 --quiet  # collect silently (benchmark mode)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>

static volatile bool exiting;
static void on_signal(int sig) { exiting = true; }

static int all_digits(const char *s)
{
	if (!*s)
		return 0;
	for (; *s; s++)
		if (!isdigit((unsigned char)*s))
			return 0;
	return 1;
}

int main(int argc, char **argv)
{
	unsigned long interval_ms = 1000;
	bool quiet = false;

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
		printf("# /proc per-PID poller: scan /proc/<pid>/stat every %lu ms. Ctrl-C to stop.\n", interval_ms);

	while (!exiting) {
		usleep(interval_ms * 1000);

		DIR *d = opendir("/proc");
		if (!d)
			continue;

		struct dirent *e;
		unsigned long long total = 0;
		int n = 0;
		char path[64], buf[1024];

		while ((e = readdir(d))) {
			if (!all_digits(e->d_name))
				continue;
			snprintf(path, sizeof(path), "/proc/%s/stat", e->d_name);
			int fd = open(path, O_RDONLY);
			if (fd < 0)
				continue;                       /* process may have exited */
			int r = read(fd, buf, sizeof(buf) - 1);
			close(fd);
			if (r <= 0)
				continue;
			buf[r] = '\0';

			/* comm (field 2) can contain spaces/parens — start after the last ')' */
			char *p = strrchr(buf, ')');
			if (!p)
				continue;
			p++;
			unsigned long ut = 0, st = 0;
			/* skip 11 fields (state..cmajflt), then utime, stime (fields 14,15) */
			if (sscanf(p, " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %lu", &ut, &st) == 2) {
				total += ut + st;
				n++;
			}
		}
		closedir(d);

		if (!quiet)
			printf("pids=%d total_jiffies=%llu\n", n, total);
	}
	return 0;
}
