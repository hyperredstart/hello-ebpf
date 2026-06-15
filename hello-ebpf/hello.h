#ifndef __HELLO_H
#define __HELLO_H

/* Shared between the eBPF (kernel) side and the loader (user) side,
 * so the struct layout is guaranteed identical on both ends. */

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 127

struct event {
	int  pid;
	int  ppid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

#endif /* __HELLO_H */
