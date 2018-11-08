#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

#define WORKSIZE (1024 * 1024 * 32)
#define LOOPSIZE 1000000
#define REP 1000

int perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		group_fd, flags);

	return ret;
}

void memory_task(void)
{
	char *work = malloc(WORKSIZE);
	char *fromaddr;
	char *toaddr;
	double r;
	int offset;
	int i;

	for (i = 0; i < LOOPSIZE; i++) {
		r = drand48();
		offset = (int)(r * (double)WORKSIZE);
		fromaddr = work + offset;
		r = drand48();
		offset = (int)(r * (double)WORKSIZE);
		toaddr = work + offset;
		*toaddr = *fromaddr;
	}
}

void calc_task(void)
{
	int i, j;
	double tmp;

	for (i = 0; i < REP; i++) {
		for (j = 0; j < REP; j++) {
			tmp = drand48() * drand48();
		}
	}
}
