#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

//#include "perftool.h"

#define WORKSIZE (1024 * 1024 * 32)
#define LOOPSIZE 1000000
#define REP 1000

long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		group_fd, flags);
	return ret;
}

long
pe_opener(long group_fd, int mode, int type, unsigned long config)
{
	struct perf_event_attr pe;
	int fd;
	long long perf_hw_cache_id;
	long long perf_hw_cache_op_id;
	long long perf_hw_cache_op_result_id;

	memset(&pe, 0, sizeof(struct perf_event_attr));
	pe.type = type;
	pe.size = sizeof(struct perf_event_attr);
	pe.config = config;
	pe.disabled = 1;
	if (mode & 0x01) {
		// EXCLUDE EVENTS THAT HAPPEN IN USER-SPACE
		pe.exclude_user = 1;
	} else {
		// INCLUDE EVENTS THAT HAPPEN IN USER-SPACE
		pe.exclude_user = 0;
	}
	if (mode & 0x02) {
		// EXCUDE EVENTS THAT HAPPEN IN KERNEL-SPACE
		pe.exclude_kernel = 1;
	} else {
		// INCUDE EVENTS THAT HAPPEN IN KERNEL-SPACE
		pe.exclude_kernel = 0;
	}
	pe.exclude_hv = 1;
	if (group_fd > 0) {
		pe.read_format = PERF_FORMAT_GROUP;
	}

	fd = perf_event_open(&pe, 0, -1, group_fd, 0);

	return fd;
}

long long
hw_cache_build(long long id, long long op_id, long long op_result_id)
{
	return (id) | (op_id << 8) | (op_result_id << 16);
}

void
memory_task()
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

void
calc_task()
{
	int i, j;
	double tmp;

	for (i = 0; i < REP; i++) {
		for (j = 0; j < REP; j++) {
			tmp = drand48() * drand48();
		}
	}
}
