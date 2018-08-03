#ifndef __PERFTOOL_H__
#define __PERFTOOL_H__

#include <linux/perf_event.h>

int perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
				  int cpu, int group_fd, unsigned long flags);

long long hw_cache_build(long long id, long long op_id, long long op_result_id);
void memory_task(void);
void calc_task(void);

#endif
