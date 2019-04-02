#ifndef __PERFTOOL_H__
#define __PERFTOOL_H__

#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <unistd.h>

extern long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
				  int cpu, int group_fd, unsigned long flags);

extern long perf_instructions(void);
extern long perf_count_hw_cache_l1d_read_miss(void);
extern long perf_count_hw_cache_dtlb_read_miss(void);
extern long pe_opener(long group_fd, int mode, int type, unsigned long config);
extern long long hw_cache_build(long long id, long long op_id,
				long long op_result_id);
extern void memory_task(void);
extern void calc_task(void);

#define PERF_CNTR_NUM 4

#define PERF_BEGIN(fd) do {				\
	if (fd > 0)					\
		ioctl(fd, PERF_EVENT_IOC_RESET, 0);	\
	if (fd > 0)					\
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);	\
} while (0)

#define PERF_END(fd) do {				\
	if (fd > 0)					\
		ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);	\
} while (0)

#define PERF_READ(fd, count) do {				\
	if (fd > 0)						\
		read(fd, &count, sizeof(long long));		\
	else							\
		count = -1;					\
} while (0)

char *hw_event_names[] = {
	"CPU_CYCLES             ",
	"INSTRUCTIONS           ",
	"CACHE_REFERENCES       ",
	"CACHE_MISSES           ",
	"BRANCH_INSTRUCTIONS    ",
	"BRANCH_MISSES          ",
	"BUS_CYCLES             ",
	"STALLED_CYCLES_FRONTEND",
	"STALLED_CYCLES_BACKEND ",
	"REF_CPU_CYCLES         ",
};

char *id_names[] = {
	"L1D ",
	"L1I ",
	"LL  ",
	"DTLB",
	"ITLB",
	"BPU ",
	"NODE",
};

char *op_id_names[] = {
	"OP_READ    ",
	"OP_WRITE   ",
	"OP_PREFETCH",
};

char *result_names[] = {
	"ACCESS",
	"MISS  ",
};

long long ids[] = {
	PERF_COUNT_HW_CACHE_L1D,
	PERF_COUNT_HW_CACHE_L1I,
	PERF_COUNT_HW_CACHE_LL,
	PERF_COUNT_HW_CACHE_DTLB,
	PERF_COUNT_HW_CACHE_ITLB,
	PERF_COUNT_HW_CACHE_BPU,
	PERF_COUNT_HW_CACHE_NODE,
};

long long op_ids[] = {
	PERF_COUNT_HW_CACHE_OP_READ,
	PERF_COUNT_HW_CACHE_OP_WRITE,
	PERF_COUNT_HW_CACHE_OP_PREFETCH,
};

long long result_ids[] = {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS,
	PERF_COUNT_HW_CACHE_RESULT_MISS,
};

int hw_configs[] = {
	PERF_COUNT_HW_CPU_CYCLES,
	PERF_COUNT_HW_INSTRUCTIONS,
	PERF_COUNT_HW_CACHE_REFERENCES,
	PERF_COUNT_HW_CACHE_MISSES,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
	PERF_COUNT_HW_BRANCH_MISSES,
	PERF_COUNT_HW_BUS_CYCLES,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND,
	PERF_COUNT_HW_REF_CPU_CYCLES,
};
#endif
