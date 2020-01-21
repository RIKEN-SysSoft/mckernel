#ifndef LTTNG_H
#define LTTNG_H

#include <ihk/types.h>
#include <process.h>

void trace_sched_switch(char *prev_comm,
			int32_t prev_tid, int32_t prev_prio, int64_t prev_state,
			char *next_comm,
			int32_t next_tid, int32_t next_prio);
void trace_entry_futex(uint64_t uaddr, int32_t op, uint32_t val,
		       uint64_t utime, uint64_t uaddr2, uint32_t val3);
void trace_exit_futex(int64_t ret, uint64_t uaddr, uint64_t uaddr2);
void trace_entry_mmap(uint64_t addr, uint64_t len, int32_t prot,
		      int32_t flags, int32_t fd, int64_t offset);
void trace_exit_mmap(uint64_t ret);
void trace_entry_mprotect(uint64_t start, uint64_t len, uint64_t prot);
void trace_exit_mprotect(int64_t ret);
void trace_entry_munmap(uint64_t addr, uint64_t len);
void trace_exit_munmap(int64_t ret);

void lttng_init(void);
void lttng_trace_prepare_directory(void);
int lttng_trace_core_dump(void);

#endif
