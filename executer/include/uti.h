#ifndef UTI_H_INCLUDED
#define UTI_H_INCLUDED

struct syscall_struct {
	int number;
	unsigned long args[6];
	unsigned long ret;
	unsigned long uti_info; /* reference to data in McKernel */
};

#define UTI_SZ_SYSCALL_STACK 16

/* Variables accessed by mcexec.c and syscall_intercept.c */
struct uti_desc {
	char lctx[4096]; /* TODO: Get the size from config.h */
	char rctx[4096]; /* TODO: Get the size from config.h */
	int mck_tid; /* TODO: Move this out for multiple migrated-to-Linux threads */
	unsigned long key; /* struct task_struct* of mcexec thread, used to search struct host_thread */
	int pid, tid; /* Used as the id of tracee when issuing MCEXEC_UP_TERMINATE_THREAD */
	unsigned long uti_info; /* reference to data in McKernel */

	int fd; /* /dev/mcosX */
	struct syscall_struct syscall_stack[UTI_SZ_SYSCALL_STACK]; /* stack of system call arguments and return values */
	int syscall_stack_top; /* stack-pointer of syscall arguments list */
	long syscalls[512], syscalls2[512]; /* Syscall profile counters */
	int start_syscall_intercept; /* Used to sync between mcexec.c and syscall_intercept.c */
};

/* Reference to McKernel variables accessed by mcctrl */
struct uti_info {
	/* clv info */
	void *thread;
	void *uti_futex_resp;
	void *ikc2linux;

	/* thread info */
	int tid;
	int cpu;
	void *status;
	void *spin_sleep_lock;
	void *spin_sleep;
	void *vm;
	void *futex_q;

	/* global info */
	void *futex_queue;
	void *os;              // set by mcctrl
	int mc_idle_halt;
};
#endif

