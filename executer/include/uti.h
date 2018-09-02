#ifndef UTI_H_INCLUDED
#define UTI_H_INCLUDED

struct syscall_struct {
	int number;
	unsigned long args[6];
	unsigned long ret;
	unsigned long uti_clv; /* copy of a clv in McKernel */
};

/* Variables accessed by mcexec.c and syscall_intercept.c */
struct uti_desc {
	void *wp; /* Syscall arguments list and record of McKernel context and Linux context */
	int mck_tid; /* TODO: Move this out for multiple migrated-to-Linux threads */
	unsigned long key; /* struct task_struct* of mcexec thread, used to search struct host_thread */
	int pid, tid; /* Used as the id of tracee when issuing MCEXEC_UP_TERMINATE_THREAD */
	unsigned long uti_clv; /* copy of McKernel clv */

	int fd; /* /dev/mcosX */
	struct syscall_struct *syscall_param_top; /* stack-pointer of syscall arguments list */
	struct syscall_struct *syscall_param; /* TODO: make it auto variable */
	long syscalls[512], syscalls2[512]; /* Syscall profile counters */
	int start_syscall_intercept; /* Used to sync between mcexec.c and syscall_intercept.c */
};


#endif

