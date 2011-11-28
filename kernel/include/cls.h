#ifndef __HEADER_CLS_H
#define __HEADER_CLS_H

#include <process.h>
#include <syscall.h>
/*
 * CPU Local Storage (cls)
 */

struct malloc_header {
	struct malloc_header *next;
	unsigned long size;
};

struct cpu_local_var {
	/* malloc */
	struct malloc_header free_list;

	struct process idle;

	struct process *current;
	struct process *next;

	struct aal_ikc_channel_desc *syscall_channel;

	struct syscall_params scp;
	struct ikc_scd_init_param iip;
} __attribute__((aligned(64)));


struct cpu_local_var *get_cpu_local_var(int id);
static struct cpu_local_var *get_this_cpu_local_var(void)
{
	return get_cpu_local_var(aal_mc_get_processor_id());
}

#define cpu_local_var(name) get_this_cpu_local_var()->name

#endif
