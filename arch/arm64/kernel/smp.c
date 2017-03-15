/* smp.c COPYRIGHT FUJITSU LIMITED 2015 */

#include <thread_info.h>
#include <smp.h>

/*
 * as from 2.5, kernels no longer have an init_tasks structure
 * so we need some other way of telling a new secondary core
 * where to place its SVC stack
 */

/* initialize value for BSP bootup */
/* AP bootup value setup in ihk_mc_boot_cpu() */
struct start_kernel_param;
extern void start_kernel(struct start_kernel_param *param);
extern struct start_kernel_param *ihk_param_head;

struct secondary_data secondary_data = {
	.stack = (char *)&init_thread_info + THREAD_START_SP,
	.next_pc = (uint64_t)start_kernel,
	.arg = (unsigned long)&ihk_param_head
};
