/* cputable.c COPYRIGHT FUJITSU LIMITED 2015 */

#include <cputable.h>

extern unsigned long __cpu_setup(void);
struct cpu_info cpu_table[] = {
	{
		.cpu_id_val	= 0x000f0000,
		.cpu_id_mask	= 0x000f0000,
		.cpu_name	= "AArch64 Processor",
		.cpu_setup	= __cpu_setup,
	},
	{ 0 },
};
