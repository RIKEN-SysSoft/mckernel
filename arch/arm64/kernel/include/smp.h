/* smp.h COPYRIGHT FUJITSU LIMITED 2015 */
#ifndef __HEADER_ARM64_COMMON_SMP_H
#define __HEADER_ARM64_COMMON_SMP_H

#ifndef __ASSEMBLY__
/*
 * Initial data for bringing up a secondary CPU.
 */
struct secondary_data {
	void *stack;
	unsigned long next_pc;
	unsigned long arg;
};
extern struct secondary_data secondary_data;

#endif /* __ASSEMBLY__ */

/* struct secondary_data offsets */
#define SECONDARY_DATA_STACK	0x00
#define SECONDARY_DATA_NEXT_PC	0x08
#define SECONDARY_DATA_ARG	0x10

#endif /* !__HEADER_ARM64_COMMON_SMP_H */
