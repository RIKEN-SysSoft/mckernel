/* cputable.h COPYRIGHT FUJITSU LIMITED 2015 */
#ifndef __HEADER_ARM64_COMMON_CPUTABLE_H
#define __HEADER_ARM64_COMMON_CPUTABLE_H

struct cpu_info {
	unsigned int	cpu_id_val;
	unsigned int	cpu_id_mask;
	const char	*cpu_name;
	unsigned long	(*cpu_setup)(void);
};

#endif /* !__HEADER_ARM64_COMMON_CPUTABLE_H */
