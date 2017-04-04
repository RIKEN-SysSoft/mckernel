/* xos_sys_common.h COPYRIGHT FUJITSU LIMITED 2017 */

#ifndef _XOS_COMMON_H_
#define _XOS_COMMON_H_

#include <stringify.h>
#include <sysreg.h>
#include <ihk/types.h>

#define XOS_FALSE (0)
#define XOS_TRUE (1)

#define READ_ACCESS  (0)
#define WRITE_ACCESS (1)
#define ACCESS_REG_FUNC(name, reg) \
	static void xos_access_##name(uint8_t flag, uint64_t *reg_value){ \
		if(flag == READ_ACCESS){ \
			__asm__ __volatile__("mrs_s %0," __stringify(reg) "\n\t" \
				:"=&r"(*reg_value)::); \
		} \
		else if(flag == WRITE_ACCESS){ \
			__asm__ __volatile__("msr_s" __stringify(reg) ", %0\n\t" \
				::"r"(*reg_value):); \
		}else{ \
			; \
		}	\
	}

#define XOS_MIDR_EL1		sys_reg(3, 0, 0, 0, 0)
#define XOS_MIDR_EL1_IMPLEMENTER_FJ (0x46)
#define XOS_MIDR_EL1_IMPLEMENTER_MASK (0xFFUL)
#define XOS_MIDR_EL1_IMPLEMENTER_SHIFT (24)
#define XOS_MIDR_EL1_PPNUM_TCHIP (0x1)
#define XOS_MIDR_EL1_PPNUM_MASK (0xFFFUL)
#define XOS_MIDR_EL1_PPNUM_SHIFT (0x4)
ACCESS_REG_FUNC(midr_el1, XOS_MIDR_EL1);

static int xos_is_tchip_arch(void)
{

	uint64_t reg = 0;
	int ret=0, impl=0, part=0;

	xos_access_midr_el1(READ_ACCESS, &reg);

	impl = (reg >> XOS_MIDR_EL1_IMPLEMENTER_SHIFT) & XOS_MIDR_EL1_IMPLEMENTER_MASK;
	part = (reg >> XOS_MIDR_EL1_PPNUM_SHIFT) & XOS_MIDR_EL1_PPNUM_MASK;

	if((impl == XOS_MIDR_EL1_IMPLEMENTER_FJ) && (part == XOS_MIDR_EL1_PPNUM_TCHIP)){
		ret = XOS_TRUE;
	}
	else{
		ret = XOS_FALSE;
	}

	return ret;
}

#endif /* #ifndef _XOS_COMMON_H_ */
