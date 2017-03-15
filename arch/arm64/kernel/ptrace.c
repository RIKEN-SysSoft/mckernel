/* ptrace.c COPYRIGHT FUJITSU LIMITED 2016 */
#include <errno.h>
#include <debug-monitors.h>
#include <hw_breakpoint.h>
#include <elfcore.h>

/* @ref.impl arch/arm64/kernel/ptrace.c::ptrace_hbp_get_resource_info */
unsigned int ptrace_hbp_get_resource_info(unsigned int note_type)
{
	unsigned char num;
	unsigned int reg = 0;

	switch (note_type) {
	case NT_ARM_HW_BREAK:
		num = hw_breakpoint_slots(TYPE_INST);
		break;
	case NT_ARM_HW_WATCH:
		num = hw_breakpoint_slots(TYPE_DATA);
		break;
	default:
		return -EINVAL;
	}

	reg |= debug_monitors_arch();
	reg <<= 8;
	reg |= num;

	return reg;
}

