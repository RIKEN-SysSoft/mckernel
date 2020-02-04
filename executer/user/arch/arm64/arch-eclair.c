/* arch-eclair.c COPYRIGHT FUJITSU LIMITED 2016-2018 */
#include <stdio.h>
#include <eclair.h>
#include <arch-eclair.h>
#include <sys/ioctl.h>
#include <ihk/ihk_host_user.h>

int print_kregs(char *rbp, size_t rbp_size, const struct arch_kregs *kregs)
{
	int i, ret, total = 0;
	uint32_t pstate;
	const unsigned long *regs[] = {&kregs->x19, &kregs->x20, &kregs->x21,
				       &kregs->x22, &kregs->x23, &kregs->x24,
				       &kregs->x25, &kregs->x26, &kregs->x27,
				       &kregs->x28};

	for (i = 0; i <= 18; i++)	/* x0-x18 */{
		ret = snprintf(rbp, rbp_size, "xxxxxxxxxxxxxxxx");
		if (ret < 0) {
			return ret;
		}
		rbp += ret;
		total += ret;
		rbp_size -= ret;
	}

	for (i = 0; i < sizeof(regs)/sizeof(regs[0]); i++) {	/* x19-x28 */
		ret = print_bin(rbp, rbp_size, (void *)regs[i], sizeof(*regs[0]));
		if (ret < 0) {
			return ret;
		}
		rbp += ret;
		total += ret;
		rbp_size -= ret;
	}

	// X29 FP
	ret = print_bin(rbp, rbp_size, (void *)&kregs->fp, sizeof(kregs->fp));
	if (ret < 0) {
		return ret;
	}
	total += ret;
	dprintf("%s: FP: %s, kregs->fp: 0x%lx\n", __func__, rbp, kregs->fp);
	rbp += ret;
	rbp_size -= ret;

	// x30 LR
	for (i = 0; i < 1; i++)	{
		ret = snprintf(rbp, rbp_size, "xxxxxxxxxxxxxxxx");
		if (ret < 0) {
			return ret;
		}
		rbp += ret;
		total += ret;
		rbp_size -= ret;
	}

	// X31 SP
	ret = print_bin(rbp, rbp_size, (void *)&kregs->sp, sizeof(kregs->sp));
	if (ret < 0) {
		return ret;
	}
	total += ret;
	dprintf("%s: SP: %s, kregs->sp: 0x%lx\n", __func__, rbp, kregs->sp);
	rbp += ret;
	rbp_size -= ret;

	// X32 PC
	ret = print_bin(rbp, rbp_size, (void *)&kregs->pc, sizeof(kregs->pc));
	if (ret < 0) {
		return ret;
	}
	total += ret;
	dprintf("%s: PC: %s, kregs->pc: 0x%lx\n", __func__, rbp, kregs->pc);
	rbp += ret;
	rbp_size -= ret;

	// PSTATE
#define PSR_MODE_EL1h   0x00000005
	pstate = PSR_MODE_EL1h;
	ret = print_bin(rbp, rbp_size, (void *)&pstate, sizeof(pstate));
	if (ret < 0) {
		return ret;
	}
	total += ret;
	rbp += ret;
	rbp_size -= ret;

	dprintf("%s: total: %d\n", __func__, total);
	return total;
}

uintptr_t virt_to_phys(uintptr_t va)
{
	extern uintptr_t kernel_base;

	if (va >= MAP_ST) {
		return (va - MAP_ST + PHYS_OFFSET);
	}

	if (va >= MAP_KERNEL_START) {
		return (va - MAP_KERNEL_START + kernel_base);
	}

	return NOPHYS;
} /* virt_to_phys() */

int arch_setup_constants(void)
{
	MAP_KERNEL_START = lookup_symbol("_head");
	if (MAP_KERNEL_START == NOSYMBOL) {
		fprintf(stderr, "error: obtaining MAP_KERNEL_START\n");
		return 1;
	}
	printf("arm64 MAP_KERNEL_START 0x%lx\n", MAP_KERNEL_START);

	return 0;
}

/*
 * NOTE: in ARM64, ctx is a pointer to thread_info, in which
 * cpu_context is the real member we are looking for thus an extra
 * indirection is needed.
 */
int arch_read_kregs(unsigned long ctx, struct arch_kregs *kregs)
{
	int error;
	error = read_mem(ctx, &ctx, sizeof(ctx));
	if (error) {
		return error;
	}

	/*
	 * TODO: the 16 below is offsetof(struct thread_info, cpu_context)
	 * add this to debug_constants or move the whole thing over DWARF
	 * based inspection...
	 */
	return read_mem(ctx + 16, kregs, sizeof(*kregs));
}
