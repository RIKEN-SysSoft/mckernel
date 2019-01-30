/* arch-eclair.c COPYRIGHT FUJITSU LIMITED 2016 */
#include <eclair.h>
#include <stdio.h>
#include <arch-eclair.h>

int print_kregs(char *rbp, size_t rbp_size, const struct arch_kregs *kregs)
{
	int i, ret, total = 0;
	uintptr_t ihk_mc_switch_context = -1;
	const uint64_t *regs_1[] = {&kregs->rsi, &kregs->rdi, &kregs->rbp,
				    &kregs->rsp};
	const uint64_t *regs_2[] = {&kregs->r12, &kregs->r13, &kregs->r14,
				    &kregs->r15};

	ihk_mc_switch_context = lookup_symbol("ihk_mc_switch_context");
	if (0) printf("ihk_mc_switch_context: %lx\n", ihk_mc_switch_context);

	ret = snprintf(rbp, rbp_size, "xxxxxxxxxxxxxxxx");	/* rax */
	if (ret < 0) {
		return ret;
	}
	rbp += ret;
	total += ret;
	rbp_size -= ret;

	ret += print_bin(rbp, rbp_size, (void *)&kregs->rbx, sizeof(uint64_t));	/* rbx */
	if (ret < 0) {
		return ret;
	}
	rbp += ret;
	total += ret;
	rbp_size -= ret;

	for (i = 0; i < 2; i++){	/* rcx, rdx */
		ret = snprintf(rbp, rbp_size, "xxxxxxxxxxxxxxxx");
		if (ret < 0) {
			return ret;
		}
		rbp += ret;
		total += ret;
		rbp_size -= ret;
	}

	for (i = 0; i < sizeof(regs_1)/sizeof(regs_1[0]); i++) {	/* rsi, rdi, rbp, rsp */
		ret = print_bin(rbp, rbp_size, regs_1 + i, sizeof(regs_1[0]));
		if (ret < 0) {
			return ret;
		}
		rbp += ret;
		total += ret;
		rbp_size -= ret;
	}

	for (i = 0; i < 4; i++) {	/* r8-x11 */
		ret = snprintf(rbp, rbp_size, "xxxxxxxxxxxxxxxx");
		if (ret < 0) {
			return ret;
		}
		rbp += ret;
		total += ret;
		rbp_size -= ret;
	}

	for (i = 0; i < sizeof(regs_2)/sizeof(regs_2[0]); i++) {	/* r12-r15 */
		ret = print_bin(rbp, rbp_size, regs_2 + i, sizeof(regs_2[0]));
		if (ret < 0) {
			return ret;
		}
		rbp += ret;
		total += ret;
		rbp_size -= ret;
	}

	ret += print_bin(rbp, rbp_size, (void *)&ihk_mc_switch_context, sizeof(uint64_t));	/* rip */
	if (ret < 0) {
		return ret;
	}
	rbp += ret;
	total += ret;
	rbp_size -= ret;

	ret += print_bin(rbp, rbp_size, (void *)&kregs->rflags, sizeof(uint32_t));	/* rflags */
	if (ret < 0) {
		return ret;
	}
	rbp += ret;
	total += ret;
	rbp_size -= ret;

	for (i = 0; i < 6; i++) {	/* cs, ss, ds, es, fs, gs */
		ret = snprintf(rbp, rbp_size, "xxxxxxxx");
		if (ret < 0) {
			return ret;
		}
		rbp += ret;
		total += ret;
		rbp_size -= ret;
	}

	return total;
}

#ifdef POSTK_DEBUG_ARCH_DEP_34
static uintptr_t virt_to_phys(uintptr_t va)
{
	extern uintptr_t kernel_base;

	if (va >= MAP_KERNEL_START) {
		return va - MAP_KERNEL_START + kernel_base;
	}
	else if (va >= LINUX_PAGE_OFFSET) {
		return va - LINUX_PAGE_OFFSET;
	}
	else if (va >= MAP_FIXED_START) {
		return va - MAP_FIXED_START;
	}
	else if (va >= MAP_ST_START) {
		return va - MAP_ST_START;
	}

	return NOPHYS;
} /* virt_to_phys() */
#endif /* POSTK_DEBUG_ARCH_DEP_34 */

