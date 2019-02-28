/* arch-eclair.c COPYRIGHT FUJITSU LIMITED 2016-2018 */
#include <stdio.h>
#include <eclair.h>
#include <arch-eclair.h>

int print_kregs(char *rbp, size_t rbp_size, const struct arch_kregs *kregs)
{
	int i, ret, total = 0;
	const unsigned long *regs[] = {&kregs->x19, &kregs->x20, &kregs->x21,
				       &kregs->x22, &kregs->x23, &kregs->x24,
				       &kregs->x25, &kregs->x26, &kregs->x27,
				       &kregs->x28};

	for (i = 0; i < 18; i++)	/* x0-x18 */{
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

	for (i = 0; i < 2; i++) {	/* x29-x30 */
		ret = snprintf(rbp, rbp_size, "xxxxxxxxxxxxxxxx");
		if (ret < 0) {
			return ret;
		}
		rbp += ret;
		total += ret;
		rbp_size -= ret;
	}

	ret += print_bin(rbp, rbp_size, (void *)&kregs->sp, sizeof(kregs->sp));
	if (ret < 0) {
		return ret;
	}
	total += ret;

	return total;
}

uintptr_t virt_to_phys(uintptr_t va)
{
	extern uintptr_t kernel_base;

	if (va >= MAP_KERNEL) {
		return (va - MAP_KERNEL + kernel_base);
	}

	if (va >= MAP_ST) {
		return (va - MAP_ST);
	}
	return NOPHYS;
} /* virt_to_phys() */

