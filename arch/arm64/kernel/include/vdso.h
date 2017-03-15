/* vdso.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef __HEADER_ARM64_COMMON_VDSO_H
#define __HEADER_ARM64_COMMON_VDSO_H

#ifdef __KERNEL__

/* @ref.impl arch/arm64/include/asm/vsdo.h::VDSO_LBASE */
/*
 * Default link address for the vDSO.
 * Since we randomise the VDSO mapping, there's little point in trying
 * to prelink this.
 */
#define VDSO_LBASE	0x0

#ifndef __ASSEMBLY__

#include <vdso-offsets.h>

/* @ref.impl arch/arm64/include/asm/vsdo.h::VDSO_SYMBOL */
#define VDSO_SYMBOL(base, name)		vdso_symbol_##name((unsigned long)(base))
void* vdso_symbol_sigtramp(unsigned long base);

int add_vdso_pages(struct thread *thread);

#endif /* !__ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* !__HEADER_ARM64_COMMON_VDSO_H */

