/* uti.h COPYRIGHT FUJITSU LIMITED 2019 */
#ifndef __UTIL_H_INCLUDED__
#define __UTIL_H_INCLUDED__

#define __NR_util_migrate_inter_kernel	730

#define __NR_util_indicate_clone	731
#define SPAWN_TO_LOCAL	0
#define SPAWN_TO_REMOTE	1

#define __NR_get_system			732

static inline void cpu_pause(void)
{
	asm volatile("yield" ::: "memory");
}

static inline void FIXED_SIZE_WORK(unsigned long *ptr)
{
	asm volatile("mov %x0, x20\n"
		     "add x20, x20, #1\n"
		     "mov x20, %x0\n"
		     : "+rm" (*ptr)
		     :
		     : "x20", "cc", "memory");
}

#endif /* !__UTIL_H_INCLUDED__ */
