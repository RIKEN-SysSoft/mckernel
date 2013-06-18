/*
 * [x86] syscall.c
 */

#include <ihk/cpu.h>
#include <cls.h>
#include <syscall.h>

//#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#define dkprintf kprintf
#else
#define dkprintf(...)
#endif

/* generate system call handler's prototypes */
#define	SYSCALL_HANDLED(number,name)	extern long sys_##name(int n, ihk_mc_user_context_t *ctx);
#define	SYSCALL_DELEGATED(number,name)
#include <syscall_list.h>
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED

/* generate syscall_table[] */
long (*syscall_table[])(int, ihk_mc_user_context_t *) = {
#define	SYSCALL_HANDLED(number,name)	[number] = &sys_##name,
#define	SYSCALL_DELEGATED(number,name)
#include <syscall_list.h>
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED
};

/* # of elements of syscall_table[] */
long syscall_table_elems = sizeof(syscall_table) / sizeof(syscall_table[0]);

/* generate syscall_name[] */
char *syscall_name[] = {
#define	DECLARATOR(number,name)		[number] = #name,
#define	SYSCALL_HANDLED(number,name)	DECLARATOR(number,sys_##name)
#define	SYSCALL_DELEGATED(number,name)	DECLARATOR(number,sys_##name)
#include <syscall_list.h>
#undef	DECLARATOR
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED
};

/* archtecture-depended syscall handlers */
