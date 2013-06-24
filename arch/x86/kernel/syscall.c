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

/* archtecture-depended syscall handlers */
