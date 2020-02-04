/* eclair.h COPYRIGHT FUJITSU LIMITED 2016 */

#ifndef HEADER_USER_COMMON_ECLAIR_H
#define HEADER_USER_COMMON_ECLAIR_H

#include "config.h"
#include <stdio.h>
#include <inttypes.h>
#include <arch-eclair.h>

extern unsigned long PHYS_OFFSET;
extern unsigned long MAP_KERNEL_START;

/* common */
int read_mem(uintptr_t va, void *buf, size_t size);
#define NOSYMBOL ((uintptr_t)-1)
uintptr_t lookup_symbol(char *name);
int read_mem(uintptr_t va, void *buf, size_t size);
int read_symbol_64(char *name, void *buf);
ssize_t print_bin(char *buf, size_t buf_size, void *data, size_t size);

/* arch depend */
int print_kregs(char *rbp, size_t rbp_size, const struct arch_kregs *kregs);
int arch_read_kregs(unsigned long ctx, struct arch_kregs *kregs);

#define NOPHYS ((uintptr_t)-1)
uintptr_t virt_to_phys(uintptr_t va);

int arch_setup_constants(void);

#endif	/* HEADER_USER_COMMON_ECLAIR_H */
