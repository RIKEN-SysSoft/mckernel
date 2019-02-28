/* eclair.h COPYRIGHT FUJITSU LIMITED 2016 */

#ifndef HEADER_USER_COMMON_ECLAIR_H
#define HEADER_USER_COMMON_ECLAIR_H

#include "config.h"
#include <stdio.h>
#include <inttypes.h>
#include <arch-eclair.h>

/* common */
uintptr_t lookup_symbol(char *name);
ssize_t print_bin(char *buf, size_t buf_size, void *data, size_t size);

/* arch depend */
int print_kregs(char *rbp, size_t rbp_size, const struct arch_kregs *kregs);

#define NOPHYS ((uintptr_t)-1)

#endif	/* HEADER_USER_COMMON_ECLAIR_H */
