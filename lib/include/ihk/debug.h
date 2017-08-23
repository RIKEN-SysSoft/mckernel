/* debug.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
/**
 * \file debug.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare types and functions to print debug message (kmsg).
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef IHK_DEBUG_H
#define IHK_DEBUG_H

#include <arch-lock.h>
#include <ihk/memconst.h>
#include <ihk/ihk_debug.h>

#ifdef POSTK_DEBUG_ARCH_DEP_9 /* want to add a static assertion */

/* Force a compilation error if condition is false */
#define STATIC_ASSERT(cond) _STATIC_ASSERT(cond, __LINE__)
#define _STATIC_ASSERT(cond, line) __STATIC_ASSERT(cond, line)
#define __STATIC_ASSERT(cond, line)			\
	static void __static_assert_ ## line (void) {	\
		STATIC_ASSERT_LOCAL(cond);		\
	}

/* Force a compilation error if condition is false */
#define STATIC_ASSERT_LOCAL(cond) ((void)sizeof(struct { int:-!!!(cond); }))

#endif /* POSTK_DEBUG_ARCH_DEP_9 */

extern int kprintf(const char *format, ...);
extern unsigned long kprintf_lock(void);
extern void kprintf_unlock(unsigned long irqflags);
extern int __kprintf(const char *format, ...);

extern void panic(const char *msg);

#endif
