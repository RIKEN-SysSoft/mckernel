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

#include <ihk/memconst.h>

struct ihk_kmsg_buf {
	int tail;
	int len;
	char str[IHK_KMSG_SIZE - sizeof(int) * 2];
};

extern int kprintf(const char *format, ...);
extern unsigned long kprintf_lock(void);
extern void kprintf_unlock(unsigned long irqflags);
extern int __kprintf(const char *format, ...);

extern void panic(const char *msg);

#endif
