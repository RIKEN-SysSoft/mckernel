/**
 * \file kmalloc.h
 *  License details are found in the file LICENSE.
 * \brief
 *  kmalloc and kfree functions
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#ifndef __HEADER_KMALLOC_H
#define __HEADER_KMALLOC_H

#include <ihk/mm.h>
#include <cls.h>

void panic(const char *);
int kprintf(const char *format, ...);

#define kmalloc(size, flag) ({\
void *r = _kmalloc(size, flag, __FILE__, __LINE__);\
if(r == NULL){\
kprintf("kmalloc: out of memory %s:%d no_preempt=%d\n", __FILE__, __LINE__, cpu_local_var(no_preempt)); \
}\
r;\
})
#define kfree(ptr) _kfree(ptr, __FILE__, __LINE__)
#define memcheck(ptr, msg) _memcheck(ptr, msg, __FILE__, __LINE__, 0)
void *_kmalloc(int size, ihk_mc_ap_flag flag, char *file, int line);
void _kfree(void *ptr, char *file, int line);
void *__kmalloc(int size, ihk_mc_ap_flag flag);
void __kfree(void *ptr);

int _memcheck(void *ptr, char *msg, char *file, int line, int free);
int memcheckall();
int freecheck(int runcount);
void kmalloc_consolidate_free_list(void);

#endif
