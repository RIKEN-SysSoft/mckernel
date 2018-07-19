/**
 * \file memory.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Convert virtual address from/to physical address.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */
/* memory.h COPYRIGHT FUJITSU LIMITED 2015-2016 */

#ifndef __HEADER_GENERIC_MEMORY_H
#define __HEADER_GENERIC_MEMORY_H

#include <arch-memory.h>

#ifndef KERNEL_PHYS_OFFSET
#define KERNEL_PHYS_OFFSET 0

static unsigned long virt_to_phys(void *v)
{
	return (unsigned long)v - KERNEL_PHYS_OFFSET;
}
static void *phys_to_virt(unsigned long p)
{
	return (void *)(p + KERNEL_PHYS_OFFSET);
}
#endif

struct process_vm;

unsigned long virt_to_phys(void *v);
void *phys_to_virt(unsigned long p);
int copy_from_user(void *dst, const void *src, size_t siz);
int strlen_user(const char *s);
int strcpy_from_user(char *dst, const char *src);
long getlong_user(long *dest, const long *p);
int getint_user(int *dest, const int *p);
int verify_process_vm(struct process_vm *vm,
		const void *usrc, size_t size);
int read_process_vm(struct process_vm *vm, void *kdst, const void *usrc, size_t siz);
int copy_to_user(void *dst, const void *src, size_t siz);
int setlong_user(long *dst, long data);
int setint_user(int *dst, int data);
int write_process_vm(struct process_vm *vm, void *udst, const void *ksrc, size_t siz);
int patch_process_vm(struct process_vm *vm, void *udst, const void *ksrc, size_t siz);
#ifdef POSTK_DEBUG_ARCH_DEP_27
struct thread;
int search_free_space(struct thread *thread, size_t len, intptr_t hint,
		      int pgshift, intptr_t *addrp);
#endif	/* POSTK_DEBUG_ARCH_DEP_27 */

#ifdef POSTK_DEBUG_TEMP_FIX_52 /* supports NUMA for memory area determination */
int is_mckernel_memory(unsigned long phys);
#endif /* POSTK_DEBUG_TEMP_FIX_52 */
void *map_pages_to_user(void *pages, int nr_pages, unsigned long extra_flag);

#endif

