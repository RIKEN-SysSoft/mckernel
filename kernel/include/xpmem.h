/* xpmem.h COPYRIGHT FUJITSU LIMITED 2017 */
/**
 * \file xpmem.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Structures and functions of xpmem
 * \author Yoichi Umezawa  <yoichi.umezawa.qh@hitachi.com> \par
 * 	Copyright (C) 2016 Yoichi Umezawa
 */
/*
 * HISTORY
 */

#ifndef _XPMEM_H
#define _XPMEM_H

#include <process.h>
#include <ihk/context.h>

#define XPMEM_DEV_PATH  "/dev/xpmem"

int xpmem_open(const char *pathname,
	       int flags, ihk_mc_user_context_t *ctx);
int xpmem_openat(const char *pathname,
		 int flags, ihk_mc_user_context_t *ctx);
int xpmem_remove_process_memory_range(struct process_vm *vm,
	struct vm_range *vmr);
int xpmem_fault_process_memory_range(struct process_vm *vm,
	struct vm_range *vmr, unsigned long vaddr, uint64_t reason);

#endif /* _XPMEM_H */

