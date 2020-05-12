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
int xpmem_update_process_page_table(struct process_vm *vm,
	struct vm_range *vmr);

struct xpmem_attachment {
	ihk_rwspinlock_t at_lock;	/* att lock */
	unsigned long vaddr;	/* starting address of seg attached */
	unsigned long at_vaddr;	/* address where seg is attached */
	size_t at_size;		/* size of seg attachment */
	struct vm_range *at_vmr;	/* vm_range where seg is attachment */
	int flags;	/* att attributes and state */
	ihk_atomic_t refcnt;	/* references to att */
	struct xpmem_access_permit *ap;	/* associated access permit */
	struct list_head att_list;	/* atts linked to access permit */
	struct process_vm *vm;	/* process_vm attached to */
};
#endif /* _XPMEM_H */

