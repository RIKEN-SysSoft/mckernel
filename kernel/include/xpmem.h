/**
 * \file xpmem.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Structures and functions of xpmem
 */
/*
 * HISTORY
 */

#ifndef _XPMEM_H
#define _XPMEM_H

#include <process.h>
#include <ihk/context.h>

#define XPMEM_DEV_PATH  "/dev/xpmem"

extern int xpmem_open(ihk_mc_user_context_t *ctx);
extern int xpmem_remove_process_memory_range(struct process_vm *vm, 
	struct vm_range *vmr);
extern int xpmem_fault_process_memory_range(struct process_vm *vm, 
	struct vm_range *vmr, unsigned long vaddr, uint64_t reason);

#endif /* _XPMEM_H */

