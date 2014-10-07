/**
 * \file cls.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Structure of cpu local variable
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#ifndef __HEADER_CLS_H
#define __HEADER_CLS_H

#include <process.h>
#include <syscall.h>
/*
 * CPU Local Storage (cls)
 */

struct malloc_header {
	unsigned int check;
	unsigned int cpu_id;
	struct malloc_header *next;
	unsigned long size;
};

#include <ihk/lock.h>
#define CPU_STATUS_DISABLE	(0)
#define CPU_STATUS_IDLE		(1)
#define CPU_STATUS_RUNNING	(2)
extern ihk_spinlock_t	cpu_status_lock;

#define CPU_FLAG_NEED_RESCHED	0x1U
#define CPU_FLAG_NEED_MIGRATE	0x2U

struct cpu_local_var {
	/* malloc */
	struct malloc_header free_list;
	ihk_spinlock_t free_list_lock;

	struct process idle;
	struct process_vm idle_vm;

	ihk_spinlock_t runq_lock;
	struct process *current;
	struct list_head runq;
	size_t runq_len;

	struct ihk_ikc_channel_desc *syscall_channel;
	struct syscall_params scp;
	struct ikc_scd_init_param iip;

	struct ihk_ikc_channel_desc *syscall_channel2;
	struct syscall_params scp2;
	struct ikc_scd_init_param iip2;
	
	int status;
	int fs;

	struct list_head pending_free_pages;

	unsigned int flags;

	ihk_spinlock_t migq_lock;
	struct list_head migq;
} __attribute__((aligned(64)));


struct cpu_local_var *get_cpu_local_var(int id);
static struct cpu_local_var *get_this_cpu_local_var(void)
{
	return get_cpu_local_var(ihk_mc_get_processor_id());
}

#define cpu_local_var(name) get_this_cpu_local_var()->name

#endif
