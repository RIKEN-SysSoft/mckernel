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

struct kmalloc_header {
	unsigned int front_magic;
	unsigned int cpu_id;
	struct list_head list;
	int size; /* The size of this chunk without the header */
	unsigned int end_magic;
	/* 32 bytes */
};

#include <ihk/lock.h>
#define CPU_STATUS_DISABLE	(0)
#define CPU_STATUS_IDLE		(1)
#define CPU_STATUS_RUNNING	(2)
#define CPU_STATUS_RESERVED	(3)
extern ihk_spinlock_t	cpu_status_lock;

#define CPU_FLAG_NEED_RESCHED	0x1U
#define CPU_FLAG_NEED_MIGRATE	0x2U

typedef int (*smp_func_t)(int cpu_index, int nr_cpus, void *arg);
int smp_call_func(cpu_set_t *__cpu_set, smp_func_t __func, void *__arg);

struct smp_func_call_data {
	/* XXX: Sync MCS lock to avoid contention on counter */
	// mcs_lock_node_t lock;
	int nr_cpus;
	ihk_atomic_t cpus_left;

	smp_func_t func;
	void *arg;
};

struct smp_func_call_request {
	struct smp_func_call_data *sfcd;
	int cpu_index;
	int ret;
	struct list_head list;
};

struct cpu_local_var {
	/* malloc */
	struct list_head free_list;
	struct list_head remote_free_list;
	ihk_spinlock_t remote_free_list_lock;

	struct thread idle;
	struct process idle_proc;
	struct process_vm idle_vm;
	struct address_space idle_asp;

	ihk_spinlock_t runq_lock;
	unsigned long runq_irqstate;
	struct thread *current;
	struct list_head runq;
	size_t runq_len;

	struct ihk_ikc_channel_desc *ikc2linux;

	struct resource_set *resource_set;
	
	int status;
	int fs;

	struct list_head pending_free_pages;

	unsigned int flags;

	ihk_spinlock_t migq_lock;
	struct list_head migq;
	int in_interrupt;
	int no_preempt;
	int timer_enabled;
	int kmalloc_initialized;
	struct ihk_os_cpu_monitor *monitor;

	ihk_spinlock_t smp_func_req_lock;
	struct list_head smp_func_req_list;
} __attribute__((aligned(64)));


struct cpu_local_var *get_cpu_local_var(int id);
static struct cpu_local_var *get_this_cpu_local_var(void)
{
	return get_cpu_local_var(ihk_mc_get_processor_id());
}

#define cpu_local_var(name) get_this_cpu_local_var()->name

#endif
