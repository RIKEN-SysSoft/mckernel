/**
 * \file cls.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Initialization of cpu local variable
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#include <kmsg.h>
#include <string.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <ihk/lock.h>
#include <ihk/mm.h>
#include <ihk/page_alloc.h>
#include <kmalloc.h>
#include <cls.h>
#include <page.h>
#include <rusage_private.h>
#include <ihk/monitor.h>

extern int num_processors;

struct cpu_local_var *clv;
int cpu_local_var_initialized = 0;

void cpu_local_var_init(void)
{
	int z;
	int i;

	z = sizeof(struct cpu_local_var) * num_processors;
	z = (z + PAGE_SIZE - 1) >> PAGE_SHIFT;

	clv = ihk_mc_alloc_pages(z, IHK_MC_AP_CRITICAL);
	memset(clv, 0, z * PAGE_SIZE);

	for (i = 0; i < num_processors; i++) {
		clv[i].monitor = monitor->cpu + i;
		clv[i].rusage = rusage.cpu + i;
		INIT_LIST_HEAD(&clv[i].smp_func_req_list);
		INIT_LIST_HEAD(&clv[i].backlog_list);
#ifdef ENABLE_PER_CPU_ALLOC_CACHE
		clv[i].free_chunks.rb_node = NULL;
#endif
	}

	cpu_local_var_initialized = 1;
	smp_mb();
}

struct cpu_local_var *get_cpu_local_var(int id)
{
	return clv + id;
}

#ifdef ENABLE_FUGAKU_HACKS
void __show_context_stack(struct thread *thread,
        unsigned long pc, uintptr_t sp, int kprintf_locked);
#endif
void preempt_enable(void)
{
#ifndef ENABLE_FUGAKU_HACKS
	if (cpu_local_var_initialized)
		--cpu_local_var(no_preempt);
#else
	if (cpu_local_var_initialized) {
		--cpu_local_var(no_preempt);

		if (cpu_local_var(no_preempt) < 0) {
			//cpu_disable_interrupt();

	__kprintf("%s: %d\n", __func__, cpu_local_var(no_preempt));
    __kprintf("TID: %d, call stack from builtin frame (most recent first):\n",
        cpu_local_var(current)->tid);
	__show_context_stack(cpu_local_var(current), (uintptr_t)&preempt_enable,
			(unsigned long)__builtin_frame_address(0), 1);

			//arch_cpu_stop();
			//cpu_halt();
#ifdef ENABLE_FUGAKU_HACKS
		panic("panic: negative preemption??");
#endif
		}
	}
#endif
}

void preempt_disable(void)
{
	if (cpu_local_var_initialized) {
		++cpu_local_var(no_preempt);
	}
}

int add_backlog(int (*func)(void *arg), void *arg)
{
	struct backlog *bl;
	struct cpu_local_var *v = get_this_cpu_local_var();
	unsigned long irqstate;

	if (!(bl = kmalloc(sizeof(struct backlog), IHK_MC_AP_NOWAIT))) {
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&bl->list);
	bl->func = func;
	bl->arg = arg;
	irqstate = ihk_mc_spinlock_lock(&v->backlog_lock);
	list_add_tail(&bl->list, &v->backlog_list);
	ihk_mc_spinlock_unlock(&v->backlog_lock, irqstate);
	irqstate = ihk_mc_spinlock_lock(&v->runq_lock);
	v->flags |= CPU_FLAG_NEED_RESCHED;
	ihk_mc_spinlock_unlock(&v->runq_lock, irqstate);
	set_timer(0);
	return 0;
}

void do_backlog(void)
{
	unsigned long irqstate;
	struct list_head list;
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct backlog *bl;
	struct backlog *next;

	INIT_LIST_HEAD(&list);
	irqstate = ihk_mc_spinlock_lock(&v->backlog_lock);
	list_for_each_entry_safe(bl, next, &v->backlog_list, list) {
		list_del(&bl->list);
		list_add_tail(&bl->list, &list);
	}
	ihk_mc_spinlock_unlock(&v->backlog_lock, irqstate);

	list_for_each_entry_safe(bl, next, &list, list) {
		list_del(&bl->list);
		if (bl->func(bl->arg)) {
			irqstate = ihk_mc_spinlock_lock(&v->backlog_lock);
			list_add_tail(&bl->list, &v->backlog_list);
			ihk_mc_spinlock_unlock(&v->backlog_lock, irqstate);
		}
		else {
			kfree(bl);
		}
	}
}

#ifdef ENABLE_FUGAKU_HACKS
ihk_spinlock_t *get_this_cpu_runq_lock(void)
{
	return &get_this_cpu_local_var()->runq_lock;
}
#endif
