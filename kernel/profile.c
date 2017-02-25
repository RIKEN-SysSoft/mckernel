/**
 * \file profile.c
 *  License details are found in the file LICENSE.
 *
 * \brief
 *  Profiler code for various process statistics
 * \author Balazs Gerofi <bgerofi@riken.jp>
 * 	Copyright (C) 2017  RIKEN AICS
 */

/*
 * HISTORY:
 */

#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <cpulocal.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <errno.h>
#include <cls.h>
#include <syscall.h>
#include <page.h>
#include <ihk/lock.h>
#include <ctype.h>
#include <waitq.h>
#include <rlimit.h>
#include <affinity.h>
#include <time.h>
#include <ihk/perfctr.h>
#include <mman.h>
#include <kmalloc.h>
#include <memobj.h>
#include <shm.h>
#include <prio.h>
#include <arch/cpu.h>
#include <limits.h>
#include <march.h>
#include <process.h>

extern char *syscall_name[];

#ifdef PROFILE_ENABLE

char *profile_event_names[] =
{
	"page_fault",
	"mpol_alloc_missed",
	""
};

enum profile_event_type profile_syscall2offload(enum profile_event_type sc)
{
	return (PROFILE_SYSCALL_MAX + sc);
}

void profile_event_add(enum profile_event_type type, uint64_t tsc)
{
	struct profile_event *event = NULL;
	if (!cpu_local_var(current)->profile)
		return;

	if (!cpu_local_var(current)->profile_events) {
		if (profile_alloc_events(cpu_local_var(current)) < 0)
			return;
	}

	if (type < PROFILE_EVENT_MAX) {
		event = &cpu_local_var(current)->profile_events[type];
	}
	else {
		kprintf("%s: WARNING: unknown event type %d\n",
			__FUNCTION__, type);
		return;
	}

	++event->cnt;
	event->tsc += tsc;
}

void profile_print_thread_stats(struct thread *thread)
{
	int i;
	unsigned long flags;

	flags = kprintf_lock();

	for (i = 0; i < PROFILE_SYSCALL_MAX; ++i) {
		if (!thread->profile_events[i].cnt &&
				!thread->profile_events[i + PROFILE_SYSCALL_MAX].cnt) 
			continue;

		__kprintf("TID: %4d (%3d,%20s): %6u %6lukC offl: %6u %6lukC\n",
				thread->tid,
				i,
				syscall_name[i],
				thread->profile_events[i].cnt,
				(thread->profile_events[i].tsc /
				 (thread->profile_events[i].cnt ?
				  thread->profile_events[i].cnt : 1))
				/ 1000,
				thread->profile_events[i + PROFILE_SYSCALL_MAX].cnt,
				(thread->profile_events[i + PROFILE_SYSCALL_MAX].tsc /
				 (thread->profile_events[i + PROFILE_SYSCALL_MAX].cnt ?
				  thread->profile_events[i + PROFILE_SYSCALL_MAX].cnt : 1))
				/ 1000
				);
	}

	for (i = PROFILE_EVENT_MIN; i < PROFILE_EVENT_MAX; ++i) {

		if (!thread->profile_events[i].cnt)
			continue;

		__kprintf("TID: %4d (%3d,%20s): %6u %6lukC \n",
				thread->tid,
				i,
				profile_event_names[i - PROFILE_EVENT_MIN],
				thread->profile_events[i].cnt,
				(thread->profile_events[i].tsc /
				 (thread->profile_events[i].cnt ?
				  thread->profile_events[i].cnt : 1))
				/ 1000);
	}


	kprintf_unlock(flags);
}

void profile_print_proc_stats(struct process *proc)
{
	int i;
	unsigned long flags;

	flags = kprintf_lock();

	for (i = 0; i < PROFILE_SYSCALL_MAX; ++i) {
		if (!proc->profile_events[i].cnt &&
				!proc->profile_events[i + PROFILE_SYSCALL_MAX].cnt) 
			continue;

		__kprintf("PID: %4d (%3d,%20s): %6u %6lukC offl: %6u %6lukC\n",
				proc->pid,
				i,
				syscall_name[i],
				proc->profile_events[i].cnt,
				(proc->profile_events[i].tsc /
				 (proc->profile_events[i].cnt ?
				  proc->profile_events[i].cnt : 1))
				/ 1000,
				proc->profile_events[i + PROFILE_SYSCALL_MAX].cnt,
				(proc->profile_events[i + PROFILE_SYSCALL_MAX].tsc /
				 (proc->profile_events[i + PROFILE_SYSCALL_MAX].cnt ?
				  proc->profile_events[i + PROFILE_SYSCALL_MAX].cnt : 1))
				/ 1000
				);
	}

	for (i = PROFILE_EVENT_MIN; i < PROFILE_EVENT_MAX; ++i) {

		if (!proc->profile_events[i].cnt)
			continue;

		__kprintf("PID: %4d (%3d,%20s): %6u %6lukC \n",
				proc->pid,
				i,
				profile_event_names[i - PROFILE_EVENT_MIN],
				proc->profile_events[i].cnt,
				(proc->profile_events[i].tsc /
				 (proc->profile_events[i].cnt ?
				  proc->profile_events[i].cnt : 1))
				/ 1000);
	}

	kprintf_unlock(flags);
}

void profile_accumulate_events(struct thread *thread,
		struct process *proc)
{
	int i;
	struct mcs_lock_node mcs_node;

	mcs_lock_lock(&proc->profile_lock, &mcs_node);

	for (i = 0; i < PROFILE_EVENT_MAX; ++i) {
		proc->profile_events[i].tsc += thread->profile_events[i].tsc;
		proc->profile_events[i].cnt += thread->profile_events[i].cnt;
	}

	mcs_lock_unlock(&proc->profile_lock, &mcs_node);
}

int profile_alloc_events(struct thread *thread)
{
	struct process *proc = thread->proc;
	struct mcs_lock_node mcs_node;

	thread->profile_events = kmalloc(sizeof(*thread->profile_events) *
			PROFILE_EVENT_MAX, IHK_MC_AP_NOWAIT);

	if (!thread->profile_events) {
		kprintf("%s: ERROR: allocating thread private profile counters\n",
				__FUNCTION__);
		return -ENOMEM;
	}

	memset(thread->profile_events, 0,
			sizeof(*thread->profile_events) * PROFILE_EVENT_MAX);

	mcs_lock_lock(&proc->profile_lock, &mcs_node);
	if (!proc->profile_events) {
		proc->profile_events = kmalloc(sizeof(*proc->profile_events) *
				PROFILE_EVENT_MAX, IHK_MC_AP_NOWAIT);

		if (!proc->profile_events) {
			kprintf("%s: ERROR: allocating proc private profile counters\n",
					__FUNCTION__);
			return -ENOMEM;
		}

		memset(proc->profile_events, 0,
				sizeof(*thread->profile_events) * PROFILE_EVENT_MAX);

	}
	mcs_lock_unlock(&proc->profile_lock, &mcs_node);

	return 0;
}

void profile_dealloc_thread_events(struct thread *thread)
{
	kfree(thread->profile_events);
}

void profile_dealloc_proc_events(struct process *proc)
{
	kfree(proc->profile_events);
}

void static profile_clear_thread(struct thread *thread)
{
	memset(thread->profile_events, 0,
			sizeof(*thread->profile_events) * PROFILE_EVENT_MAX);
}

int do_profile(int flag)
{
	struct thread *thread = cpu_local_var(current);

	/* Process level? */
	if (flag & PROF_PROC) {
		if (flag & PROF_PRINT) {
			profile_print_proc_stats(thread->proc);
		}

		if (flag & PROF_ON) {
			thread->profile = 1;
		}
		else if (flag & PROF_OFF) {
			thread->profile = 0;
		}
	}
	/* Thread level */
	else {
		if (flag & PROF_PRINT) {
			profile_print_thread_stats(thread);
		}

		if (flag & PROF_CLEAR) {
			profile_clear_thread(thread);
		}

		if (flag & PROF_ON) {
			thread->profile = 1;
		}
		else if (flag & PROF_OFF) {
			thread->profile = 0;
		}
	}

	return 0;
}

SYSCALL_DECLARE(profile)
{
	int flag = (int)ihk_mc_syscall_arg0(ctx);
	return do_profile(flag);
}

#endif // PROFILE_ENABLE
