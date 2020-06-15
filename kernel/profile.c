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
#include <ihk/debug.h>

extern char *syscall_name[];

#ifdef PROFILE_ENABLE

//#define DEBUG_PRINT_PROFILE

#ifdef DEBUG_PRINT_PROFILE
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif


char *profile_event_names[] =
{
	"remote_tlb_invalidate",
	"page_fault",
	"page_fault_anon_clr_mem",
	"page_fault_file",
	"page_fault_dev_file",
	"page_fault_file_clr_mem",
	"remote_page_fault",
	"mpol_alloc_missed",
	"mmap_anon_contig_phys",
	"|-------mmap_straight",
	"|---mmap_not_straight",
	"mmap_anon_no_contig_phys",
	"mmap_regular_file",
	"mmap_device_file",
	""
};

mcs_lock_node_t job_profile_lock = { 0 };
struct profile_event *job_profile_events = NULL;
int job_nr_processes = -1;
int job_nr_processes_left = -1;
unsigned long job_elapsed_ts;



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

static void print_profile_events(struct profile_event *profile_events,
	char *full_hdr_fmt,
	char *hdr_prefix,
	int id,
	unsigned long elapsed_ts)
{
	int i;
	unsigned long flags;

	flags = kprintf_lock();
	__kprintf(full_hdr_fmt, id, elapsed_ts / 1000);

	__kprintf("%3s: %5s (%3s,%20s): %6s %7s offl: %6s %7s (%6s)\n",
		"ID", "<num>", "num", "(syscall/event) name", "cnt",
		"cycles", "cnt", "cycles", "perc");

	for (i = 0; i < PROFILE_SYSCALL_MAX; ++i) {
		if (!profile_events[i].cnt &&
				!profile_events[i + PROFILE_SYSCALL_MAX].cnt)
			continue;

		__kprintf("%s: %4d (%3d,%20s): %6u %6luk "
				"offl: %6u %6luk (%2d.%2d%%)\n",
				hdr_prefix,
				id,
				i,
				syscall_name[i],
				profile_events[i].cnt,
				profile_events[i].tsc / 1000,
				profile_events[i + PROFILE_SYSCALL_MAX].cnt,
				profile_events[i + PROFILE_SYSCALL_MAX].tsc /
					1000,
				(profile_events[i].tsc ?
				 profile_events[i].tsc * 100
				 / elapsed_ts : 0),
				(profile_events[i].tsc ?
				 (profile_events[i].tsc * 10000
				  / elapsed_ts) % 100 : 0)
				);
	}

	for (i = PROFILE_EVENT_MIN; i < PROFILE_EVENT_MAX; ++i) {
		if (!profile_events[i].cnt)
			continue;

		__kprintf("%s: %4d (%24s): %6u %6lu\n",
				hdr_prefix,
				id,
				profile_event_names[i - PROFILE_EVENT_MIN],
				profile_events[i].cnt,
				(profile_events[i].tsc /
				 (profile_events[i].cnt ?
				  profile_events[i].cnt : 1))
				,
				(profile_events[i].tsc &&
				 elapsed_ts ?
				 profile_events[i].tsc * 100
				 / elapsed_ts : 0),
				(profile_events[i].tsc &&
				 elapsed_ts ?
				 (profile_events[i].tsc * 10000
				  / elapsed_ts) % 100 : 0)
				);
	}

	kprintf_unlock(flags);
}


void profile_print_thread_stats(struct thread *thread)
{
	if (!thread->profile_events)
		return;

	/* Not yet accumulated period? */
	if (thread->profile_start_ts) {
		thread->profile_elapsed_ts += (rdtsc() -
			thread->profile_start_ts);
	}

	print_profile_events(thread->profile_events,
		"TID: %4d elapsed cycles (excluding idle): %luk\n",
		"TID",
		thread->tid,
		thread->profile_elapsed_ts);
}

void profile_print_proc_stats(struct process *proc)
{
	if (!proc->profile_events || !proc->profile_elapsed_ts)
		return;

	print_profile_events(proc->profile_events,
		"PID: %4d elapsed cycles for all threads (excluding idle): %luk\n",
		"PID",
		proc->pid,
		proc->profile_elapsed_ts);
}

int profile_accumulate_and_print_job_events(struct process *proc)
{
	int i;
	struct mcs_lock_node mcs_node;

	mcs_lock_lock(&job_profile_lock, &mcs_node);

	/* First process? */
	if (job_nr_processes == -1) {
		job_nr_processes = proc->nr_processes;
		job_nr_processes_left = proc->nr_processes;
		job_elapsed_ts = 0;
	}

	--job_nr_processes_left;

	/* Allocate event counters */
	if (!job_profile_events) {

		job_profile_events = kmalloc(sizeof(*job_profile_events) *
				PROFILE_EVENT_MAX, IHK_MC_AP_NOWAIT);

		if (!job_profile_events) {
			kprintf("%s: ERROR: allocating job profile counters\n",
					__FUNCTION__);
			return -ENOMEM;
		}

		memset(job_profile_events, 0,
				sizeof(*job_profile_events) * PROFILE_EVENT_MAX);
	}

	/* Accumulate process */
	for (i = 0; i < PROFILE_EVENT_MAX; ++i) {
		if (!proc->profile_events[i].tsc)
			continue;

		job_profile_events[i].tsc += proc->profile_events[i].tsc;
		job_profile_events[i].cnt += proc->profile_events[i].cnt;
		proc->profile_events[i].tsc = 0;
		proc->profile_events[i].cnt = 0;
	}

	job_elapsed_ts += proc->profile_elapsed_ts;

	/* Last process? */
	if (job_nr_processes_left == 0) {

		print_profile_events(job_profile_events,
			"JOB: (%2d) elapsed cycles for all threads (excluding idle): %luk\n",
			"JOB",
			job_nr_processes,
			job_elapsed_ts);

		/* Reset job process indicators */
		job_nr_processes = -1;
		job_nr_processes_left = -1;
		job_elapsed_ts = 0;

		memset(job_profile_events, 0, sizeof(*job_profile_events) *
			PROFILE_EVENT_MAX);
	}

	mcs_lock_unlock(&job_profile_lock, &mcs_node);

	return 0;
}

void profile_accumulate_events(struct thread *thread,
		struct process *proc)
{
	int i;
	struct mcs_lock_node mcs_node;

	if (!thread->profile_events || !proc->profile_events) return;

	mcs_lock_lock(&proc->profile_lock, &mcs_node);

	for (i = 0; i < PROFILE_EVENT_MAX; ++i) {
		proc->profile_events[i].tsc += thread->profile_events[i].tsc;
		proc->profile_events[i].cnt += thread->profile_events[i].cnt;
		thread->profile_events[i].tsc = 0;
		thread->profile_events[i].cnt = 0;
	}

	proc->profile_elapsed_ts += thread->profile_elapsed_ts;
	if (thread->profile_start_ts) {
		proc->profile_elapsed_ts +=
			(rdtsc() - thread->profile_start_ts);
	}

	mcs_lock_unlock(&proc->profile_lock, &mcs_node);
}

int profile_alloc_events(struct thread *thread)
{
	struct process *proc = thread->proc;
	struct mcs_lock_node mcs_node;

	if (!thread->profile_events) {
		thread->profile_events = kmalloc(sizeof(*thread->profile_events) *
				PROFILE_EVENT_MAX, IHK_MC_AP_NOWAIT);

		if (!thread->profile_events) {
			kprintf("%s: ERROR: allocating thread private profile counters\n",
					__FUNCTION__);
			return -ENOMEM;
		}

		memset(thread->profile_events, 0,
				sizeof(*thread->profile_events) * PROFILE_EVENT_MAX);
	}

	mcs_lock_lock(&proc->profile_lock, &mcs_node);
	if (!proc->profile_events) {
		proc->profile_events = kmalloc(sizeof(*proc->profile_events) *
				PROFILE_EVENT_MAX, IHK_MC_AP_NOWAIT);

		if (!proc->profile_events) {
			kprintf("%s: ERROR: allocating proc private profile counters\n",
					__FUNCTION__);
			mcs_lock_unlock(&proc->profile_lock, &mcs_node);
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

static void profile_clear_process(struct process *proc)
{
	proc->profile_elapsed_ts = 0;
	if (!proc->profile_events) return;

	memset(proc->profile_events, 0,
			sizeof(*proc->profile_events) * PROFILE_EVENT_MAX);
}

static void profile_clear_thread(struct thread *thread)
{
	thread->profile_start_ts = 0;
	thread->profile_elapsed_ts = 0;
	if (!thread->profile_events) return;

	memset(thread->profile_events, 0,
			sizeof(*thread->profile_events) * PROFILE_EVENT_MAX);
}

int do_profile(int flag)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	unsigned long now_ts = rdtsc();

	/* Job level? */
	if (flag & PROF_JOB) {
		dkprintf("%s: JOB %d, flag: 0x%lx\n",
				__FUNCTION__, proc->nr_processes, flag);
		if (flag & PROF_PRINT) {
			struct mcs_rwlock_node lock;
			struct thread *_thread;

			/* Accumulate events from all threads to process level */
			mcs_rwlock_reader_lock_noirq(&proc->threads_lock, &lock);
			list_for_each_entry(_thread, &proc->threads_list,
					siblings_list) {
				profile_accumulate_events(_thread, proc);
			}
			mcs_rwlock_reader_unlock_noirq(&proc->threads_lock, &lock);

			/* Accumulate events to job level */
			return profile_accumulate_and_print_job_events(proc);
		}
	}
	/* Process level? */
	else if (flag & PROF_PROC) {
		struct mcs_rwlock_node lock;
		struct thread *_thread;

		dkprintf("%s: PID %d, flag: 0x%lx\n",
				__FUNCTION__, proc->pid, flag);
		/* Accumulate events from all threads */
		mcs_rwlock_reader_lock_noirq(&proc->threads_lock, &lock);

		list_for_each_entry(_thread, &proc->threads_list,
				siblings_list) {
			if (flag & PROF_PRINT) {
				profile_accumulate_events(_thread, proc);
			}

			if (flag & PROF_CLEAR) {
				profile_clear_thread(_thread);
			}

			if (flag & PROF_ON) {
				_thread->profile = 1;
				if (!_thread->profile_start_ts)
					_thread->profile_start_ts = now_ts;
			}
			else if (flag & PROF_OFF) {
				if (_thread->profile) {
					_thread->profile = 0;
					if (_thread->profile_start_ts) {
						_thread->profile_elapsed_ts +=
							(now_ts - _thread->profile_start_ts);
					}
					_thread->profile_start_ts = 0;
				}
			}
		}

		mcs_rwlock_reader_unlock_noirq(&proc->threads_lock, &lock);

		if (flag & PROF_PRINT) {
			profile_print_proc_stats(proc);
		}

		if (flag & PROF_CLEAR) {
			profile_clear_process(proc);
		}

		/* Make sure future threads profile as well */
		if (flag & PROF_ON) {
			if (!proc->profile) {
				proc->profile = 1;
			}
		}
		else if (flag & PROF_OFF) {
			proc->profile = 0;
		}
	}
	/* Thread level */
	else {
		dkprintf("%s: TID %d, flag: 0x%lx\n",
				__FUNCTION__, thread->tid, flag);
		if (flag & PROF_PRINT) {
			profile_print_thread_stats(thread);
		}

		if (flag & PROF_CLEAR) {
			profile_clear_thread(thread);
			/* If profiling, reset start and elapsed */
			if (thread->profile) {
				thread->profile_start_ts = 0;
				thread->profile_elapsed_ts = 0;
			}
		}

		if (flag & PROF_ON) {
			if (!thread->profile) {
				thread->profile = 1;
				thread->profile_start_ts = now_ts;
			}
		}
		else if (flag & PROF_OFF) {
			if (thread->profile) {
				thread->profile = 0;
				if (thread->profile_start_ts) {
					thread->profile_elapsed_ts +=
						(now_ts - thread->profile_start_ts);
				}
				thread->profile_start_ts = 0;
			}
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
