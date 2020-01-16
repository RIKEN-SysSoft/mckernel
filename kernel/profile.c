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

#define PERF_SAMPLING_BUFFER_ENTRIES (1024*1024)
#define PERF_SAMPLING_BUFFER_SIZE \
	(PERF_SAMPLING_BUFFER_ENTRIES*sizeof(unsigned long long))
#define PERF_SAMPLING_BUFFER_PAGES \
	((PERF_SAMPLING_BUFFER_SIZE + 4095) >> PAGE_SHIFT)


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

void profile_print_thread_stats(struct thread *thread)
{
	int i;
	unsigned long flags;

	if (!thread->profile_events)
		return;

	/* Not yet accumulated period? */
	if (thread->profile_start_ts) {
		thread->profile_elapsed_ts += (rdtsc() - thread->profile_start_ts);
	}

	flags = kprintf_lock();

	__kprintf("TID: %4d elapsed cycles (excluding idle): %luk\n",
			thread->tid,
			thread->profile_elapsed_ts / 1000);

	for (i = 0; i < PROFILE_SYSCALL_MAX; ++i) {
		if (!thread->profile_events[i].cnt &&
				!thread->profile_events[i + PROFILE_SYSCALL_MAX].cnt)
			continue;

		__kprintf("TID: %4d (%3d,%20s): %6u %6luk offl: %6u %6luk (%2d.%2d%%)\n",
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
				/ 1000,
				 (thread->profile_events[i].tsc ?
				  thread->profile_events[i].tsc * 100
				  / thread->profile_elapsed_ts : 0),
				 (thread->profile_events[i].tsc ?
				  (thread->profile_events[i].tsc * 10000
				  / thread->profile_elapsed_ts) % 100 : 0)
				);
	}

	for (i = PROFILE_EVENT_MIN; i < PROFILE_EVENT_MAX; ++i) {

		if (!thread->profile_events[i].cnt)
			continue;

		__kprintf("TID: %4d (%24s): %6u %6luk \n",
				thread->tid,
				profile_event_names[i - PROFILE_EVENT_MIN],
				thread->profile_events[i].cnt,
				(thread->profile_events[i].tsc /
				 (thread->profile_events[i].cnt ?
				  thread->profile_events[i].cnt : 1))
				/ 1000,
				(thread->profile_events[i].tsc ?
				 thread->profile_events[i].tsc * 100
				 / thread->profile_elapsed_ts : 0),
				(thread->profile_events[i].tsc ?
				 (thread->profile_events[i].tsc * 10000
				  / thread->profile_elapsed_ts) % 100 : 0)
				);
	}


	kprintf_unlock(flags);
}

void profile_print_proc_stats(struct process *proc)
{
	int i;
	unsigned long flags;

	if (!proc->profile_events || !proc->profile_elapsed_ts)
		return;

	flags = kprintf_lock();
	__kprintf("PID: %4d elapsed cycles for all threads (excluding idle): %luk\n",
			proc->pid,
			proc->profile_elapsed_ts / 1000);

	for (i = 0; i < PROFILE_SYSCALL_MAX; ++i) {
		if (!proc->profile_events[i].cnt &&
				!proc->profile_events[i + PROFILE_SYSCALL_MAX].cnt)
			continue;

		__kprintf("PID: %4d (%3d,%20s): %6u %6luk offl: %6u %6luk (%2d.%2d%%)\n",
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
				/ 1000,
				(proc->profile_events[i].tsc ?
				 proc->profile_events[i].tsc * 100
				 / proc->profile_elapsed_ts : 0),
				(proc->profile_events[i].tsc ?
				 (proc->profile_events[i].tsc * 10000
				  / proc->profile_elapsed_ts) % 100 : 0)
				);
	}

	for (i = PROFILE_EVENT_MIN; i < PROFILE_EVENT_MAX; ++i) {

		if (!proc->profile_events[i].cnt)
			continue;

//		__kprintf("PID: %4d (%24s): %6u %6luk \n",
		__kprintf("PID: %4d (%24s): %6u %6lu \n",
				proc->pid,
				profile_event_names[i - PROFILE_EVENT_MIN],
				proc->profile_events[i].cnt,
				(proc->profile_events[i].tsc /
				 (proc->profile_events[i].cnt ?
				  proc->profile_events[i].cnt : 1))
//				/ 1000
				,
				(proc->profile_events[i].tsc &&
				 proc->profile_elapsed_ts ?
				 proc->profile_events[i].tsc * 100
				 / proc->profile_elapsed_ts : 0),
				(proc->profile_events[i].tsc &&
				 proc->profile_elapsed_ts ?
				 (proc->profile_events[i].tsc * 10000
				  / proc->profile_elapsed_ts) % 100 : 0)
				);
	}

	kprintf_unlock(flags);
}

int profile_accumulate_and_print_job_events(struct process *proc)
{
	int i;
	unsigned long flags;
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
		flags = kprintf_lock();
		__kprintf("JOB: (%2d) elapsed cycles for all threads (excluding idle): %luk\n",
				job_nr_processes,
				job_elapsed_ts / 1000);

		for (i = 0; i < PROFILE_SYSCALL_MAX; ++i) {
			if (!job_profile_events[i].cnt &&
					!job_profile_events[i + PROFILE_SYSCALL_MAX].cnt)
				continue;

			__kprintf("JOB: (%2d) (%3d,%20s): %6u %6luk offl: %6u %6luk (%2d.%2d%%)\n",
					job_nr_processes,
					i,
					syscall_name[i],
					job_profile_events[i].cnt,
					(job_profile_events[i].tsc /
					 (job_profile_events[i].cnt ?
					  job_profile_events[i].cnt : 1))
					/ 1000,
					job_profile_events[i + PROFILE_SYSCALL_MAX].cnt,
					(job_profile_events[i + PROFILE_SYSCALL_MAX].tsc /
					 (job_profile_events[i + PROFILE_SYSCALL_MAX].cnt ?
					  job_profile_events[i + PROFILE_SYSCALL_MAX].cnt : 1))
					/ 1000,
					(job_profile_events[i].tsc ?
					 job_profile_events[i].tsc * 100
					 / job_elapsed_ts : 0),
					(job_profile_events[i].tsc ?
					 (job_profile_events[i].tsc * 10000
					  / job_elapsed_ts) % 100 : 0)
					);

			job_profile_events[i].tsc = 0;
			job_profile_events[i].cnt = 0;
			job_profile_events[i + PROFILE_SYSCALL_MAX].tsc = 0;
			job_profile_events[i + PROFILE_SYSCALL_MAX].cnt = 0;
		}

		for (i = PROFILE_EVENT_MIN; i < PROFILE_EVENT_MAX; ++i) {

			if (!job_profile_events[i].cnt)
				continue;

			__kprintf("JOB: (%2d) (%24s): %6u %6luk \n",
					job_nr_processes,
					profile_event_names[i - PROFILE_EVENT_MIN],
					job_profile_events[i].cnt,
					(job_profile_events[i].tsc /
					 (job_profile_events[i].cnt ?
					  job_profile_events[i].cnt : 1))
					/ 1000);

			job_profile_events[i].tsc = 0;
			job_profile_events[i].cnt = 0;
		}

		kprintf_unlock(flags);

		/* Reset job process indicators */
		job_nr_processes = -1;
		job_nr_processes_left = -1;
		job_elapsed_ts = 0;
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

int alloc_perf_sampling_buffer(struct perf_sampling *ps)
{
	int p2align = PAGE_P2ALIGN;

	ps->nentries = PERF_SAMPLING_BUFFER_ENTRIES;
	ps->size = PERF_SAMPLING_BUFFER_SIZE;
	ps->len = 0;

	kprintf("perf: allocating buffer\n");
	ps->buffer = ihk_mc_alloc_aligned_pages(PERF_SAMPLING_BUFFER_PAGES,
						p2align, IHK_MC_AP_NOWAIT);
	if (!ps->buffer) {
		kprintf("Error: Cannot allocate PEBS buffer\n");
		return -ENOMEM;
	}
	kprintf("perf: memsetting buffer\n");
	memset((void *)ps->buffer, 0, ps->size);

	return 0;
}

void print_perf_sampling(struct perf_sampling *ps)
{
	size_t i, j, slen;

	kprintf("perf: printing buffer\n");

	for (i = 0; i < ps->len;) {
		slen = ps->buffer[i];
		kprintf("\n");
		i++;
		for (j = 0; j < slen; j++, i++) {
			kprintf(" %#16lx\n", ps->buffer[i]);
		}
	}
}

void dump_perf_sampling(void)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	ihk_mc_user_context_t ctx1, ctx2;
	int fd;
	int status;
	struct perf_sampling *ps;
	char *exec = "mcexec";
	unsigned long long *usr_buf = 0;
	unsigned long long *krn_fn_buf = 0, *usr_fn_buf = 0;
	int p2align = PAGE_P2ALIGN;
	int i;
	int ret;

	kprintf("allocating perf filename buffer\n");
	krn_fn_buf = ihk_mc_alloc_aligned_pages(1, p2align, IHK_MC_AP_NOWAIT);
	if (krn_fn_buf == 0) {
		kprintf("Cannot allocate filename perf buffer\n");
		return;
	}

	kprintf("maping to user\n");
	usr_fn_buf = map_pages_to_user(krn_fn_buf, 1, VR_REMOTE);
	if (usr_fn_buf == NULL) {
		kprintf("%s: error: mapping PEBS buffer\n", __func__);
		goto free_fn_buf;
	}

	if (proc->saved_cmdline) {
		exec = strrchr(proc->saved_cmdline, '/');
		if (exec) {
			/* Point after '/' */
			++exec;
		}
		else {
			exec = proc->saved_cmdline;
		}
	}

	kprintf("writing to kernel buffer\n");
	snprintf((char *) krn_fn_buf, PATH_MAX, "%s-PERF-sampling.dat", exec);

	// TODO: move me to some more appropriate place
#define O_RDWR		00000002
#define O_CREAT		00000100
#define O_TRUNC		00001000

	ihk_mc_syscall_arg0(&ctx1) = (intptr_t)usr_fn_buf;
	ihk_mc_syscall_arg1(&ctx1) = O_RDWR | O_CREAT | O_TRUNC;
	ihk_mc_syscall_arg2(&ctx1) = 00600;

	kprintf("trying to open the file: %s\n", krn_fn_buf);
	fd = syscall_generic_forwarding(__NR_open, &ctx1);
	if (fd < 0) {
		kprintf("Can't open PEBS out file: %s, fd = %d",
			krn_fn_buf, fd);
		fd = 0;
		goto unmap_fn_usrbuf;
	}

	for_each_set_bit(i, (unsigned long *)&proc->cpu_set,
			 sizeof(proc->cpu_set) * BITS_PER_BYTE) {

		ps = &get_cpu_local_var(i)->perf_sampling;

		kprintf("perf sample dump of cpu %d: %s\n", i,
			(ps->buffer) ? "proceed" : "skip");

		if (!ps->buffer)
			continue;

		kprintf("mapping to user space\n");
		usr_buf = map_pages_to_user(ps->buffer,
					    PERF_SAMPLING_BUFFER_PAGES,
					    VR_REMOTE);
		if (usr_buf == NULL) {
			kprintf("%s: error: mapping PERF buffer\n", __func__);
			goto close;
		}

		kprintf("writing %lu perf buffer entries (%lu bytes) of cpu %d to file\n",
			ps->len, ps->len*sizeof(unsigned long long), i);
		ret = forward_write(fd, usr_buf,
				    ps->len*sizeof(unsigned long long));
		if (ret) {
			kprintf("%s: error: writing pebs buffer\n", __func__);
			ret = do_munmap((void *)usr_buf,
					PERF_SAMPLING_BUFFER_SIZE, 0);
			if (ret)
				kprintf("%s:error: unmaping PERF user buffer\n",
					__func__);
			goto close;
		}

		//kprintf("unmap user map\n");
		//ret = do_munmap((void *)usr_buf,
		//		PERF_SAMPLING_BUFFER_SIZE, 0)
		//if (ret) {
		//	kprintf("%s:error: unmaping PERF user buffer\n",
		//		__func__);
		//	goto close;
		//}
	}

close:
	kprintf("closing the file!\n");
	ihk_mc_syscall_arg0(&ctx2) = fd;
	status = syscall_generic_forwarding(__NR_close, &ctx2);
	if (status < 0) {
		kprintf("Can't close PERF out file. fd = %d", status);
	}

unmap_fn_usrbuf:
	kprintf("unmap filename kernel buffer\n");
	if (do_munmap((void *)usr_fn_buf, 4096, 0))
		kprintf("%s:error: unmaping PEBS user buffer\n", __func__);

free_fn_buf:
	kprintf("free filename user buffer\n");
	ihk_mc_free_pages(krn_fn_buf, 1);
}

int perf_sampling_smp_handler(int cpu_index, int nr_cpus, void *arg)
{
	int flag = *((int *) arg);
	int ret;
	struct perf_sampling *ps;

	ps = &cpu_local_var(perf_sampling);

	if (flag & PROF_ON) {
		kprintf("in cpu %d prof sample on!\n", cpu_index);

		if (ps->buffer == NULL) {
			ret = alloc_perf_sampling_buffer(ps);
			if (ret)
				return ret;
		}

		timer_enable(TIMER_PERF, 1000000);
	}
	if (flag & PROF_OFF) {
		kprintf("in cpu %d prof sample off!\n", cpu_index);

		timer_disable(TIMER_PERF);
	}

	return 0;
}

int do_profile(int flag)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	unsigned long now_ts = rdtsc();

	kprintf("in do_profile! %x\n", flag);

	/* Job level? */
	if (flag & PROF_JOB) {
		dkprintf("%s: JOB %d, flag: 0x%lx\n",
				__FUNCTION__, proc->nr_processes, flag);
		if (flag & PROF_SAMPLE) {
			kprintf("in prof sample!\n");

			// TODO this needs to be properly integrated with the
			// timer used in oversubscription. Right now it is just
			// assuming that the sched timer does not exists. Also
			// look at the handle_interrupt function

			if (flag & (PROF_ON | PROF_OFF)) {
				if (smp_call_func(&proc->cpu_set,
						    perf_sampling_smp_handler,
						    &flag)) {
					kprintf("Error: enable/disable perf sampling\n");
				}
				kprintf("perf buffer allocation done!\n");

			}

			if (flag & PROF_PRINT) {
				kprintf("in prof sample print!\n");
				//print_perf_sampling(ps);
				dump_perf_sampling();
			}

		} else if (flag & PROF_PRINT) {
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
				thread->profile_start_ts = 0;
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
