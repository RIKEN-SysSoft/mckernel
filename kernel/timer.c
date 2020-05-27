/**
 * \file timer.c
 * Licence details are found in the file LICENSE.
 *  
 * \brief
 * Simple spinning timer for timeout support in futex.
 *
 * \author Balazs Gerofi  <bgerofi@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2013  The University of Tokyo
 *
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
#include <amemcpy.h>
#include <uio.h>
#include <ihk/lock.h>
#include <ctype.h>
#include <waitq.h>
#include <rlimit.h>
#include <affinity.h>
#include <time.h>
#include <lwk/stddef.h>
#include <futex.h>
#include <bitops.h>
#include <timer.h>
#include <ihk/debug.h>

//#define DEBUG_PRINT_TIMER

#ifdef DEBUG_PRINT_TIMER
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#define LOOP_TIMEOUT 500

struct list_head timers;
ihk_spinlock_t timers_lock;


void init_timers(void)
{
	ihk_mc_spinlock_init(&timers_lock);
	INIT_LIST_HEAD(&timers);
}

uint64_t schedule_timeout(uint64_t timeout)
{
	struct thread *thread = cpu_local_var(current);
	long irqstate;

	/* Spin sleep.. */
	for (;;) {
		int need_schedule;
		struct cpu_local_var *v = get_this_cpu_local_var();
		uint64_t t_s = rdtsc();
		uint64_t t_e;

		irqstate = ihk_mc_spinlock_lock(&thread->spin_sleep_lock);

		/* Woken up by someone? */
		if (thread->spin_sleep == 0) {
			t_e = rdtsc();

			if ((t_e - t_s) < timeout) {
				timeout -= (t_e - t_s);
			}
			else {
				timeout = 1;
			}

			ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);
			break;
		}

		ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);

		/* Give a chance to another thread (if any) in case the core is
		 * oversubscribed, but make sure we will be re-scheduled */
		irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
		need_schedule = v->runq_len > 1 ? 1 : 0;

		if (need_schedule) {
			xchg4(&(cpu_local_var(current)->status), PS_RUNNING);
			ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
			schedule();

			/* Recheck if woken */
			continue;
		}
		else {
			ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
		}

		/* Spin wait */
		while ((rdtsc() - t_s) < LOOP_TIMEOUT) {
			ihk_numa_zero_free_pages(ihk_mc_get_numa_node_by_distance(0));
			cpu_pause();
		}

		/* Time out? */
		if (timeout < LOOP_TIMEOUT) {
			timeout = 0;

			/* We are not sleeping any more */
			irqstate = ihk_mc_spinlock_lock(&thread->spin_sleep_lock);
			thread->spin_sleep = 0;
			ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);

			break;
		}
		else {
			timeout -= LOOP_TIMEOUT;
		}
	}

	return timeout;
}


void wake_timers_loop(void)
{
	unsigned long loop_s;
	struct timer *timer;
	struct timer *timer_next;

	dkprintf("timers thread, entering loop\n");
	for (;;) {
		loop_s = rdtsc();

		while (rdtsc() < (loop_s + LOOP_TIMEOUT)) {
			cpu_pause();
		}

		/* Iterate and decrease timeout for all timers,
		 * wake up if timeout reaches zero. */
		ihk_mc_spinlock_lock_noirq(&timers_lock);
		
		list_for_each_entry_safe(timer, timer_next, &timers, list) {
			
			timer->timeout -= LOOP_TIMEOUT;
			if (timer->timeout < LOOP_TIMEOUT) {
				timer->timeout = 0;
				list_del(&timer->list);

				dkprintf("timers timeout occurred, waking up pid: %d\n", 
						timer->thread->proc->pid);

				waitq_wakeup(&timer->processes);
			}
		}
		
		ihk_mc_spinlock_unlock_noirq(&timers_lock);
	}
}
