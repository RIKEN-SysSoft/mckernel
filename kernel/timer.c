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
#include <ihk/debug.h>
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

//#define DEBUG_PRINT_TIMER

#ifdef DEBUG_PRINT_TIMER
#define dkprintf kprintf
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
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
	struct waitq_entry my_wait;
	struct timer my_timer;
	struct thread *thread = cpu_local_var(current);
	int irqstate;
	int spin_sleep;

	irqstate = ihk_mc_spinlock_lock(&thread->spin_sleep_lock);
	dkprintf("schedule_timeout() spin sleep timeout: %lu\n", timeout);
	spin_sleep = ++thread->spin_sleep;
	ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);

	/* Spin sleep.. */
	for (;;) {
		uint64_t t_s = rdtsc();
		uint64_t t_e;
		int spin_over = 0;
		
		irqstate = ihk_mc_spinlock_lock(&thread->spin_sleep_lock);
		
		/* Woken up by someone? */
		if (thread->spin_sleep < 1) {
			t_e = rdtsc();

			spin_over = 1;
			if ((t_e - t_s) < timeout) {
				timeout -= (t_e - t_s);
			}
			else {
				timeout = 1;
			}
		}
		
		ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);

		if (!spin_over) {
			t_s = rdtsc();
			int need_schedule;
			struct cpu_local_var *v = get_this_cpu_local_var();
			int irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
			need_schedule = v->runq_len > 1 ? 1 : 0;
			ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

			/* Give a chance to another thread (if any) in case the core is
			 * oversubscribed, but make sure we will be re-scheduled */
			if (need_schedule) {
				xchg4(&(cpu_local_var(current)->status), PS_RUNNING);
				schedule();
				xchg4(&(cpu_local_var(current)->status), 
						PS_INTERRUPTIBLE);
			}
			else {
				/* Spin wait */
				while ((rdtsc() - t_s) < LOOP_TIMEOUT) {
					cpu_pause();
				}

				if (timeout < LOOP_TIMEOUT) {
					timeout = 0;
					spin_over = 1;
				}
				else {
					timeout -= LOOP_TIMEOUT;
				}
			}
		}
		
		if (spin_over) {
			dkprintf("schedule_timeout() spin woken up, timeout: %lu\n", 
					timeout);
			
			/* Give a chance to another thread (if any) in case we timed out, 
			 * but make sure we will be re-scheduled */
			if (timeout == 0) {
				int need_schedule;
				struct cpu_local_var *v = get_this_cpu_local_var();

				int irqstate = 
					ihk_mc_spinlock_lock(&(v->runq_lock));
				need_schedule = v->runq_len > 1 ? 1 : 0;
				ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

				if (need_schedule) {
					xchg4(&(cpu_local_var(current)->status), PS_RUNNING);
					schedule();
					xchg4(&(cpu_local_var(current)->status), 
							PS_INTERRUPTIBLE);
				}
			}
			
			irqstate = ihk_mc_spinlock_lock(&thread->spin_sleep_lock);
			if (spin_sleep == thread->spin_sleep) {
				--thread->spin_sleep;
			}
			ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);

			return timeout;
		}
	}

	/* Init waitq and wait entry for this timer */
	my_timer.timeout = (timeout < LOOP_TIMEOUT) ? LOOP_TIMEOUT : timeout;
	my_timer.thread = cpu_local_var(current);
	waitq_init(&my_timer.processes);
	waitq_init_entry(&my_wait, cpu_local_var(current));

	/* Add ourself to the timer queue */
	ihk_mc_spinlock_lock_noirq(&timers_lock);
	list_add_tail(&my_timer.list, &timers);

	dkprintf("schedule_timeout() sleep timeout: %lu\n", my_timer.timeout);

	/* Add ourself to the waitqueue and sleep */ 
	waitq_prepare_to_wait(&my_timer.processes, &my_wait, PS_INTERRUPTIBLE);
	ihk_mc_spinlock_unlock_noirq(&timers_lock);
	schedule();
	waitq_finish_wait(&my_timer.processes, &my_wait);

	ihk_mc_spinlock_lock_noirq(&timers_lock);
	
	/* Waken up by someone else then timeout? */
	if (my_timer.timeout) {
		list_del(&my_timer.list);
	}
	ihk_mc_spinlock_unlock_noirq(&timers_lock);

	dkprintf("schedule_timeout() woken up, timeout: %lu\n", 
			my_timer.timeout);

	return my_timer.timeout;
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
