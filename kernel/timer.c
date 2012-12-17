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
#define dkprintf(...)
#endif

#define LOOP_TIMEOUT 500

struct list_head timers;
aal_spinlock_t timers_lock;


void init_timers(void)
{
	aal_mc_spinlock_init(&timers_lock);
	INIT_LIST_HEAD(&timers);
}

uint64_t schedule_timeout(uint64_t timeout)
{	
	struct waitq_entry my_wait;
	struct timer my_timer;
	unsigned long irqflags;
	struct process *proc = cpu_local_var(current);

	irqflags = aal_mc_spinlock_lock(&proc->spin_sleep_lock);
	dkprintf("schedule_timeout() spin sleep timeout: %lu\n", timeout);
	proc->spin_sleep = 1;
	aal_mc_spinlock_unlock(&proc->spin_sleep_lock, irqflags);

	/* Spin sleep.. */
	for (;;) {
		uint64_t t_s = rdtsc();
		uint64_t t_e;
		int spin_over = 0;

		irqflags = aal_mc_spinlock_lock(&proc->spin_sleep_lock);
		
		/* Woken up by someone? */
		if (!proc->spin_sleep) {
			t_e = rdtsc();

			spin_over = 1;
			if ((t_e - t_s) < timeout) {
				timeout -= (t_e - t_s);
			}
			else {
				timeout = 1;
			}
		}
		
		aal_mc_spinlock_unlock(&proc->spin_sleep_lock, irqflags);

		t_s = rdtsc();
		
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

		if (spin_over) {
			dkprintf("schedule_timeout() spin woken up, timeout: %lu\n", 
					timeout);
			return timeout;
		}
	}

	/* Init waitq and wait entry for this timer */
	my_timer.timeout = (timeout < LOOP_TIMEOUT) ? LOOP_TIMEOUT : timeout;
	my_timer.proc = cpu_local_var(current);
	waitq_init(&my_timer.processes);
	waitq_init_entry(&my_wait, cpu_local_var(current));

	/* Add ourself to the timer queue */
	irqflags = aal_mc_spinlock_lock(&timers_lock);
	list_add_tail(&my_timer.list, &timers);
	aal_mc_spinlock_unlock(&timers_lock, irqflags);

	dkprintf("schedule_timeout() sleep timeout: %lu\n", my_timer.timeout);

	/* Add ourself to the waitqueue and sleep */ 
	waitq_prepare_to_wait(&my_timer.processes, &my_wait, PS_INTERRUPTIBLE);
	schedule();
	waitq_finish_wait(&my_timer.processes, &my_wait);

	irqflags = aal_mc_spinlock_lock(&timers_lock);
	
	/* Waken up by someone else then timeout? */
	if (my_timer.timeout) {
		list_del(&my_timer.list);
	}
	
	aal_mc_spinlock_unlock(&timers_lock, irqflags);

	dkprintf("schedule_timeout() woken up, timeout: %lu\n", 
			my_timer.timeout);

	return my_timer.timeout;
}


void wake_timers_loop(void)
{
	unsigned long loop_s;
	unsigned long irqflags;
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
		irqflags = aal_mc_spinlock_lock(&timers_lock);
		
		list_for_each_entry_safe(timer, timer_next, &timers, list) {
			
			timer->timeout -= LOOP_TIMEOUT;
			if (timer->timeout < LOOP_TIMEOUT) {
				timer->timeout = 0;
				list_del(&timer->list);

				dkprintf("timers timeout occurred, waking up pid: %d\n", 
						timer->proc->pid);

				waitq_wakeup(&timer->processes);
			}
		}
		
		aal_mc_spinlock_unlock(&timers_lock, irqflags);
	}
}
