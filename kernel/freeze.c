/* freeze.c COPYRIGHT FUJITSU LIMITED 2019 */
#include <kmsg.h>
#include <string.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <cls.h>
#include <ihk/monitor.h>
#include <init.h>

extern void mod_nmi_ctx(void *, void(*)());
extern void lapic_ack();
extern void __freeze();

void
freeze()
{
	unsigned long flags;
	struct ihk_os_cpu_monitor *monitor = cpu_local_var(monitor);
	struct cpu_local_var *clv = get_this_cpu_local_var();

	ihk_mc_spinlock_lock_noirq(&clv->monitor_lock);
	monitor->status_bak = monitor->status;
	monitor->status = IHK_OS_MONITOR_KERNEL_FROZEN;
	flags = cpu_enable_interrupt_save();
	while (monitor->status == IHK_OS_MONITOR_KERNEL_FROZEN) {
		cpu_halt();
		cpu_pause();
	}
	cpu_restore_interrupt(flags);
	monitor->status = monitor->status_bak;
	ihk_mc_spinlock_unlock_noirq(&clv->monitor_lock);
}

long
freeze_thaw(void *nmi_ctx)
{
	struct ihk_os_cpu_monitor *monitor = cpu_local_var(monitor);

	if (multi_intr_mode == 1) {
		if (monitor->status != IHK_OS_MONITOR_KERNEL_FROZEN) {
#if 1
			mod_nmi_ctx(nmi_ctx, __freeze);
			return 1;
#else
			unsigned long flags;

			flags = cpu_disable_interrupt_save();
			monitor->status_bak = monitor->status;
			monitor->status = IHK_OS_MONITOR_KERNEL_FROZEN;
			lapic_ack();
			while (monitor->status == IHK_OS_MONITOR_KERNEL_FROZEN)
				cpu_halt();
			monitor->status = monitor->status_bak;
			cpu_restore_interrupt(flags);
#endif
		}
	}
	else if (multi_intr_mode == 2) {
		if (monitor->status == IHK_OS_MONITOR_KERNEL_FROZEN) {
			monitor->status = IHK_OS_MONITOR_KERNEL_THAW;
		}
	}
	return 0;
}
