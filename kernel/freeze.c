#include <kmsg.h>
#include <string.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <cls.h>
#include <ihk/monitor.h>

extern int nmi_mode;
extern void mod_nmi_ctx(void *, void(*)());
extern void lapic_ack();
extern void __freeze();

void
freeze()
{
	struct ihk_os_cpu_monitor *monitor = cpu_local_var(monitor);

	monitor->status_bak = monitor->status;
	monitor->status = IHK_OS_MONITOR_KERNEL_FROZEN;
	while (monitor->status == IHK_OS_MONITOR_KERNEL_FROZEN) {
		cpu_halt();
		cpu_pause();
	}
	monitor->status = monitor->status_bak;
}

long
freeze_thaw(void *nmi_ctx)
{
	struct ihk_os_cpu_monitor *monitor = cpu_local_var(monitor);

	if (nmi_mode == 1) {
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
	else if(nmi_mode == 2) {
		if (monitor->status == IHK_OS_MONITOR_KERNEL_FROZEN) {
			monitor->status = IHK_OS_MONITOR_KERNEL_THAW;
		}
	}
	return 0;
}

extern void arch_save_panic_regs(void *irq_regs);
extern void arch_clear_panic(void);

void
multi_nm_interrupt_handler(void *irq_regs)
{
	dkprintf("%s: ...\n", __func__);
	switch (nmi_mode) {
	case 1:
	case 2:
		/* mode == 1 or 2, for FREEZER NMI */
		dkprintf("%s: freeze mode NMI catch. (nmi_mode=%d)\n",
			 __func__, nmi_mode);
		freeze_thaw(NULL);
		break;

	case 0:
		/* mode == 0, for MEMDUMP NMI */
		arch_save_panic_regs(irq_regs);
		ihk_mc_query_mem_areas();
		/* memdump-nmi is halted McKernel, break is unnecessary. */
		/* fall through */
	case 3:
		/* mode == 3, for SHUTDOWN-WAIT NMI */
		kprintf("%s: STOP\n", __func__);
		while (nmi_mode != 4)
			cpu_halt();
		break;

	case 4:
		/* mode == 4, continue NMI */
		arch_clear_panic();
		if (!ihk_mc_get_processor_id()) {
			ihk_mc_clear_dump_page_completion();
		}
		kprintf("%s: RESUME, nmi_mode: %d\n", __func__, nmi_mode);
		break;

	default:
		ekprintf("%s: Unknown nmi-mode(%d) detected.\n",
			 __func__, nmi_mode);
		break;
	}
}
