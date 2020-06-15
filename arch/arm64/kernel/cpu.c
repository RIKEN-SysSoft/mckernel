/* cpu.c COPYRIGHT FUJITSU LIMITED 2015-2019 */
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <types.h>
#include <errno.h>
#include <list.h>
#include <memory.h>
#include <string.h>
#include <registers.h>
#include <cpulocal.h>
#include <signal.h>
#include <process.h>
#include <cls.h>
#include <thread_info.h>
#include <arch-memory.h>
#include <irq.h>
#include <lwk/compiler.h>
#include <ptrace.h>
#include <psci.h>
#include <smp.h>
#include <arch-timer.h>
#include <page.h>
#include <kmalloc.h>
#include <cpuinfo.h>
#include <cputype.h>
#include <hw_breakpoint.h>
#include <arch-perfctr.h>
#include <bitops-fls.h>
#include <debug-monitors.h>
#include <sysreg.h>
#include <cpufeature.h>
#include <ihk/debug.h>
#include <hwcap.h>
#include <virt.h>
#include <init.h>
#include <bootparam.h>

//#define DEBUG_PRINT_CPU

#include "postk_print_sysreg.c"

#ifdef DEBUG_PRINT_CPU
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

struct cpuinfo_arm64 cpuinfo_data[NR_CPUS];	/* index is logical cpuid */

static struct list_head handlers[1024];
static void cpu_init_interrupt_handler(void);

void init_processors_local(int max_id);
void assign_processor_id(void);
void arch_delay(int);
int gettime_local_support = 0;

extern int interrupt_from_user(void *);

extern unsigned long ihk_param_gic_dist_base_pa;
extern unsigned long ihk_param_gic_dist_map_size;
extern unsigned long ihk_param_gic_cpu_base_pa;
extern unsigned long ihk_param_gic_cpu_map_size;
extern unsigned int  ihk_param_gic_version;
extern int snprintf(char * buf, size_t size, const char *fmt, ...);

/* Function pointers for GIC */
void (*gic_dist_init)(unsigned long dist_base_pa, unsigned long size);
void (*gic_cpu_init)(unsigned long cpu_base_pa, unsigned long size);
void (*gic_enable)(void);
void (*arm64_issue_ipi)(unsigned int cpid, unsigned int vector);
void (*arm64_issue_host_ipi)(unsigned int cpid, unsigned int vector);
void (*handle_arch_irq)(struct pt_regs *);

static void gic_init(void)
{
	if(ihk_param_gic_version >= 3) {
		/* Setup functions for GICv3 */
		gic_dist_init = gic_dist_init_gicv3;
		gic_cpu_init = gic_cpu_init_gicv3;
		gic_enable = gic_enable_gicv3;
		arm64_issue_ipi = arm64_issue_ipi_gicv3;
		arm64_issue_host_ipi = arm64_issue_host_ipi_gicv3;
		handle_arch_irq = handle_interrupt_gicv3;
		kprintf("%: GICv3\n", __func__);
	} else {
		/* Setup functions for GICv2 */
		gic_dist_init = gic_dist_init_gicv2;
		gic_cpu_init = gic_cpu_init_gicv2;
		gic_enable = gic_enable_gicv2;
		arm64_issue_ipi = arm64_issue_ipi_gicv2;
		arm64_issue_host_ipi = arm64_issue_host_ipi_gicv2;
		handle_arch_irq = handle_interrupt_gicv2;
		kprintf("%: GICv2\n", __func__);
	}

	gic_dist_init(ihk_param_gic_dist_base_pa, ihk_param_gic_dist_map_size);
	gic_cpu_init(ihk_param_gic_cpu_base_pa, ihk_param_gic_cpu_map_size);
}

static void remote_tlb_flush_interrupt_handler(void *priv)
{
	/*Interim support*/
	flush_tlb();
}

static struct ihk_mc_interrupt_handler remote_tlb_flush_handler = {
	.func = remote_tlb_flush_interrupt_handler,
	.priv = NULL,
};

static void cpu_stop_interrupt_handler(void *priv)
{
	kprintf("CPU%d: shutdown.\n", ihk_mc_get_processor_id());
	psci_cpu_off();
}

static struct ihk_mc_interrupt_handler cpu_stop_handler = {
	.func = cpu_stop_interrupt_handler,
	.priv = NULL,
};

extern long freeze_thaw(void *nmi_ctx);
static void multi_interrupt_handler(void *priv)
{
	switch (multi_intr_mode) {
	case 1:
	case 2: /* mode == 1or2, for FREEZER intr */
		dkprintf("%s: freeze mode intr catch. (multi_intr_mode=%d)\n",
			 __func__, multi_intr_mode);
		freeze_thaw(NULL);
		break;
	default:
		ekprintf("%s: Unknown multi-intr-mode(%d) detected.\n",
			 __func__, multi_intr_mode);
		break;
	}
}

void arch_save_panic_regs(void *irq_regs)
{
	struct pt_regs *regs = (struct pt_regs *)irq_regs;
	union arm64_cpu_local_variables *clv;

	clv = get_arm64_this_cpu_local();

	/* For user-space, use saved kernel context */
	if (regs->pc < USER_END) {
		memset(clv->arm64_cpu_local_thread.panic_regs,
				0, sizeof(clv->arm64_cpu_local_thread.panic_regs));
		clv->arm64_cpu_local_thread.panic_regs[29] =
			current_thread_info()->cpu_context.fp;
		clv->arm64_cpu_local_thread.panic_regs[31] =
			current_thread_info()->cpu_context.sp;
		clv->arm64_cpu_local_thread.panic_regs[32] =
			current_thread_info()->cpu_context.pc;
		clv->arm64_cpu_local_thread.panic_regs[33] =
			PSR_MODE_EL1h;
	}
	else {
		memcpy(clv->arm64_cpu_local_thread.panic_regs,
				regs->regs, sizeof(regs->regs));
		clv->arm64_cpu_local_thread.panic_regs[31] = regs->sp;
		clv->arm64_cpu_local_thread.panic_regs[32] = regs->pc;
		clv->arm64_cpu_local_thread.panic_regs[33] =
			regs->pstate;

	}

	clv->arm64_cpu_local_thread.paniced = 1;
}

void arch_clear_panic(void)
{
	union arm64_cpu_local_variables *clv;

	clv = get_arm64_this_cpu_local();
	clv->arm64_cpu_local_thread.paniced = 0;
}

static struct ihk_mc_interrupt_handler multi_intr_handler = {
	.func = multi_interrupt_handler,
	.priv = NULL,
};

static void multi_nm_interrupt_handler(void *irq_regs)
{
	extern int nmi_mode;

	dkprintf("%s: ...\n", __func__);
	switch (nmi_mode) {
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

static struct ihk_mc_interrupt_handler multi_nmi_handler = {
	.func = multi_nm_interrupt_handler,
	.priv = NULL,
};

static void init_smp_processor(void)
{
	/* nothing */
}

/* @ref.impl arch/arm64/include/asm/cputype.h */
static inline uint32_t read_cpuid_cachetype(void)
{
	return read_cpuid(CTR_EL0);
}

/* @ref.impl arch/arm64/include/asm/arch_timer.h */
static inline uint32_t arch_timer_get_cntfrq(void)
{
	return read_sysreg(cntfrq_el0);
}

/* @ref.impl arch/arm64/kernel/cpuinfo.c::__cpuinfo_store_cpu */
static void __cpuinfo_store_cpu(struct cpuinfo_arm64 *info)
{
	info->hwid = ihk_mc_get_hardware_processor_id(); /* McKernel Original. */

	info->reg_cntfrq = arch_timer_get_cntfrq();
	info->reg_ctr = read_cpuid_cachetype();
	info->reg_dczid = read_cpuid(DCZID_EL0);
	info->reg_midr = read_cpuid_id();
	info->reg_revidr = read_cpuid(REVIDR_EL1);

	info->reg_id_aa64dfr0 = read_cpuid(ID_AA64DFR0_EL1);
	info->reg_id_aa64dfr1 = read_cpuid(ID_AA64DFR1_EL1);
	info->reg_id_aa64isar0 = read_cpuid(ID_AA64ISAR0_EL1);
	info->reg_id_aa64isar1 = read_cpuid(ID_AA64ISAR1_EL1);
	info->reg_id_aa64mmfr0 = read_cpuid(ID_AA64MMFR0_EL1);
	info->reg_id_aa64mmfr1 = read_cpuid(ID_AA64MMFR1_EL1);
	info->reg_id_aa64mmfr2 = read_cpuid(ID_AA64MMFR2_EL1);
	info->reg_id_aa64pfr0 = read_cpuid(ID_AA64PFR0_EL1);
	info->reg_id_aa64pfr1 = read_cpuid(ID_AA64PFR1_EL1);
	info->reg_id_aa64zfr0 = read_cpuid(ID_AA64ZFR0_EL1);

	/* Update the 32bit ID registers only if AArch32 is implemented */
//	if (id_aa64pfr0_32bit_el0(info->reg_id_aa64pfr0)) {
//		panic("AArch32 is not supported.");
//	}

	if (id_aa64pfr0_sve(info->reg_id_aa64pfr0)) {
		uint64_t zcr;

		write_sysreg_s(ZCR_EL1_LEN_MASK, SYS_ZCR_EL1);
		zcr = read_sysreg_s(SYS_ZCR_EL1);
		zcr &= ~(uint64_t)ZCR_EL1_LEN_MASK;
		zcr |= sve_get_vl() / 16 - 1;

		info->reg_zcr = zcr;
	}
}

/* @ref.impl arch/arm64/kernel/cpuinfo.c */
static void cpuinfo_store_boot_cpu(void)
{
	struct cpuinfo_arm64 *info = &cpuinfo_data[0];
	__cpuinfo_store_cpu(info);
	init_cpu_features(info);
}

/* @ref.impl arch/arm64/kernel/cpuinfo.c */
static void cpuinfo_store_cpu(void)
{
	int cpuid = ihk_mc_get_processor_id();
	struct cpuinfo_arm64 *boot_cpu_data = &cpuinfo_data[0];
	struct cpuinfo_arm64 *info = &cpuinfo_data[cpuid];
	__cpuinfo_store_cpu(info);
	update_cpu_features(cpuid, info, boot_cpu_data);
}

/* @ref.impl arch/arm64/kernel/setup.c::setup_processor */
static void setup_processor(void)
{
	cpuinfo_store_boot_cpu();
	enable_mrs_emulation();
}

static char *trampoline_va, *first_page_va;

static inline uint64_t pwr_arm64hpc_read_imp_fj_core_uarch_restrection_el1(void)
{
	uint64_t reg;

	asm volatile("mrs_s %0, " __stringify(IMP_FJ_CORE_UARCH_RESTRECTION_EL1)
		     : "=r" (reg) : : "memory");
	return reg;
}

static ihk_spinlock_t imp_fj_core_uarch_restrection_el1_lock =
	SPIN_LOCK_UNLOCKED;
static inline void pwr_arm64hpc_write_imp_fj_core_uarch_restrection_el1(uint64_t set_bit,
									uint64_t clear_bit)
{
	uint64_t reg;
	unsigned long flags;

	flags = ihk_mc_spinlock_lock(&imp_fj_core_uarch_restrection_el1_lock);
	reg = pwr_arm64hpc_read_imp_fj_core_uarch_restrection_el1();
	reg = (reg & ~clear_bit) | set_bit;
	asm volatile("msr_s " __stringify(IMP_FJ_CORE_UARCH_RESTRECTION_EL1) ", %0"
		     : : "r" (reg) : "memory");
	ihk_mc_spinlock_unlock(&imp_fj_core_uarch_restrection_el1_lock, flags);
}

static inline uint64_t pwr_arm64hpc_read_imp_soc_standby_ctrl_el1(void)
{
	uint64_t reg;

	asm volatile("mrs_s %0, " __stringify(IMP_SOC_STANDBY_CTRL_EL1)
		     : "=r" (reg) : : "memory");
	return reg;
}

static ihk_spinlock_t imp_soc_standby_ctrl_el1_lock = SPIN_LOCK_UNLOCKED;
static inline void pwr_arm64hpc_write_imp_soc_standby_ctrl_el1(uint64_t set_bit,
							       uint64_t clear_bit)
{
	unsigned long flags;
	uint64_t reg;

	flags = ihk_mc_spinlock_lock(&imp_soc_standby_ctrl_el1_lock);
	reg = pwr_arm64hpc_read_imp_soc_standby_ctrl_el1();
	reg = (reg & ~clear_bit) | set_bit;
	asm volatile("msr_s " __stringify(IMP_SOC_STANDBY_CTRL_EL1) ", %0"
		     : : "r" (reg) : "memory");
	ihk_mc_spinlock_unlock(&imp_soc_standby_ctrl_el1_lock, flags);
}

static unsigned long *retention_state_flag;

static inline int is_hpcpwr_available(void)
{
	if (retention_state_flag)
		return 1;
	else
		return 0;
}

static inline void pwr_arm64hpc_map_retention_state_flag(void)
{
	extern unsigned long ihk_param_retention_state_flag_pa;
	unsigned long size = BITS_TO_LONGS(NR_CPUS) * sizeof(unsigned long);

	if (!ihk_param_retention_state_flag_pa) {
		return;
	}
	retention_state_flag = map_fixed_area(ihk_param_retention_state_flag_pa,
					      size, 0);
}

static inline int pwr_arm64hpc_retention_state_get(uint64_t *val)
{
	unsigned long linux_core_id;
	int cpu = ihk_mc_get_processor_id();
	int ret;

	if (!is_hpcpwr_available()) {
		*val = 0;
		return 0;
	}

	ret = ihk_mc_get_core(cpu, &linux_core_id, NULL, NULL);
	if (ret) {
		return ret;
	}
	*val = test_bit(linux_core_id, retention_state_flag);
	return ret;
}

static inline int pwr_arm64hpc_retention_state_set(uint64_t val)
{
	unsigned long linux_core_id;
	int cpu = ihk_mc_get_processor_id();
	int ret;

	if (!is_hpcpwr_available()) {
		return 0;
	}

	ret = ihk_mc_get_core(cpu, &linux_core_id, NULL, NULL);
	if (ret) {
		return ret;
	}

	if (val) {
		set_bit(cpu, retention_state_flag);
	} else {
		clear_bit(cpu, retention_state_flag);
	}
	return ret;
}

static inline int pwr_arm64hpc_enable_retention_state(void)
{
	if (!is_hpcpwr_available()) {
		return 0;
	}

	pwr_arm64hpc_write_imp_soc_standby_ctrl_el1(IMP_SOC_STANDBY_CTRL_EL1_RETENTION,
						    0);
	return 0;
}

static inline void init_power_management(void)
{
	int state;
	uint64_t imp_fj_clear_bit = 0;
	uint64_t imp_soc_clear_bit = 0;

	if (!is_hpcpwr_available()) {
		return;
	}

	/* retention state */
	state = pwr_arm64hpc_retention_state_set(0);
	if (state) {
		panic("error: initialize power management\n");
	}

	/* issue state */
	imp_fj_clear_bit |= IMP_FJ_CORE_UARCH_RESTRECTION_EL1_ISSUE_RESTRICTION;

	/* eco_state  */
	imp_fj_clear_bit |= IMP_FJ_CORE_UARCH_RESTRECTION_EL1_FL_RESTRICT_TRANS;
	imp_soc_clear_bit |= IMP_SOC_STANDBY_CTRL_EL1_ECO_MODE;

	/* ex_pipe_state */
	imp_fj_clear_bit |= IMP_FJ_CORE_UARCH_RESTRECTION_EL1_EX_RESTRICTION;

	/* write */
	pwr_arm64hpc_write_imp_fj_core_uarch_restrection_el1(0,
							     imp_fj_clear_bit);
	pwr_arm64hpc_write_imp_soc_standby_ctrl_el1(0, imp_soc_clear_bit);
}

/*@
  @ assigns torampoline_va;
  @ assigns first_page_va;
  @*/
void ihk_mc_init_ap(void)
{
	struct ihk_mc_cpu_info *cpu_info = ihk_mc_get_cpu_info();

	trampoline_va = map_fixed_area(ap_trampoline, AP_TRAMPOLINE_SIZE, 0);
	kprintf("Trampoline area: 0x%lx \n", ap_trampoline);
	first_page_va = map_fixed_area(0, PAGE_SIZE, 0);

	kprintf("# of cpus : %d\n", cpu_info->ncpus);
	init_processors_local(cpu_info->ncpus);
	
	/* Do initialization for THIS cpu (BSP) */
	assign_processor_id();

	ihk_mc_register_interrupt_handler(INTRID_CPU_STOP, &cpu_stop_handler);
	ihk_mc_register_interrupt_handler(INTRID_MULTI_NMI, &multi_nmi_handler);
	ihk_mc_register_interrupt_handler(INTRID_MULTI_INTR,
					  &multi_intr_handler);
	ihk_mc_register_interrupt_handler(
		ihk_mc_get_vector(IHK_TLB_FLUSH_IRQ_VECTOR_START),
		&remote_tlb_flush_handler);
	ihk_mc_register_interrupt_handler(get_timer_intrid(),
					  get_timer_handler());

	init_smp_processor();
	init_power_management();
}

extern void vdso_init(void);
long (*__arm64_syscall_handler)(int, ihk_mc_user_context_t *);

/* @ref.impl arch/arm64/include/asm/arch_timer.h::arch_timer_get_cntkctl */
static inline unsigned int arch_timer_get_cntkctl(void)
{
	return read_sysreg(cntkctl_el1);
}

/* @ref.impl arch/arm64/include/asm/arch_timer.h::arch_timer_set_cntkctl */
static inline void arch_timer_set_cntkctl(unsigned int cntkctl)
{
	write_sysreg(cntkctl, cntkctl_el1);
}

#ifdef CONFIG_ARM_ARCH_TIMER_EVTSTREAM
/* @ref.impl drivers/clocksource/arm_arch_timer.c::arch_timer_evtstrm_enable */
static void arch_timer_evtstrm_enable(int divider)
{
	uint32_t cntkctl = arch_timer_get_cntkctl();

	cntkctl &= ~ARCH_TIMER_EVT_TRIGGER_MASK;
	/* Set the divider and enable virtual event stream */
	cntkctl |= (divider << ARCH_TIMER_EVT_TRIGGER_SHIFT)
			| ARCH_TIMER_VIRT_EVT_EN;
	arch_timer_set_cntkctl(cntkctl);
}

/* @ref.impl include/clocksource/arm_arch_timer.h::ARCH_TIMER_EVT_STREAM_FREQ */
#define ARCH_TIMER_EVT_STREAM_FREQ	10000	/* 100us */

/* @ref.impl drivers/clocksource/arm_arch_timer.c::arch_timer_configure_evtstream */
static void arch_timer_configure_evtstream(void)
{
	int evt_stream_div, pos;
	extern unsigned long ihk_param_evtstrm_timer_rate;

	/* Find the closest power of two to the divisor */
	evt_stream_div = ihk_param_evtstrm_timer_rate / ARCH_TIMER_EVT_STREAM_FREQ;
	pos = fls(evt_stream_div);
	if (pos > 1 && !(evt_stream_div & (1 << (pos - 2))))
		pos--;
	/* enable event stream */
	arch_timer_evtstrm_enable(pos > 15 ? 15 : pos);
}
#else /* CONFIG_ARM_ARCH_TIMER_EVTSTREAM */
static inline void arch_timer_configure_evtstream(void) {}
#endif /* CONFIG_ARM_ARCH_TIMER_EVTSTREAM */

/* @ref.impl drivers/clocksource/arm_arch_timer.c::arch_counter_set_user_access */
static void arch_counter_set_user_access(void)
{
	unsigned int cntkctl = arch_timer_get_cntkctl();

	/* Disable user access to the timers and the physical counter */
	/* Also disable virtual event stream */

	cntkctl &= ~(ARCH_TIMER_USR_PT_ACCESS_EN
			| ARCH_TIMER_USR_VT_ACCESS_EN
			| ARCH_TIMER_VIRT_EVT_EN
			| ARCH_TIMER_USR_PCT_ACCESS_EN);

	/* Enable user access to the virtual counter */
	cntkctl |= ARCH_TIMER_USR_VCT_ACCESS_EN;
	arch_timer_set_cntkctl(cntkctl);
}

static void init_gettime_support(void)
{
	arch_counter_set_user_access();

	gettime_local_support = 1;
}

void init_cpu(void)
{
	if(gic_enable) 
		gic_enable();

	arm64_init_per_cpu_perfctr();
	arm64_enable_pmu();

	if (xos_is_tchip()) {
		vhbm_barrier_registers_init();
		scdrv_registers_init();
		hpc_registers_init();
	}
	arm64_enable_user_access_pmu_regs();
}

#ifdef CONFIG_ARM64_VHE
/* @ref.impl arch/arm64/kernel/smp.c */
/* Whether the boot CPU is running in HYP mode or not */
static int boot_cpu_hyp_mode;

static inline void save_boot_cpu_run_el(void)
{
	boot_cpu_hyp_mode = is_kernel_in_hyp_mode();
}

static inline int is_boot_cpu_in_hyp_mode(void)
{
	return boot_cpu_hyp_mode;
}

/*
 * Verify that a secondary CPU is running the kernel at the same
 * EL as that of the boot CPU.
 */
static void verify_cpu_run_el(void)
{
	int in_el2 = is_kernel_in_hyp_mode();
	int boot_cpu_el2 = is_boot_cpu_in_hyp_mode();

	if (in_el2 ^ boot_cpu_el2) {
		kprintf("CPU%d: mismatched Exception Level(EL%d) with boot CPU(EL%d)\n",
					ihk_mc_get_processor_id(),
					in_el2 ? 2 : 1,
					boot_cpu_el2 ? 2 : 1);
		panic("verify_cpu_run_el(): PANIC: mismatched Exception Level.\n");
	}
}
#else /* CONFIG_ARM64_VHE */
static inline void save_boot_cpu_run_el(void) {}
static inline void verify_cpu_run_el(void) {}
#endif /* CONFIG_ARM64_VHE */

void setup_arm64(void)
{
	cpu_disable_interrupt();

	cpu_init_interrupt_handler();

	arm64_init_perfctr();

	arch_timer_init();

	gic_init();

	pwr_arm64hpc_map_retention_state_flag();

	init_cpu();

	init_gettime_support();

	setup_processor();

	save_boot_cpu_run_el();

	arch_hw_breakpoint_init();

	debug_monitors_init();

	arch_timer_configure_evtstream();

	if (psci_init()) {
		panic("setup_arm64(): PANIC: HOST-Linux does not have a psci -> method property.\n");
	}

	kprintf("setup_arm64 done.\n");
}

static volatile int cpu_boot_status;

void call_ap_func(void (*next_func)(void))
{
	/* ap boot flag ON */
	cpu_boot_status = 1;
	cpu_enable_interrupt();
	next_func();
}

void setup_arm64_ap(void (*next_func)(void))
{
	/* set this core logical cpuid for struct thread_info */
	assign_processor_id();
	verify_cpu_run_el();
	arch_counter_set_user_access();
	cpuinfo_store_cpu();
	hw_breakpoint_reset();
	debug_monitors_init();
	arch_timer_configure_evtstream();
	init_cpu();
	init_power_management();
	call_ap_func(next_func);

	/* BUG */
	while(1);
}

void arch_show_interrupt_context(const void *reg);
extern void tlb_flush_handler(int vector);

static void show_context_stack(struct pt_regs *regs)
{
	const int min_stack_frame_size = 0x10;
	uintptr_t sp;
	uintptr_t stack_top;
	int max_loop;
	int i;

	if (interrupt_from_user(regs)) {
		kprintf("It is a user stack region and it ends.\n");
		return;
	}

	ihk_mc_debug_show_interrupt_context(regs);

	sp = (uintptr_t)regs + sizeof(*regs);
	stack_top = ALIGN_UP(sp, (uintptr_t)KERNEL_STACK_SIZE);
	max_loop = (stack_top - sp) / min_stack_frame_size;

	for (i = 0; i < max_loop; i++) {
		extern char _head[], _end[];
		uintptr_t *fp, *lr;
		fp = (uintptr_t *)sp;
		lr = (uintptr_t *)(sp + 8);

		if ((*fp <= sp) || (*fp > stack_top)) {
			break;
		}

		if ((*lr < (unsigned long)_head) ||
		    (*lr > (unsigned long)_end)) {
			break;
		}

		kprintf("LR: %016lx, SP: %016lx, FP: %016lx\n", *lr, sp, *fp);
		sp = *fp;
	}
}

void handle_IPI(unsigned int vector, struct pt_regs *regs)
{
	struct ihk_mc_interrupt_handler *h;

	dkprintf("CPU[%d] got interrupt, vector: %d\n", 
		 ihk_mc_get_processor_id(), vector);

	if (vector > ((sizeof(handlers) / sizeof(handlers[0])) - 1)) {
		panic("Maybe BUG.");
	}
	else if (vector == INTRID_STACK_TRACE) {
		show_context_stack(regs);
	}
	else {
		list_for_each_entry(h, &handlers[vector], list) {
			if (h->func) {
				h->func(h->priv == NULL ? regs : h->priv);
			}
		}
	}
}

static void __arm64_wakeup(int hw_cpuid, unsigned long entry)
{
	if (cpu_psci_cpu_boot(hw_cpuid, entry)) {
		panic("ap kickup cpu_psci_cpu_boot() failed.\n");
	}
}

/** IHK Functions **/

/* send WFI(Wait For Interrupt) instruction */
static inline void cpu_do_idle(void)
{
	extern void __cpu_do_idle(void);
	uint64_t retention;
	int state;

	state = pwr_arm64hpc_retention_state_get(&retention);
	if ((state == 0) && (retention != 0)) {
		pwr_arm64hpc_enable_retention_state();
	}
	__cpu_do_idle();
}

/* halt by WFI(Wait For Interrupt) */
void cpu_halt(void)
{
	cpu_do_idle();
}

/*@
  @ assigns \nothing;
  @ ensures \interrupt_disabled == 0;
  @*/
void cpu_safe_halt(void)
{
	cpu_do_idle();
	cpu_enable_interrupt();
}

/*@
  @ assigns \nothing;
  @ ensures \interrupt_disabled == 0;
  @*/
void cpu_halt_panic(void)
{
	extern void __cpu_do_idle(void);
	cpu_enable_interrupt();
	__cpu_do_idle();
}

#if defined(CONFIG_HAS_NMI)
#include <arm-gic-v3.h>

/* enable interrupt (ICC_PMR_EL1 <= ICC_PMR_EL1_UNMASKED) */
void cpu_enable_interrupt(void)
{
	unsigned long unmasked = ICC_PMR_EL1_UNMASKED;
	asm volatile(
		"msr_s  " __stringify(ICC_PMR_EL1) ",%0"
		:
		: "r" (unmasked)
		: "memory");
}

/* disable interrupt (ICC_PMR_EL1 <= ICC_PMR_EL1_MASKED) */
void cpu_disable_interrupt(void)
{
	unsigned long masked = ICC_PMR_EL1_MASKED;
	asm volatile(
		"msr_s  " __stringify(ICC_PMR_EL1) ",%0"
		:
		: "r" (masked)
		: "memory");
}

/* restore interrupt (ICC_PMR_EL1 <= flags) */
void cpu_restore_interrupt(unsigned long flags)
{
	asm volatile(
		"msr_s  " __stringify(ICC_PMR_EL1) ",%0"
		:
		: "r" (flags)
		: "memory");
}

/* save ICC_PMR_EL1 & disable interrupt (ICC_PMR_EL1 <= ICC_PMR_EL1_MASKED) */
unsigned long cpu_disable_interrupt_save(void)
{
	unsigned long flags;
	unsigned long masked = ICC_PMR_EL1_MASKED;

	asm volatile(
		"mrs_s  %0, " __stringify(ICC_PMR_EL1) "\n"
		"msr_s  " __stringify(ICC_PMR_EL1) ",%1"
		: "=&r" (flags)
		: "r" (masked)
		: "memory");
	return flags;
}

/* save ICC_PMR_EL1 & enable interrupt (ICC_PMR_EL1 <= ICC_PMR_EL1_UNMASKED) */
unsigned long cpu_enable_interrupt_save(void)
{
	unsigned long flags;
	unsigned long masked = ICC_PMR_EL1_UNMASKED;

	asm volatile(
		"mrs_s  %0, " __stringify(ICC_PMR_EL1) "\n"
		"msr_s  " __stringify(ICC_PMR_EL1) ",%1"
		: "=&r" (flags)
		: "r" (masked)
		: "memory");
	return flags;
}

#else /* defined(CONFIG_HAS_NMI) */

/* @ref.impl arch/arm64/include/asm/irqflags.h::arch_local_irq_enable */
/* enable interrupt (PSTATE.DAIF I bit clear) */
void cpu_enable_interrupt(void)
{
	asm volatile(
		"msr    daifclr, #2	// arch_local_irq_enable"
		:
		:
		: "memory");
}

/* @ref.impl arch/arm64/include/asm/irqflags.h::arch_local_irq_disable */
/* disable interrupt (PSTATE.DAIF I bit set) */
void cpu_disable_interrupt(void)
{
	asm volatile(
		"msr    daifset, #2	// arch_local_irq_disable"
		:
		:
		: "memory");
}

/* @ref.impl arch/arm64/include/asm/spinlock.h::arch_local_irq_restore */
/* restore interrupt (PSTATE.DAIF = flags restore) */
void cpu_restore_interrupt(unsigned long flags)
{
	asm volatile(
		"msr    daif, %0	// arch_local_irq_restore"
		:
		: "r" (flags)
		: "memory");
}

/* @ref.impl arch/arm64/include/asm/irqflags.h::arch_local_irq_save */
/* save PSTATE.DAIF & disable interrupt (PSTATE.DAIF I bit set) */
unsigned long cpu_disable_interrupt_save(void)
{
	unsigned long flags;
	asm volatile(
		"mrs    %0, daif	// arch_local_irq_save\n"
		"msr    daifset, #2"
		: "=r" (flags)
		:
		: "memory");
	return flags;
}

/* save PSTATE.DAIF & enable interrupt (PSTATE.DAIF I bit set) */
unsigned long cpu_enable_interrupt_save(void)
{
	unsigned long flags;

	asm volatile(
		"mrs    %0, daif	// arch_local_irq_save\n"
		"msr    daifclr, #2"
		: "=r" (flags)
		:
		: "memory");
	return flags;
}
#endif /* defined(CONFIG_HAS_NMI) */

/* we not have "pause" instruction, instead "yield" instruction */
void cpu_pause(void)
{
	asm volatile("yield" ::: "memory");
}

static void cpu_init_interrupt_handler(void)
{
	int i;
	for (i = 0; i < (sizeof(handlers) / sizeof(handlers[0])); i++) {
		INIT_LIST_HEAD(&handlers[i]);
	}
}

/*@
  @ behavior valid_vector:
  @   assumes 0 <= vector <= 15;
  @   requires \valid(h);
  @   assigns handlers[vector-32];
  @   ensures \result == 0;
  @ behavior invalid_vector:
  @   assumes (vector > 15);
  @   assigns \nothing;
  @   ensures \result == -EINVAL;
  @*/
int ihk_mc_register_interrupt_handler(int vector,
                                      struct ihk_mc_interrupt_handler *h)
{
	if ((vector < 0) || (vector > ((sizeof(handlers) / sizeof(handlers[0])) - 1))) {
		return -EINVAL;
	}

	list_add_tail(&h->list, &handlers[vector]);

	return 0;
}
int ihk_mc_unregister_interrupt_handler(int vector,
                                        struct ihk_mc_interrupt_handler *h)
{
	list_del(&h->list);

	return 0;
}

extern unsigned long __page_fault_handler_address;

/*@
  @ requires \valid(h);
  @ assigns __page_fault_handler_address;
  @ ensures __page_fault_handler_address == h;
  @*/
void ihk_mc_set_page_fault_handler(void (*h)(void *, uint64_t, void *))
{
	__page_fault_handler_address = (unsigned long)h;
}

extern char trampoline_code_data[], trampoline_code_data_end[];
unsigned long get_transit_page_table(void);

int get_virt_cpuid(int hw_cpuid)
{
	int virt_cpuid = -1;
	const struct ihk_mc_cpu_info *cpu_info;
	int i;

	cpu_info = ihk_mc_get_cpu_info();
	for (i = 0; i < cpu_info->ncpus; i++) {
		if (cpu_info->hw_ids[i] == hw_cpuid) {
			virt_cpuid = i;
			break;
		}
	}
	return virt_cpuid;
}

/* reusable, but not reentrant */
/*@
  @ requires \valid_apicid(cpuid);	// valid APIC ID or not
  @ requires \valid(pc);
  @ requires \valid(trampoline_va);
  @ requires \valid(trampoline_code_data
  @		+(0..(trampoline_code_data_end - trampoline_code_data)));
  @ requires \valid_physical(ap_trampoline);	// valid physical address or not
  @ assigns (char *)trampoline_va+(0..trampoline_code_data_end - trampoline_code_data);
  @ assigns cpu_boot_status;
  @ ensures cpu_boot_status != 0;
  @*/
void ihk_mc_boot_cpu(int cpuid, unsigned long pc)
{
	int virt_cpuid = get_virt_cpuid(cpuid);
	extern void arch_ap_start();
	extern int num_processors;
	int ncpus;

	/* virt cpuid check */
	if (virt_cpuid == -1) {
		panic("exchange failed, PHYSCPUID --> VIRTCPUID\n");
	}

	/* ap stack address set for secondary_data */
	secondary_data.stack = 
		(void *)get_arm64_cpu_local_variable(virt_cpuid) + THREAD_START_SP - sizeof(ihk_mc_user_context_t);

	/* next_pc address set for secondary_data (setup_arm64_ap) */
	secondary_data.next_pc = (uint64_t)setup_arm64_ap;

	/* next_pc argument set for secondary_data (ihk_mc_boot_cpu argument 2) */
	secondary_data.arg = pc;

	/* ap wait flag initialize */
	cpu_boot_status = 0;

	/* ap kickup */
	__arm64_wakeup(cpuid, virt_to_phys(arch_ap_start));

	/* wait for ap call call_ap_func() */
	while (!cpu_boot_status) {
		cpu_pause();
	}

	ncpus = ihk_mc_get_cpu_info()->ncpus;
	if (ncpus - 1 <= num_processors) {
		setup_cpu_features();
	}

	sve_setup();
}

/* for ihk_mc_init_context() */
extern void ret_from_fork(void);

/*@
  @ requires \valid(new_ctx);
  @ requires (stack_pointer == NULL) || \valid((unsigned long *)stack_pointer-1);
  @ requires \valid(next_function);
  @*/
/* initialize context */
/* stack_pointer == NULL is idle process context */
/* stack_pointer != NULL is user thread context */
void ihk_mc_init_context(ihk_mc_kernel_context_t *new_ctx,
                         void *stack_pointer, void (*next_function)(void))
{
	unsigned long sp = 0;
	ihk_mc_user_context_t *new_uctx = NULL;

	if (unlikely(!stack_pointer)) {
		/* for idle process */
		/* get idle stack address */
		sp = (unsigned long)get_arm64_this_cpu_kstack();

		/* get thread_info address */
		new_ctx->thread = (struct thread_info *)((unsigned long)ALIGN_DOWN(sp, KERNEL_STACK_SIZE));

		/* set ret_from_fork address */
		new_ctx->thread->cpu_context.pc = (unsigned long)ret_from_fork;

		/* set idle address */
		/* branch in ret_from_fork */
		new_ctx->thread->cpu_context.x19 = (unsigned long)next_function;

		sp -= 16;
		new_ctx->thread->cpu_context.fp = sp;

		/* set stack_pointer */
		new_ctx->thread->cpu_context.sp = sp - sizeof(ihk_mc_user_context_t);

		/* clear pt_regs area */
		new_uctx = (ihk_mc_user_context_t *)new_ctx->thread->cpu_context.sp;
		memset(new_uctx, 0, sizeof(ihk_mc_user_context_t));

		/* set pt_regs->pstate */
		new_uctx->pstate = PSR_MODE_EL1h;
	} else {
		/* for user thread, kernel stack */
		/* save logical cpuid (for execve) */
		const int lcpuid = ihk_mc_get_processor_id();
		const unsigned long syscallno = current_pt_regs()->syscallno;
#ifdef CONFIG_ARM64_SVE
		struct thread_info *ti = current_thread_info();
		const unsigned int orig_sve_vl = ti->sve_vl;
		const unsigned int orig_sve_vl_onexec = ti->sve_vl_onexec;
		const unsigned long orig_sve_flags = ti->sve_flags;
#endif /* CONFIG_ARM64_SVE */

		/* get kernel stack address */
		sp = (unsigned long)stack_pointer;

		/* get thread_info address */
		new_ctx->thread = (struct thread_info *)((unsigned long)ALIGN_DOWN(sp, KERNEL_STACK_SIZE));

		/* clear thread_info */
		memset(new_ctx->thread, 0, sizeof(struct thread_info));

		/* restore logical cpuid (for execve) */
		new_ctx->thread->cpu = lcpuid;

		/* set ret_from_fork address */
		new_ctx->thread->cpu_context.pc = (unsigned long)ret_from_fork;

		/* set stack_pointer */
		new_ctx->thread->cpu_context.sp = sp;
		/* use the 16 bytes padding in ihk_mc_init_user_process()
		 * as closing frame in the frame chain */
		new_ctx->thread->cpu_context.fp = sp + sizeof(ihk_mc_user_context_t);

		/* clear pt_regs area */
		new_uctx = (ihk_mc_user_context_t *)new_ctx->thread->cpu_context.sp;
		memset(new_uctx, 0, sizeof(ihk_mc_user_context_t));

		/* initialize user context */
		/* copy from current_pt_regs */
		*new_uctx = *((ihk_mc_user_context_t *)current_pt_regs());
		new_uctx->regs[0] = 0;
		new_uctx->pc = (unsigned long)next_function;
		new_uctx->pstate = (new_uctx->pstate & ~PSR_MODE_MASK) | PSR_MODE_EL0t;

#ifdef CONFIG_ARM64_SVE
		/* SVE-VL inherit */
		if (likely(elf_hwcap & HWCAP_SVE)) {
			new_ctx->thread->sve_vl_onexec = orig_sve_vl_onexec;
			new_ctx->thread->sve_flags = orig_sve_flags;

			if (syscallno == __NR_execve) {
				new_ctx->thread->sve_vl = orig_sve_vl_onexec ?
					orig_sve_vl_onexec : sve_default_vl;

				BUG_ON(!sve_vl_valid(new_ctx->thread->sve_vl));

				if (!(new_ctx->thread->sve_flags & THREAD_VL_INHERIT)) {
					new_ctx->thread->sve_vl_onexec = 0;
				}
			} else {
				new_ctx->thread->sve_vl = orig_sve_vl ?
					orig_sve_vl : sve_default_vl;
			}
		}
#endif /* CONFIG_ARM64_SVE */
	}
}

/*
 * Release runq_lock before entering user space.
 * This is needed because schedule() holds the runq lock throughout
 * the context switch and when a new process is created it starts
 * execution in enter_user_mode, which in turn calls this function.
 */
void release_runq_lock(void)
{
	ihk_mc_spinlock_unlock(&(cpu_local_var(runq_lock)),
			cpu_local_var(runq_irqstate));
}

/*@
  @ requires \valid(ctx);
  @ requires \valid(puctx);
  @ requires \valid((ihk_mc_user_context_t *)stack_pointer-1);
  @ requires \valid_user(new_pc);	// valid user space address or not
  @ requires \valid_user(user_sp-1);
  @ assigns *((ihk_mc_user_context_t *)stack_pointer-1);
  @ assigns ctx->rsp0;
  @*/
void ihk_mc_init_user_process(ihk_mc_kernel_context_t *ctx,
                              ihk_mc_user_context_t **puctx,
                              void *stack_pointer, unsigned long new_pc,
                              unsigned long user_sp)
{
	char *sp = NULL;

	/* calc aligned kernel stack address */
	/* higher 16 byte area is padding area */
	sp = (char *)(ALIGN_DOWN((unsigned long)stack_pointer, KERNEL_STACK_SIZE) - 16);

	/* get pt_regs address */
	sp -= sizeof(ihk_mc_user_context_t);

	/* puctx return value set */
	*puctx = (ihk_mc_user_context_t *)sp;

	/* initialize kernel context */
	ihk_mc_init_context(ctx, sp, (void (*)(void))new_pc);
}

/*@
  @ behavior rsp:
  @   assumes reg == IHK_UCR_STACK_POINTER;
  @   requires \valid(uctx);
  @   assigns uctx->gpr.rsp;
  @   ensures uctx->gpr.rsp == value;
  @ behavior rip:
  @   assumes reg == IHK_UCR_PROGRAM_COUNTER;
  @   requires \valid(uctx);
  @   assigns uctx->gpr.rip;
  @   ensures uctx->gpr.rip == value;
  @*/
void ihk_mc_modify_user_context(ihk_mc_user_context_t *uctx,
                                enum ihk_mc_user_context_regtype reg,
                                unsigned long value)
{
	if (reg == IHK_UCR_STACK_POINTER) {
		if (value & 15) {
			panic("User Stack Pointer Unaligned !!\n");
		}
		uctx->sp = value;
	} else if (reg == IHK_UCR_PROGRAM_COUNTER) {
		uctx->pc = value;
	}
}

/* @ref.impl arch/arm64/kernel/setup.c::hwcap_str */
static const char *const hwcap_str[] = {
	"fp",
	"asimd",
	"evtstrm",
	"aes",
	"pmull",
	"sha1",
	"sha2",
	"crc32",
	"atomics",
	"fphp",
	"asimdhp",
	"cpuid",
	"asimdrdm",
	"sve",
	NULL
};

#define CPUINFO_LEN_PER_CORE 0x100
long ihk_mc_show_cpuinfo(char *buf, size_t buf_size, unsigned long read_off, int *eofp)
{
	extern int num_processors;
	int i = 0;
	char *lbuf = NULL;
	const size_t lbuf_size = CPUINFO_LEN_PER_CORE * num_processors;
	size_t loff = 0;
	long ret = 0;

	/* eof flag initialization */
	*eofp = 0;

	/* offset is over lbuf_size, return */
	if (read_off >= lbuf_size) {
		*eofp = 1;
		return 0;
	}

	/* local buffer allocate */
	lbuf = kmalloc(lbuf_size, IHK_MC_AP_NOWAIT);
	if (lbuf == NULL) {
		ekprintf("%s: ERROR Local buffer allocation failed.\n");
		ret = -ENOMEM;
		*eofp = 1;
		goto err;
	}
	memset(lbuf, '\0', lbuf_size);

	/* cpuinfo strings generate and copy */
	for (i = 0; i < num_processors; i++) {
		const struct cpuinfo_arm64 *cpuinfo = &cpuinfo_data[i];
		const unsigned int midr = cpuinfo->reg_midr;
		int j = 0;

		/* generate strings */
		loff += scnprintf(lbuf + loff, lbuf_size - loff,
				  "processor\t: %d\n", cpuinfo->hwid);
		loff += scnprintf(lbuf + loff, lbuf_size - loff, "Features\t:");

		for (j = 0; hwcap_str[j]; j++) {
			if (elf_hwcap & (1 << j)) {
				loff += scnprintf(lbuf + loff,
						  lbuf_size - loff,
						  " %s", hwcap_str[j]);
			}
		}
		loff += scnprintf(lbuf + loff, lbuf_size - loff, "\n");
		loff += scnprintf(lbuf + loff, lbuf_size - loff,
				  "CPU implementer\t: 0x%02x\n",
				  MIDR_IMPLEMENTOR(midr));
		loff += scnprintf(lbuf + loff, lbuf_size - loff,
				  "CPU architecture: 8\n");
		loff += scnprintf(lbuf + loff, lbuf_size - loff,
				  "CPU variant\t: 0x%x\n",
				  MIDR_VARIANT(midr));
		loff += scnprintf(lbuf + loff, lbuf_size - loff,
				  "CPU part\t: 0x%03x\n",
				  MIDR_PARTNUM(midr));
		loff += scnprintf(lbuf + loff, lbuf_size - loff,
				  "CPU revision\t: %d\n\n",
				  MIDR_REVISION(midr));

		/* check buffer depletion */
		if ((i < num_processors - 1) && ((lbuf_size - loff) == 1)) {
			ekprintf("%s: ERROR Local buffer size shortage.\n", __FUNCTION__);
			ret = -ENOMEM;
			*eofp = 1;
			goto err_free;
		}
	}

	/* copy to host buffer */
	memcpy(buf, lbuf + read_off, buf_size);
	if (read_off + buf_size >= loff) {
		*eofp = 1;
		ret = loff - read_off;
	} else {
		ret = buf_size;
	}

err_free:
	kfree(lbuf);
err:
	return ret;
}

static int check_and_allocate_fp_regs(struct thread *thread);

void arch_clone_thread(struct thread *othread, unsigned long pc,
			unsigned long sp, struct thread *nthread)
{
	unsigned long tls = 0;

	/* get tpidr_el0 value, and set original-thread->tlsblock_base, new-thread->tlsblock_base */
	asm("mrs %0, tpidr_el0" : "=r" (tls));
	othread->tlsblock_base = nthread->tlsblock_base = tls;

	/* if SVE enable, takeover lower 128 bit register */
	if (likely(elf_hwcap & HWCAP_SVE)) {
		fp_regs_struct fp_regs;

		memset(&fp_regs, 0, sizeof(fp_regs_struct));
		fpsimd_save_state(&fp_regs);
		thread_fpsimd_to_sve(nthread, &fp_regs);
	}
}

/*@
  @ requires \valid(handler);
  @ assigns __arm64_syscall_handler;
  @ ensures __arm64_syscall_handler == handler;
  @*/
void ihk_mc_set_syscall_handler(long (*handler)(int, ihk_mc_user_context_t *))
{
	__arm64_syscall_handler = handler;
}

/*@
  @ assigns \nothing;
  @*/
void ihk_mc_delay_us(int us)
{
	arch_delay(us);
}

void arch_print_stack(void)
{
}

void arch_show_interrupt_context(const void *reg)
{
	const struct pt_regs *regs = (struct pt_regs *)reg;
	kprintf("dump pt_regs:\n");
	kprintf("   x0 : %016lx  x1 : %016lx  x2 : %016lx  x3 : %016lx\n",
		regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3]);
	kprintf("   x4 : %016lx  x5 : %016lx  x6 : %016lx  x7 : %016lx\n",
		regs->regs[4], regs->regs[5], regs->regs[6], regs->regs[7]);
	kprintf("   x8 : %016lx  x9 : %016lx x10 : %016lx x11 : %016lx\n",
		regs->regs[8], regs->regs[9], regs->regs[10], regs->regs[11]);
	kprintf("  x12 : %016lx x13 : %016lx x14 : %016lx x15 : %016lx\n",
		regs->regs[12], regs->regs[13], regs->regs[14], regs->regs[15]);
	kprintf("  x16 : %016lx x17 : %016lx x18 : %016lx x19 : %016lx\n",
		regs->regs[16], regs->regs[17], regs->regs[18], regs->regs[19]);
	kprintf("  x20 : %016lx x21 : %016lx x22 : %016lx x23 : %016lx\n",
		regs->regs[20], regs->regs[21], regs->regs[22], regs->regs[23]);
	kprintf("  x24 : %016lx x25 : %016lx x26 : %016lx x27 : %016lx\n",
		regs->regs[24], regs->regs[25], regs->regs[26], regs->regs[27]);
	kprintf("  x28 : %016lx x29 : %016lx x30 : %016lx\n",
		regs->regs[28], regs->regs[29], regs->regs[30]);
	kprintf("  sp       : %016lx\n", regs->sp);
	kprintf("  pc       : %016lx\n", regs->pc);
	kprintf("  pstate   : %016lx(N:%d Z:%d C:%d V:%d SS:%d IL:%d D:%d A:%d I:%d F:%d M[4]:%d M:%d)\n",
		regs->pstate,
		(regs->pstate >> 31 & 1), (regs->pstate >> 30 & 1), (regs->pstate >> 29 & 1),
		(regs->pstate >> 28 & 1), (regs->pstate >> 21 & 1), (regs->pstate >> 20 & 1),
		(regs->pstate >>  9 & 1), (regs->pstate >>  8 & 1), (regs->pstate >>  7 & 1),
		(regs->pstate >>  6 & 1), (regs->pstate >>  4 & 1), (regs->pstate & 7));
	kprintf("  orig_x0   : %016lx\n", regs->orig_x0);
	kprintf("  syscallno : %016lx\n", regs->syscallno);
}

void arch_cpu_stop(void)
{
	psci_cpu_off();
}

/*@
  @ behavior fs_base:
  @   assumes type == IHK_ASR_X86_FS;
  @   ensures \result == 0;
  @ behavior invaiid_type:
  @   assumes type != IHK_ASR_X86_FS;
  @   ensures \result == -EINVAL;
  @*/
int ihk_mc_arch_set_special_register(enum ihk_asr_type type,
                                     unsigned long value)
{
/* TODO(pka_idle) */
	return -1;
}

/*@
  @ behavior fs_base:
  @   assumes type == IHK_ASR_X86_FS;
  @   requires \valid(value);
  @   ensures \result == 0;
  @ behavior invalid_type:
  @   assumes type != IHK_ASR_X86_FS;
  @   ensures \result == -EINVAL;
  @*/
int ihk_mc_arch_get_special_register(enum ihk_asr_type type,
                                     unsigned long *value)
{
/* TODO(pka_idle) */
	return -1;
}

/*@
  @ requires \valid_cpuid(cpu);     // valid CPU logical ID
  @ ensures \result == 0
  @*/
int ihk_mc_interrupt_cpu(int cpu, int vector)
{
	if (cpu < 0 || cpu >= num_processors) {
		kprintf("%s: invalid CPU id: %d\n", __func__, cpu);
		return -1;
	}
	dkprintf("[%d] ihk_mc_interrupt_cpu: %d\n", ihk_mc_get_processor_id(), cpu);
	(*arm64_issue_ipi)(cpu, vector);
	return 0;
}

/*
 * @ref.impl linux-linaro/arch/arm64/kernel/process.c::tls_thread_switch()
 */
static void tls_thread_switch(struct thread *prev, struct thread *next)
{
	unsigned long tpidr, tpidrro;

	asm("mrs %0, tpidr_el0" : "=r" (tpidr));
	prev->tlsblock_base = tpidr;

	tpidr = next->tlsblock_base;
	tpidrro = 0;

	asm(
	"	msr	tpidr_el0, %0\n"
	"	msr	tpidrro_el0, %1"
	: : "r" (tpidr), "r" (tpidrro));
}

struct thread *arch_switch_context(struct thread *prev, struct thread *next)
{
	// TODO[PMU]: 暫定的にここに関数宣言を置く。共通部のヘッダに書くのが作法だと思うが、今後の動向を様子見。
	extern void perf_start(struct mc_perf_event *event);
	extern void perf_reset(struct mc_perf_event *event);
	struct thread *last;
	struct mcs_rwlock_node_irqsave lock;

	/* Set up new TLS.. */
	dkprintf("[%d] arch_switch_context: tlsblock_base: 0x%lX\n", 
		 ihk_mc_get_processor_id(), next->tlsblock_base);

#ifdef ENABLE_PERF
	/* Performance monitoring inherit */
	if(next->proc->monitoring_event) {
		if(next->proc->perf_status == PP_RESET)
			perf_reset(next->proc->monitoring_event);
		if(next->proc->perf_status != PP_COUNT) {
			perf_reset(next->proc->monitoring_event);
			perf_start(next->proc->monitoring_event);
		}
	}
#endif /*ENABLE_PERF*/

#ifdef PROFILE_ENABLE
	if (prev && prev->profile && prev->profile_start_ts != 0) {
		prev->profile_elapsed_ts +=
			(rdtsc() - prev->profile_start_ts);
		prev->profile_start_ts = 0;
	}

	if (next->profile && next->profile_start_ts == 0) {
		next->profile_start_ts = rdtsc();
	}
#endif

	if (likely(prev)) {
		tls_thread_switch(prev, next);

		mcs_rwlock_writer_lock(&prev->proc->update_lock, &lock);
		if (prev->proc->status & (PS_DELAY_STOPPED | PS_DELAY_TRACED)) {
			switch (prev->proc->status) {
			case PS_DELAY_STOPPED:
				prev->proc->status = PS_STOPPED;
				break;
			case PS_DELAY_TRACED:
				prev->proc->status = PS_TRACED;
				break;
			default:
				break;
			}
			mcs_rwlock_writer_unlock(&prev->proc->update_lock, &lock);

			/* Wake up the parent who tried wait4 and sleeping */
			waitq_wakeup(&prev->proc->parent->waitpid_q);
		} else {
			mcs_rwlock_writer_unlock(&prev->proc->update_lock, &lock);
		}

		last = ihk_mc_switch_context(&prev->ctx, &next->ctx, prev);
	}
	else {
		last = ihk_mc_switch_context(NULL, &next->ctx, prev);
	}

	return last;
}

/*@
  @ requires \valid(thread);
  @ ensures thread->fp_regs == NULL;
  @*/
void
release_fp_regs(struct thread *thread)
{
	if (!thread) {
		return;
	}

	if (likely(elf_hwcap & (HWCAP_FP | HWCAP_ASIMD))) {
		int pages;

		if (thread->fp_regs) {
			// calcurate number of pages for fp regs area
			pages = (sizeof(fp_regs_struct) + PAGE_SIZE -1) >> PAGE_SHIFT;
			ihk_mc_free_pages(thread->fp_regs, pages);
			thread->fp_regs = NULL;
		}

#ifdef CONFIG_ARM64_SVE
		if (likely(elf_hwcap & HWCAP_SVE)) {
			sve_free(thread);
		}
#endif /* CONFIG_ARM64_SVE */
	}
}

static int
check_and_allocate_fp_regs(struct thread *thread)
{
	int	result = 0;
	int	pages;

	if (!thread->fp_regs) {
		pages = (sizeof(fp_regs_struct) + PAGE_SIZE -1) >> PAGE_SHIFT;
		thread->fp_regs = ihk_mc_alloc_pages(pages, IHK_MC_AP_NOWAIT);

		if (!thread->fp_regs) {
			kprintf("error: allocating fp_regs pages\n");
			result = -ENOMEM;
			goto out;
		}

		memset(thread->fp_regs, 0, sizeof(fp_regs_struct));
	}

#ifdef CONFIG_ARM64_SVE
	if (likely(elf_hwcap & HWCAP_SVE)) {
		result = sve_alloc(thread);
	}
#endif /* CONFIG_ARM64_SVE */
out:
	if (result) {
		release_fp_regs(thread);
	}
	return result;
}

/*@
  @ requires \valid(thread);
  @*/
int
save_fp_regs(struct thread *thread)
{
	int ret = 0;
	if (thread == &cpu_local_var(idle)) {
		goto out;
	}

	if (likely(elf_hwcap & (HWCAP_FP | HWCAP_ASIMD))) {
		ret = check_and_allocate_fp_regs(thread);
		if (ret) {
			goto out;
		}
		thread_fpsimd_save(thread);
	}
out:
	return ret;
}

int copy_fp_regs(struct thread *from, struct thread *to)
{
	int ret = 0;

	if (from->fp_regs != NULL) {
		ret = check_and_allocate_fp_regs(to);
		if (!ret) {
			memcpy(to->fp_regs,
			       from->fp_regs,
			       sizeof(fp_regs_struct));
		}
	}
	return ret;
}

void clear_fp_regs(void)
{
	if (likely(elf_hwcap & (HWCAP_FP | HWCAP_ASIMD))) {
#ifdef CONFIG_ARM64_SVE
		if (likely(elf_hwcap & HWCAP_SVE)) {
			unsigned int fpscr[2] = { 0, 0 };
			unsigned int vl = current_thread_info()->sve_vl;
			struct fpsimd_sve_state(sve_vq_from_vl(sve_max_vl)) clear_sve;

			if (vl == 0) {
				vl = sve_default_vl;
			}
			memset(&clear_sve, 0, sizeof(clear_sve));
			sve_load_state(clear_sve.ffr, fpscr, sve_vq_from_vl(vl) - 1);
		} else {
			fp_regs_struct clear_fp;
			memset(&clear_fp, 0, sizeof(fp_regs_struct));
			fpsimd_load_state(&clear_fp);
		}
#else /* CONFIG_ARM64_SVE */
		fp_regs_struct clear_fp;
		memset(&clear_fp, 0, sizeof(fp_regs_struct));
		fpsimd_load_state(&clear_fp);
#endif /* CONFIG_ARM64_SVE */
	}
}

/*@
  @ requires \valid(thread);
  @ assigns thread->fp_regs;
  @*/
void
restore_fp_regs(struct thread *thread)
{
	if (likely(elf_hwcap & (HWCAP_FP | HWCAP_ASIMD))) {
		if (!thread->fp_regs) {
			// only clear fpregs.
			clear_fp_regs();
			return;
		}
		thread_fpsimd_load(thread);
	}
}

void init_tick(void)
{
	dkprintf("init_tick():\n");
	return;
}

void init_delay(void)
{
	dkprintf("init_delay():\n");
	return;
}

void sync_tick(void)
{
	dkprintf("sync_tick():\n");
	return;
}

void arch_start_pvclock(void)
{
	/* linux-linaro(aarch64)ではKVM向けpvclockの処理が未サポート */
	dkprintf("arch_start_pvclock(): not supported\n");
	return;
}

void
mod_nmi_ctx(void *nmi_ctx, void (*func)())
{
	func();
}

extern void freeze(void);
void __freeze(void)
{
	freeze();
}


#define SYSREG_READ_S(sys_reg)  case (sys_reg): asm volatile("mrs_s %0, " __stringify(sys_reg) : "=r" (*val)); break
static inline int arch_cpu_mrs(uint32_t sys_reg, uint64_t *val)
{
	int ret = 0;

	switch (sys_reg) {
		SYSREG_READ_S(IMP_FJ_TAG_ADDRESS_CTRL_EL1);
		SYSREG_READ_S(IMP_SCCR_CTRL_EL1);
		SYSREG_READ_S(IMP_SCCR_ASSIGN_EL1);
		SYSREG_READ_S(IMP_SCCR_SET0_L2_EL1);
		SYSREG_READ_S(IMP_SCCR_SET1_L2_EL1);
		SYSREG_READ_S(IMP_SCCR_L1_EL0);
		SYSREG_READ_S(IMP_PF_CTRL_EL1);
		SYSREG_READ_S(IMP_PF_STREAM_DETECT_CTRL_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_CTRL0_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_CTRL1_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_CTRL2_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_CTRL3_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_CTRL4_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_CTRL5_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_CTRL6_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_CTRL7_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_DISTANCE0_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_DISTANCE1_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_DISTANCE2_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_DISTANCE3_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_DISTANCE4_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_DISTANCE5_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_DISTANCE6_EL0);
		SYSREG_READ_S(IMP_PF_INJECTION_DISTANCE7_EL0);
		SYSREG_READ_S(IMP_PF_PMUSERENR_EL0);
		SYSREG_READ_S(IMP_BARRIER_CTRL_EL1);
		SYSREG_READ_S(IMP_BARRIER_BST_BIT_EL1);
		SYSREG_READ_S(IMP_BARRIER_INIT_SYNC_BB0_EL1);
		SYSREG_READ_S(IMP_BARRIER_INIT_SYNC_BB1_EL1);
		SYSREG_READ_S(IMP_BARRIER_INIT_SYNC_BB2_EL1);
		SYSREG_READ_S(IMP_BARRIER_INIT_SYNC_BB3_EL1);
		SYSREG_READ_S(IMP_BARRIER_INIT_SYNC_BB4_EL1);
		SYSREG_READ_S(IMP_BARRIER_INIT_SYNC_BB5_EL1);
		SYSREG_READ_S(IMP_BARRIER_ASSIGN_SYNC_W0_EL1);
		SYSREG_READ_S(IMP_BARRIER_ASSIGN_SYNC_W1_EL1);
		SYSREG_READ_S(IMP_BARRIER_ASSIGN_SYNC_W2_EL1);
		SYSREG_READ_S(IMP_BARRIER_ASSIGN_SYNC_W3_EL1);
		SYSREG_READ_S(IMP_SOC_STANDBY_CTRL_EL1);
		SYSREG_READ_S(IMP_FJ_CORE_UARCH_CTRL_EL2);
		SYSREG_READ_S(IMP_FJ_CORE_UARCH_RESTRECTION_EL1);
		/* fall through */
	default:
		return -EINVAL;
	}
	return ret;
}

static inline int arch_cpu_read_register(struct ihk_os_cpu_register *desc)
{
	int ret = 0;
	uint64_t value;

	if (desc->addr) {
		panic("memory mapped register is not supported.\n");
	} else if (desc->addr_ext) {
		ret = arch_cpu_mrs(desc->addr_ext, &value);
		if (ret == 0) {
			desc->val = value;
		}
	} else {
		ret = -EINVAL;
	}
	return ret;
}

#define SYSREG_WRITE_S(sys_reg) case (sys_reg): asm volatile("msr_s " __stringify(sys_reg) ", %0" :: "r" (val)); break
static inline int arch_cpu_msr(uint32_t sys_reg, uint64_t val)
{
	int ret = 0;

	switch (sys_reg) {
	SYSREG_WRITE_S(IMP_FJ_TAG_ADDRESS_CTRL_EL1);
	SYSREG_WRITE_S(IMP_SCCR_CTRL_EL1);
	SYSREG_WRITE_S(IMP_SCCR_ASSIGN_EL1);
	SYSREG_WRITE_S(IMP_SCCR_SET0_L2_EL1);
	SYSREG_WRITE_S(IMP_SCCR_SET1_L2_EL1);
	SYSREG_WRITE_S(IMP_SCCR_L1_EL0);
	SYSREG_WRITE_S(IMP_PF_CTRL_EL1);
	SYSREG_WRITE_S(IMP_PF_STREAM_DETECT_CTRL_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_CTRL0_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_CTRL1_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_CTRL2_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_CTRL3_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_CTRL4_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_CTRL5_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_CTRL6_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_CTRL7_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_DISTANCE0_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_DISTANCE1_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_DISTANCE2_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_DISTANCE3_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_DISTANCE4_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_DISTANCE5_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_DISTANCE6_EL0);
	SYSREG_WRITE_S(IMP_PF_INJECTION_DISTANCE7_EL0);
	SYSREG_WRITE_S(IMP_PF_PMUSERENR_EL0);
	SYSREG_WRITE_S(IMP_BARRIER_CTRL_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_BST_BIT_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_INIT_SYNC_BB0_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_INIT_SYNC_BB1_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_INIT_SYNC_BB2_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_INIT_SYNC_BB3_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_INIT_SYNC_BB4_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_INIT_SYNC_BB5_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_ASSIGN_SYNC_W0_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_ASSIGN_SYNC_W1_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_ASSIGN_SYNC_W2_EL1);
	SYSREG_WRITE_S(IMP_BARRIER_ASSIGN_SYNC_W3_EL1);
	SYSREG_WRITE_S(IMP_FJ_CORE_UARCH_CTRL_EL2);
	SYSREG_WRITE_S(IMP_FJ_CORE_UARCH_RESTRECTION_EL1);
	/* fallthrough */
	case IMP_SOC_STANDBY_CTRL_EL1:
		asm volatile("msr_s " __stringify(IMP_SOC_STANDBY_CTRL_EL1) ", %0"
			     : : "r" (val) : "memory");
		if (val & IMP_SOC_STANDBY_CTRL_EL1_MODE_CHANGE) {
			wfe();
		}
		break;
	default:
		return -EINVAL;
	}
	return ret;
}

static inline int arch_cpu_write_register(struct ihk_os_cpu_register *desc)
{
	int ret = 0;

	if (desc->addr) {
		panic("memory mapped register is not supported.\n");
	} else if (desc->addr_ext) {
		ret = arch_cpu_msr(desc->addr_ext, desc->val);
	} else {
		ret = -EINVAL;
	}
	return ret;
}

int arch_cpu_read_write_register(
		struct ihk_os_cpu_register *desc,
		enum mcctrl_os_cpu_operation op)
{
	int ret;
	if (op == MCCTRL_OS_CPU_READ_REGISTER) {
		ret = arch_cpu_read_register(desc);
	}
	else if (op == MCCTRL_OS_CPU_WRITE_REGISTER) {
		ret = arch_cpu_write_register(desc);
	}
	else {
		ret = -1;
	}

	dkprintf("%s: MCCTRL_OS_CPU_%s_REGISTER: reg: 0x%lx, val: 0x%lx\n",
			__FUNCTION__,
			(op == MCCTRL_OS_CPU_READ_REGISTER ? "READ" : "WRITE"),
			desc->addr, desc->val);

	return ret;
}

int smp_call_func(cpu_set_t *__cpu_set, smp_func_t __func, void *__arg)
{
	/* TODO: skeleton for smp_call_func */
	return -1;
}

void arch_flush_icache_all(void)
{
	asm("ic	ialluis");
	dsb(ish);
}
/*** end of file ***/
