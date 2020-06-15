/* irq-gic-v3.c COPYRIGHT FUJITSU LIMITED 2015-2018 */
#include <irq.h>
#include <arm-gic-v2.h>
#include <arm-gic-v3.h>
#include <io.h>
#include <cputype.h>
#include <process.h>
#include <syscall.h>
#include <ihk/debug.h>
#include <ihk/monitor.h>
#include <arch-timer.h>
#include <cls.h>

//#define DEBUG_GICV3

#define USE_CAVIUM_THUNDER_X

#ifdef DEBUG_GICV3
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#ifdef USE_CAVIUM_THUNDER_X
static char is_cavium_thunderx = 0;
#endif

void *dist_base;
void *rdist_base[NR_CPUS];

extern uint64_t ihk_param_cpu_logical_map;
static uint64_t *__cpu_logical_map = &ihk_param_cpu_logical_map;

extern uint64_t ihk_param_gic_rdist_base_pa[NR_CPUS];

#define cpu_logical_map(cpu)    __cpu_logical_map[cpu]

/* Our default, arbitrary priority value. Linux only uses one anyway. */
#define DEFAULT_PMR_VALUE	0xf0

/**
 * Low level accessors
 * @ref.impl host-kernel/drivers/irqchip/irq-gic-v3.c
 */
static uint64_t gic_read_iar_common(void)
{
	uint64_t irqstat;

#ifdef CONFIG_HAS_NMI
	uint64_t daif;
	uint64_t pmr;
	uint64_t default_pmr_value = DEFAULT_PMR_VALUE;

	/*
	 * The PMR may be configured to mask interrupts when this code is
	 * called, thus in order to acknowledge interrupts we must set the
	 * PMR to its default value before reading from the IAR.
	 *
	 * To do this without taking an interrupt we also ensure the I bit
	 * is set whilst we are interfering with the value of the PMR.
	 */
	asm volatile(
		"mrs  %1, daif\n\t"				/* save I bit  */
		"msr  daifset, #2\n\t"				/* set I bit   */
		"mrs_s  %2, " __stringify(ICC_PMR_EL1) "\n\t"	/* save PMR    */
		"msr_s  " __stringify(ICC_PMR_EL1) ",%3\n\t"	/* set PMR     */
		"mrs_s  %0, " __stringify(ICC_IAR1_EL1) "\n\t"	/* ack int   */
		"msr_s  " __stringify(ICC_PMR_EL1) ",%2\n\t"	/* restore PMR */
		"isb\n\t"
		"msr  daif, %1"					/* restore I   */
		: "=r" (irqstat), "=&r" (daif), "=&r" (pmr)
		: "r" (default_pmr_value));
#else /* CONFIG_HAS_NMI */
	asm volatile("mrs_s %0, " __stringify(ICC_IAR1_EL1) : "=r" (irqstat));
#endif /* CONFIG_HAS_NMI */

	return irqstat;
}

#ifdef USE_CAVIUM_THUNDER_X
/* Cavium ThunderX erratum 23154 */
static uint64_t gic_read_iar_cavium_thunderx(void)
{
	uint64_t irqstat;

#ifdef CONFIG_HAS_NMI
	uint64_t daif;
	uint64_t pmr;
	uint64_t default_pmr_value = DEFAULT_PMR_VALUE;

	/*
	 * The PMR may be configured to mask interrupts when this code is
	 * called, thus in order to acknowledge interrupts we must set the
	 * PMR to its default value before reading from the IAR.
	 *
	 * To do this without taking an interrupt we also ensure the I bit
	 * is set whilst we are interfering with the value of the PMR.
	 */
	asm volatile(
		"mrs  %1, daif\n\t"				/* save I bit  */
		"msr  daifset, #2\n\t"				/* set I bit   */
		"mrs_s  %2, " __stringify(ICC_PMR_EL1) "\n\t"	/* save PMR    */
		"msr_s  " __stringify(ICC_PMR_EL1) ",%3\n\t"	/* set PMR     */
		"nop;nop;nop;nop\n\t"
		"nop;nop;nop;nop\n\t"
		"mrs_s  %0, " __stringify(ICC_IAR1_EL1) "\n\t"	/* ack int   */
		"nop;nop;nop;nop\n\t"
		"msr_s  " __stringify(ICC_PMR_EL1) ",%2\n\t"	/* restore PMR */
		"isb\n\t"
		"msr  daif, %1"					/* restore I   */
		: "=r" (irqstat), "=&r" (daif), "=&r" (pmr)
		: "r" (default_pmr_value));
#else /* CONFIG_HAS_NMI */
	asm volatile("nop;nop;nop;nop;");
	asm volatile("nop;nop;nop;nop;");
	asm volatile("mrs_s %0, " __stringify(ICC_IAR1_EL1) : "=r" (irqstat));
	asm volatile("nop;nop;nop;nop;");
#endif /* CONFIG_HAS_NMI */
	mb();

	return irqstat;
}
#endif

static uint64_t gic_read_iar(void)
{
#ifdef USE_CAVIUM_THUNDER_X
	if (is_cavium_thunderx)
		return gic_read_iar_cavium_thunderx();
	else
#endif
		return gic_read_iar_common();

}

static void gic_write_pmr(uint64_t val)
{
	asm volatile("msr_s " __stringify(ICC_PMR_EL1) ", %0" : : "r" (val));
}

static void gic_write_ctlr(uint64_t val)
{
	asm volatile("msr_s " __stringify(ICC_CTLR_EL1) ", %0" : : "r" (val));
	isb();
}

static void gic_write_grpen1(uint64_t val)
{
	asm volatile("msr_s " __stringify(ICC_GRPEN1_EL1) ", %0" : : "r" (val));
	isb();
}

static inline void gic_write_eoir(uint64_t irq)
{
	asm volatile("msr_s " __stringify(ICC_EOIR1_EL1) ", %0" : : "r" (irq));
	isb();
}

static void gic_write_sgi1r(uint64_t val)
{
	asm volatile("msr_s " __stringify(ICC_SGI1R_EL1) ", %0" : : "r" (val));
}

static inline uint32_t gic_read_sre(void)
{
	uint64_t val;

	asm volatile("mrs_s %0, " __stringify(ICC_SRE_EL1) : "=r" (val));
	return val;
}

static inline void gic_write_sre(uint32_t val)
{
	asm volatile("msr_s " __stringify(ICC_SRE_EL1) ", %0" : : "r" ((uint64_t)val));
	isb();
}

static uint32_t gic_enable_sre(void)
{
	uint32_t val;

	val = gic_read_sre();
	if (val & ICC_SRE_EL1_SRE)
		return 1; /*ok*/

	val |= ICC_SRE_EL1_SRE;
	gic_write_sre(val);
	val = gic_read_sre();

	return !!(val & ICC_SRE_EL1_SRE);
}

#ifdef CONFIG_HAS_NMI
static inline void gic_write_bpr1(uint32_t val)
{
	asm volatile("msr_s " __stringify(ICC_BPR1_EL1) ", %0" : : "r" (val));
}
#endif

static void __arm64_raise_sgi_gicv3(uint32_t hw_cpuid, uint32_t vector)
{
	uint64_t mpidr, cluster_id;
	uint16_t tlist;
	uint64_t val;

	/*
	 * Ensure that stores to Normal memory are visible to the
	 * other CPUs before issuing the IPI.
	 */
	smp_wmb();

	mpidr = cpu_logical_map(hw_cpuid);
	if((mpidr & 0xffUL) < 16) {
		cluster_id = cpu_logical_map(hw_cpuid) & ~0xffUL;
		tlist = (uint16_t)(1 << (mpidr & 0xf));
	
#define MPIDR_TO_SGI_AFFINITY(cluster_id, level) \
	(MPIDR_AFFINITY_LEVEL(cluster_id, level) \
		<< ICC_SGI1R_AFFINITY_## level ##_SHIFT)

		val = (MPIDR_TO_SGI_AFFINITY(cluster_id, 3)	|
		       MPIDR_TO_SGI_AFFINITY(cluster_id, 2)	|
		       vector << ICC_SGI1R_SGI_ID_SHIFT		|
		       MPIDR_TO_SGI_AFFINITY(cluster_id, 1)	|
		       tlist << ICC_SGI1R_TARGET_LIST_SHIFT);
	
		dkprintf("CPU%d: ICC_SGI1R_EL1 %llx\n", ihk_mc_get_processor_id(), val);
		gic_write_sgi1r(val);

		/* Force the above writes to ICC_SGI1R_EL1 to be executed */
		isb();
	}  else {
		/*
		 * If we ever get a cluster of more than 16 CPUs, just
		 * scream and skip that CPU.
		 */
		ekprintf("GICv3 can't send SGI for TargetList=%d\n", (mpidr & 0xffUL));
	}
}

static void arm64_raise_sgi_gicv3(uint32_t cpuid, uint32_t vector)
{
	/* Build interrupt destination of the target CPU */
	uint32_t hw_cpuid = ihk_mc_get_cpu_info()->hw_ids[cpuid];

	__arm64_raise_sgi_gicv3(hw_cpuid, vector);
}

static void arm64_raise_sgi_to_host_gicv3(uint32_t cpuid, uint32_t vector)
{
	/* Build interrupt destination of the target Linux/host CPU */
	uint32_t hw_cpuid = ihk_mc_get_apicid(cpuid);

	__arm64_raise_sgi_gicv3(hw_cpuid, vector);
}

static void arm64_raise_spi_gicv3(uint32_t cpuid, uint32_t vector)
{
	uint64_t spi_reg_offset;
	uint32_t spi_set_pending_bitpos;

	/**
	 * calculates register offset and bit position corresponding to the numbers.
	 *
	 * For interrupt vector m, 
	 * - the corresponding GICD_ISPENDR number, n, is given by n = m / 32 
	 * - the offset of the required GICD_ISPENDR is (0x200 + (4*n)) 
	 * - the bit number of the required Set-pending bit in this register is m % 32.
	 */
	spi_reg_offset = vector / 32 * 4;
	spi_set_pending_bitpos = vector % 32;

	/* write to GICD_ISPENDR */
	writel_relaxed(
		1 << spi_set_pending_bitpos, 
		(void *)(dist_base + GICD_ISPENDR + spi_reg_offset)
	);
}

static void arm64_raise_lpi_gicv3(uint32_t cpuid, uint32_t vector)
{
	// @todo.impl
	ekprintf("%s called.\n", __func__);
}
 
void arm64_issue_host_ipi_gicv3(uint32_t cpuid, uint32_t vector)
{
	arm64_raise_sgi_to_host_gicv3(cpuid, vector);
}

void arm64_issue_ipi_gicv3(uint32_t cpuid, uint32_t vector)
{
	dkprintf("Send irq#%d to cpuid=%d\n", vector, cpuid);

	barrier();
	if(vector < 16){
		// send SGI
		arm64_raise_sgi_gicv3(cpuid, vector);
	} else if (32 <= vector && vector < 1020) {
		// send SPI (allow only to host)
		arm64_raise_spi_gicv3(cpuid, vector);
	} else if (8192 <= vector) {
		// send LPI (allow only to host)
		arm64_raise_lpi_gicv3(cpuid, vector);
	} else {
		ekprintf("#%d is bad irq number.\n", vector);
	}
}

extern int interrupt_from_user(void *);
void handle_interrupt_gicv3(struct pt_regs *regs)
{
	uint64_t irqnr;
	const int from_user = interrupt_from_user(regs);
	struct cpu_local_var *v = get_this_cpu_local_var();
	//unsigned long irqflags;
	int do_check = 0;
	struct ihk_os_cpu_monitor *monitor = cpu_local_var(monitor);

	++v->in_interrupt;
	irqnr = gic_read_iar();
	cpu_enable_nmi();
	set_cputime(from_user ? CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);
	while (irqnr != ICC_IAR1_EL1_SPURIOUS) {
		if ((irqnr < 1020) || (irqnr >= 8192)) {
			gic_write_eoir(irqnr);
			/* Once paniced, only allow CPU stop and NMI IRQs */
			if (monitor->status != IHK_OS_MONITOR_PANIC ||
					irqnr == INTRID_CPU_STOP ||
					irqnr == INTRID_MULTI_NMI) {
				handle_IPI(irqnr, regs);
			}
		}
		irqnr = gic_read_iar();
	}
	set_cputime(from_user ? CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);

	//irqflags = ihk_mc_spinlock_lock(&v->runq_lock);
	/* For migration by IPI or by timesharing */
	if (v->flags &
	    (CPU_FLAG_NEED_MIGRATE | CPU_FLAG_NEED_RESCHED)) {
		v->flags &= ~CPU_FLAG_NEED_RESCHED;
		do_check = 1;
	}
	//ihk_mc_spinlock_unlock(&v->runq_lock, irqflags);

	--v->in_interrupt;
	if (monitor->status != IHK_OS_MONITOR_PANIC && do_check) {
		check_signal(0, regs, 0);
		schedule();
	}
}

static uint64_t gic_mpidr_to_affinity(unsigned long mpidr)
{
	uint64_t aff;

	aff = ((uint64_t)MPIDR_AFFINITY_LEVEL(mpidr, 3) << 32 |
			 MPIDR_AFFINITY_LEVEL(mpidr, 2) << 16 |
			 MPIDR_AFFINITY_LEVEL(mpidr, 1) << 8  |
			 MPIDR_AFFINITY_LEVEL(mpidr, 0));
	return aff;
}

static void init_spi_routing(uint32_t irq, uint32_t linux_cpu)
{
	uint64_t spi_route_reg_val, spi_route_reg_offset;

	if (irq < 32 || 1020 <= irq) {
		ekprintf("%s: irq is not spi number. (irq=%d)\n",
			 __func__, irq);
		return;
	}

	/* write to GICD_IROUTER */
	spi_route_reg_offset = irq * 8;
	spi_route_reg_val = gic_mpidr_to_affinity(cpu_logical_map(linux_cpu));

	writeq_relaxed(spi_route_reg_val,
		       (void *)(dist_base + GICD_IROUTER +
				spi_route_reg_offset));
}

void gic_dist_init_gicv3(unsigned long dist_base_pa, unsigned long size)
{
#ifndef IHK_IKC_USE_LINUX_WORK_IRQ
	extern int spi_table[];
	extern int nr_spi_table;
	int i;
#endif // !IHK_IKC_USE_LINUX_WORK_IRQ

	dist_base = map_fixed_area(dist_base_pa, size, 1 /*non chachable*/);

#ifdef USE_CAVIUM_THUNDER_X
	/* Cavium ThunderX erratum 23154 */
	if (MIDR_IMPLEMENTOR(read_cpuid_id()) == ARM_CPU_IMP_CAVIUM) {
		is_cavium_thunderx = 1;
	}
#endif

#ifndef IHK_IKC_USE_LINUX_WORK_IRQ
	/* initialize spi routing */
	for (i = 0; i < nr_spi_table; i++) {
		if (spi_table[i] == -1) {
			continue;
		}
		init_spi_routing(spi_table[i], i);
	}
#endif // !IHK_IKC_USE_LINUX_WORK_IRQ
}

void gic_cpu_init_gicv3(unsigned long cpu_base_pa, unsigned long size)
{
	int32_t cpuid, hw_cpuid;
	struct ihk_mc_cpu_info *cpu_info = ihk_mc_get_cpu_info();

	for(cpuid = 0; cpuid < cpu_info->ncpus; cpuid++) {
		hw_cpuid = cpu_info->hw_ids[cpuid];
		if(ihk_param_gic_rdist_base_pa[hw_cpuid] != 0) {
			rdist_base[hw_cpuid] = 
				map_fixed_area(ihk_param_gic_rdist_base_pa[hw_cpuid], size, 1 /*non chachable*/);
		}
	}
}

static void gic_do_wait_for_rwp(void *base)
{
	uint32_t count = 1000000;	/* 1s! */

	while (readl_relaxed(base + GICD_CTLR) & GICD_CTLR_RWP) {
		count--;
		if (!count) {
			ekprintf("RWP timeout, gone fishing\n");
			return;
		}
		cpu_pause();
	};
}

void gic_enable_gicv3(void)
{
	void *rbase = rdist_base[ihk_mc_get_hardware_processor_id()];
	void *rd_sgi_base = rbase + 0x10000 /* SZ_64K */;
	int i;
	unsigned int enable_ppi_sgi = GICD_INT_EN_SET_SGI;
	extern int ihk_param_nr_pmu_irq_affi;
	extern int ihk_param_pmu_irq_affi[CONFIG_SMP_MAX_CORES];

	enable_ppi_sgi |= GICD_ENABLE << get_timer_intrid();

	if (0 < ihk_param_nr_pmu_irq_affi) {
		for (i = 0; i < ihk_param_nr_pmu_irq_affi; i++) {
			if ((0 <= ihk_param_pmu_irq_affi[i]) &&
			    (ihk_param_pmu_irq_affi[i] <
			     sizeof(enable_ppi_sgi) * BITS_PER_BYTE)) {
				enable_ppi_sgi |= GICD_ENABLE <<
					ihk_param_pmu_irq_affi[i];
			}
		}
	}
	else {
		enable_ppi_sgi |= GICD_ENABLE << INTRID_PERF_OVF;
	}

	/*
	 * Deal with the banked PPI and SGI interrupts - disable all
	 * PPI interrupts, ensure all SGI interrupts are enabled.
	 */
	writel_relaxed(~enable_ppi_sgi, rd_sgi_base + GIC_DIST_ENABLE_CLEAR);
	writel_relaxed(enable_ppi_sgi, rd_sgi_base + GIC_DIST_ENABLE_SET);

	/*
	 * Set priority on PPI and SGI interrupts
	 */
	for (i = 0; i < 32; i += 4) {
		writel_relaxed(GICD_INT_DEF_PRI_X4,
			       rd_sgi_base + GIC_DIST_PRI + i);
	}

	/* sync wait */
	gic_do_wait_for_rwp(rbase);

	/*
	 * Need to check that the SRE bit has actually been set. If
	 * not, it means that SRE is disabled at EL2. We're going to
	 * die painfully, and there is nothing we can do about it.
	 *
	 * Kindly inform the luser.
	 */
	if (!gic_enable_sre())
		panic("GIC: unable to set SRE (disabled at EL2), panic ahead\n");

#ifndef CONFIG_HAS_NMI
	/* Set priority mask register */
	gic_write_pmr(DEFAULT_PMR_VALUE);
#endif
	
	/* EOI deactivates interrupt too (mode 0) */
	gic_write_ctlr(ICC_CTLR_EL1_EOImode_drop_dir);

	/* ... and let's hit the road... */
	gic_write_grpen1(1);

#ifdef CONFIG_HAS_NMI
	/*
	 * Some firmwares hand over to the kernel with the BPR changed from
	 * its reset value (and with a value large enough to prevent
	 * any pre-emptive interrupts from working at all). Writing a zero
	 * to BPR restores is reset value.
	 */
	gic_write_bpr1(0);

	/* Set specific IPI to NMI */
	writeb_relaxed(GICD_INT_NMI_PRI,
		       rd_sgi_base + GIC_DIST_PRI + INTRID_CPU_STOP);
	writeb_relaxed(GICD_INT_NMI_PRI,
		       rd_sgi_base + GIC_DIST_PRI + INTRID_MULTI_NMI);
	writeb_relaxed(GICD_INT_NMI_PRI,
		       rd_sgi_base + GIC_DIST_PRI + INTRID_STACK_TRACE);

	/* sync wait */
	gic_do_wait_for_rwp(rbase);
#endif /* CONFIG_HAS_NMI */
}
