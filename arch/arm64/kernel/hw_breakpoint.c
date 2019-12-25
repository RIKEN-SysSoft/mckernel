/* hw_breakpoint.c COPYRIGHT FUJITSU LIMITED 2016 */
#include <ihk/debug.h>
#include <cputype.h>
#include <errno.h>
#include <elfcore.h>
#include <ptrace.h>
#include <hw_breakpoint.h>
#include <arch-memory.h>
#include <signal.h>
#include <process.h>
#include <debug-monitors.h>

void aarch64_setup_kernel_breakpoint(int i, unsigned long addr, int j);

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::core_num_[brps|wrps] */
/* Number of BRP/WRP registers on this CPU. */
int core_num_brps;
int core_num_wrps;

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::get_num_brps */
/* Determine number of BRP registers available. */
int get_num_brps(void)
{
	return ((read_cpuid(ID_AA64DFR0_EL1) >> 12) & 0xf) + 1;
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::get_num_wrps */
/* Determine number of WRP registers available. */
int get_num_wrps(void)
{
	return ((read_cpuid(ID_AA64DFR0_EL1) >> 20) & 0xf) + 1;
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::hw_breakpoint_slots */
int hw_breakpoint_slots(int type)
{
	/*
	 * We can be called early, so don't rely on
	 * our static variables being initialised.
	 */
	switch (type) {
	case TYPE_INST:
		return get_num_brps();
	case TYPE_DATA:
		return get_num_wrps();
	default:
		kprintf("unknown slot type: %d\n", type);
		return 0;
	}
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::READ_WB_REG_CASE */
#define READ_WB_REG_CASE(OFF, N, REG, VAL)	\
	case (OFF + N):				\
		AARCH64_DBG_READ(N, REG, VAL);	\
		break

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::READ_WB_REG_CASE */
#define WRITE_WB_REG_CASE(OFF, N, REG, VAL)	\
	case (OFF + N):				\
		AARCH64_DBG_WRITE(N, REG, VAL);	\
		break

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::GEN_READ_WB_REG_CASES */
#define GEN_READ_WB_REG_CASES(OFF, REG, VAL)	\
	READ_WB_REG_CASE(OFF,  0, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  1, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  2, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  3, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  4, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  5, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  6, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  7, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  8, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  9, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 10, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 11, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 12, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 13, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 14, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 15, REG, VAL)

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::GEN_WRITE_WB_REG_CASES */
#define GEN_WRITE_WB_REG_CASES(OFF, REG, VAL)	\
	WRITE_WB_REG_CASE(OFF,  0, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  1, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  2, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  3, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  4, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  5, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  6, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  7, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  8, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  9, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 10, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 11, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 12, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 13, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 14, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 15, REG, VAL)

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::read_wb_reg */
unsigned long read_wb_reg(int reg, int n)
{
	unsigned long val = 0;

	switch (reg + n) {
	GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
	GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
	GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
	GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
	default:
		kprintf("attempt to read from unknown breakpoint register %d\n", n);
	}

	return val;
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::write_wb_reg */
void write_wb_reg(int reg, int n, unsigned long val)
{
	switch (reg + n) {
	GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
	GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
	GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
	GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
	default:
		kprintf("attempt to write to unknown breakpoint register %d\n", n);
	}
	isb();
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::hw_breakpoint_reset */
void hw_breakpoint_reset(void)
{
	int i = 0;

	/* clear DBGBVR<n>_EL1 and DBGBCR<n>_EL1 (n=0-(core_num_brps-1)) */
	for (i = 0; i < core_num_brps; i++) {
		write_wb_reg(AARCH64_DBG_REG_BVR, i, 0UL);
		write_wb_reg(AARCH64_DBG_REG_BCR, i, 0UL);
	}

	/* clear DBGWVR<n>_EL1 and DBGWCR<n>_EL1 (n=0-(core_num_wrps-1)) */
	for (i = 0; i < core_num_wrps; i++) {
		write_wb_reg(AARCH64_DBG_REG_WVR, i, 0UL);
		write_wb_reg(AARCH64_DBG_REG_WCR, i, 0UL);
	}
}


void my_silly_function(void)
{
	if (ihk_mc_get_processor_id() == 0) {
		dkprintf("%s: \n", __func__);
	}
	return;
}


/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::arch_hw_breakpoint_init */
void arch_hw_breakpoint_init(void)
{
	struct user_hwdebug_state hws;
	int max_hws_dbg_regs = sizeof(hws.dbg_regs) / sizeof(hws.dbg_regs[0]);

	core_num_brps = get_num_brps();
	core_num_wrps = get_num_wrps();

	if (max_hws_dbg_regs < core_num_brps) {
		kprintf("debugreg struct size is less than Determine number of BRP registers available.\n");
		core_num_brps = max_hws_dbg_regs;
	}

	if (max_hws_dbg_regs < core_num_wrps) {
		kprintf("debugreg struct size is less than Determine number of WRP registers available.\n");
		core_num_wrps = max_hws_dbg_regs;
	}
	hw_breakpoint_reset();
	kprintf("%s: core_num_brps: %d\n", __func__, core_num_brps);

	{
#if 1
		int j;
		for (j = 0; j < 23; ++j) {
			aarch64_setup_kernel_breakpoint(0,
					(unsigned long)&my_silly_function + 4, j);
			my_silly_function();
		}
#else
		aarch64_setup_kernel_breakpoint(0,
			0x100000106918, 1);
#endif

#if 0
		aarch64_setup_kernel_breakpoint(0,
			0x100000106918);
		aarch64_setup_kernel_breakpoint(1,
			(unsigned long)&my_silly_function + 4);
		my_silly_function();
#endif
	}
}

struct arch_hw_breakpoint_ctrl {
	unsigned int __reserved	: 19,
	len			: 8,
	type			: 2,
	privilege		: 2,
	enabled			: 1;
};

static inline unsigned int encode_ctrl_reg(struct arch_hw_breakpoint_ctrl ctrl)
{
	return (ctrl.len << 5) | (ctrl.type << 3) | (ctrl.privilege << 1) |
		ctrl.enabled;
}

static inline void decode_ctrl_reg(unsigned int reg, struct arch_hw_breakpoint_ctrl *ctrl)
{
	ctrl->enabled	= reg & 0x1;
	reg >>= 1;
	ctrl->privilege	= reg & 0x3;
	reg >>= 2;
	ctrl->type	= reg & 0x3;
	reg >>= 2;
	ctrl->len	= reg & 0xff;
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::arch_bp_generic_fields */
/*
 * Extract generic type and length encodings from an arch_hw_breakpoint_ctrl.
 * Hopefully this will disappear when ptrace can bypass the conversion
 * to generic breakpoint descriptions.
 */
int arch_bp_generic_fields(struct arch_hw_breakpoint_ctrl ctrl,
			   int *gen_len, int *gen_type)
{
	/* Type */
	switch (ctrl.type) {
	case ARM_BREAKPOINT_EXECUTE:
		*gen_type = HW_BREAKPOINT_X;
		break;
	case ARM_BREAKPOINT_LOAD:
		*gen_type = HW_BREAKPOINT_R;
		break;
	case ARM_BREAKPOINT_STORE:
		*gen_type = HW_BREAKPOINT_W;
		break;
	case ARM_BREAKPOINT_LOAD | ARM_BREAKPOINT_STORE:
		*gen_type = HW_BREAKPOINT_RW;
		break;
	default:
		return -EINVAL;
	}

	/* Len */
	switch (ctrl.len) {
	case ARM_BREAKPOINT_LEN_1:
		*gen_len = HW_BREAKPOINT_LEN_1;
		break;
	case ARM_BREAKPOINT_LEN_2:
		*gen_len = HW_BREAKPOINT_LEN_2;
		break;
	case ARM_BREAKPOINT_LEN_4:
		*gen_len = HW_BREAKPOINT_LEN_4;
		break;
	case ARM_BREAKPOINT_LEN_8:
		*gen_len = HW_BREAKPOINT_LEN_8;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::arch_check_bp_in_kernelspace */
/*
 * Check whether bp virtual address is in kernel space.
 */
int arch_check_bp_in_kernelspace(unsigned long addr, unsigned int len)
{
	return (addr >= USER_END) && ((addr + len - 1) >= USER_END);
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::arch_validate_hwbkpt_settings */
int arch_validate_hwbkpt_settings(long note_type, struct user_hwdebug_state *hws, size_t len)
{
	int i;
	unsigned long alignment_mask;
	size_t cpysize, cpynum;

	switch(note_type) {
	case NT_ARM_HW_BREAK: /* breakpoint */
		alignment_mask = 0x3;
		break;
	case NT_ARM_HW_WATCH: /* watchpoint */
		alignment_mask = 0x7;
		break;
	default:
		return -EINVAL;
	}

	cpysize = len - offsetof(struct user_hwdebug_state, dbg_regs[0]);
	cpynum = cpysize / sizeof(hws->dbg_regs[0]);

	for (i = 0; i < cpynum; i++) {
		unsigned long addr = hws->dbg_regs[i].addr;
		unsigned int uctrl = hws->dbg_regs[i].ctrl;
		struct arch_hw_breakpoint_ctrl ctrl;
		int err, len, type;

		/* empty dbg_regs check skip */
		if (addr == 0 && uctrl == 0) {
			continue;
		}

		/* check address alignment */
		if (addr & alignment_mask) {
			return -EINVAL;
		}

		/* decode control bit */
		decode_ctrl_reg(uctrl, &ctrl);

		/* disabled, continue */
		if (!ctrl.enabled) {
			continue;
		}

		err = arch_bp_generic_fields(ctrl, &len, &type);
		if (err) {
			return err;
		}

		/* type check */
		switch (note_type) {
		case NT_ARM_HW_BREAK: /* breakpoint */
			if ((type & HW_BREAKPOINT_X) != type) {
				return -EINVAL;
			}
			break;
		case NT_ARM_HW_WATCH: /* watchpoint */
			if ((type & HW_BREAKPOINT_RW) != type) {
				return -EINVAL;
			}
			break;
		default:
			return -EINVAL;
		}

		/* privilege generate */
		if (arch_check_bp_in_kernelspace(addr, len)) {
			/* kernel space breakpoint unsupported. */
			return -EINVAL;
		} else {
			ctrl.privilege = AARCH64_BREAKPOINT_EL0;
		}

		/* ctrl check OK. */
		hws->dbg_regs[i].ctrl = encode_ctrl_reg(ctrl);
	}
	return 0;
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::breakpoint_handler */
/*
 * Debug exception handlers.
 */
int breakpoint_handler(unsigned long unused, unsigned int esr, struct pt_regs *regs)
{
	int i = 0;
	unsigned long val;
	unsigned int ctrl_reg;
	struct arch_hw_breakpoint_ctrl ctrl;
	siginfo_t info;

	for (i = 0; i < core_num_brps; i++) {

		/* Check if the breakpoint value matches. */
		val = read_wb_reg(AARCH64_DBG_REG_BVR, i);
		if (val != (regs->pc & ~0x3)) {
			continue;
		}

		/* Possible match, check the byte address select to confirm. */
		ctrl_reg = read_wb_reg(AARCH64_DBG_REG_BCR, i);
		decode_ctrl_reg(ctrl_reg, &ctrl);
		if (!((1 << (regs->pc & 0x3)) & ctrl.len)) {
			continue;
		}

		/* send SIGTRAP */
		info.si_signo = SIGTRAP;
		info.si_errno = 0;
		info.si_code  = TRAP_HWBKPT;
		info._sifields._sigfault.si_addr = (void *)regs->pc;
		set_signal(SIGTRAP, regs, &info);
	}
	return 0;
}

/* @ref.impl arch/arm64/kernel/hw_breakpoint.c::watchpoint_handler */
int watchpoint_handler(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	int i = 0;
	int access;
	unsigned long val;
	unsigned int ctrl_reg;
	struct arch_hw_breakpoint_ctrl ctrl;
	siginfo_t info;

	for (i = 0; i < core_num_wrps; i++) {
		/* Check if the watchpoint value matches. */
		val = read_wb_reg(AARCH64_DBG_REG_WVR, i);
		if (val != (addr & ~0x7)) {
			continue;
		}

		/* Possible match, check the byte address select to confirm. */
		ctrl_reg = read_wb_reg(AARCH64_DBG_REG_WCR, i);
		decode_ctrl_reg(ctrl_reg, &ctrl);
		if (!((1 << (addr & 0x7)) & ctrl.len)) {
			continue;
		}

		/*
		 * Check that the access type matches.
		 * 0 => load, otherwise => store
		 */
		access = (esr & AARCH64_ESR_ACCESS_MASK) ? ARM_BREAKPOINT_STORE :
			 ARM_BREAKPOINT_LOAD;
		if (!(access & ctrl.type)) {
			continue;
		}

		/* send SIGTRAP */
		info.si_signo = SIGTRAP;
		info.si_errno = 0;
		info.si_code  = TRAP_HWBKPT;
		info._sifields._sigfault.si_addr = (void *)addr;
		set_signal(SIGTRAP, regs, &info);
	}
	return 0;
}


#define DBGBCR_HMC	13
#define DBGBCR_SSC  14
#define DBGBCR_PMC  1

struct breakpoint_enconding {
	uint64_t hmc;
	uint64_t ssc;
	uint64_t pmc;
};


struct breakpoint_enconding breakpoint_encondings[23] =
{
	// HMC 0
	{
		.hmc = 0,
		.ssc = 0,
		.pmc = 0x1,
	},
	{
		.hmc = 0,
		.ssc = 0,
		.pmc = 0x2,
	},
	{
		.hmc = 0,
		.ssc = 0,
		.pmc = 0x3,
	},

	{
		.hmc = 0,
		.ssc = 0x1,
		.pmc = 0x1,
	},
	{
		.hmc = 0,
		.ssc = 0x1,
		.pmc = 0x2,
	},
	{
		.hmc = 0,
		.ssc = 0x1,
		.pmc = 0x3,
	},

	{
		.hmc = 0,
		.ssc = 0x2,
		.pmc = 0x1,
	},
	{
		.hmc = 0,
		.ssc = 0x2,
		.pmc = 0x2,
	},
	{
		.hmc = 0,
		.ssc = 0x2,
		.pmc = 0x3,
	},

	{
		.hmc = 0,
		.ssc = 0x3,
		.pmc = 0x0,
	},
	{
		.hmc = 0,
		.ssc = 0x3,
		.pmc = 0x1,
	},
	{
		.hmc = 0,
		.ssc = 0x3,
		.pmc = 0x3,
	},

	// HMC 1
	{
		.hmc = 0x1,
		.ssc = 0x0,
		.pmc = 0x1,
	},
	{
		.hmc = 0x1,
		.ssc = 0x0,
		.pmc = 0x3,
	},

	{
		.hmc = 0x1,
		.ssc = 0x1,
		.pmc = 0x0,
	},
	{
		.hmc = 0x1,
		.ssc = 0x1,
		.pmc = 0x1,
	},
	{
		.hmc = 0x1,
		.ssc = 0x1,
		.pmc = 0x3,
	},

	{
		.hmc = 0x1,
		.ssc = 0x2,
		.pmc = 0x0,
	},
	{
		.hmc = 0x1,
		.ssc = 0x2,
		.pmc = 0x1,
	},
	{
		.hmc = 0x1,
		.ssc = 0x2,
		.pmc = 0x3,
	},

	{
		.hmc = 0x1,
		.ssc = 0x3,
		.pmc = 0x0,
	},
	{
		.hmc = 0x1,
		.ssc = 0x3,
		.pmc = 0x1,
	},
	{
		.hmc = 0x1,
		.ssc = 0x3,
		.pmc = 0x3,
	},
};


void aarch64_setup_kernel_breakpoint(int i, unsigned long addr, int j)
{
	struct arch_hw_breakpoint_ctrl ahb_ctrl;
	uint32_t mdscr, enable;
	uint32_t ctrl;
	uint64_t val;

	/* Enable and allow kernel mode */
	enable = DBG_MDSCR_MDE;
	enable |= DBG_MDSCR_KDE;

	mdscr = mdscr_read();
	mdscr |= enable;
	mdscr_write(mdscr);

#if 0
	ahb_ctrl.type = ARM_BREAKPOINT_EXECUTE;
	ahb_ctrl.len = ARM_BREAKPOINT_LEN_4;
	ahb_ctrl.privilege = AARCH64_BREAKPOINT_EL1;
	//ahb_ctrl.privilege = AARCH64_BREAKPOINT_EL0;
	ahb_ctrl.enabled = 0x1;

	/* Use DBG reg i */
	write_wb_reg(AARCH64_DBG_REG_BVR, i, addr);
	ctrl = encode_ctrl_reg(ahb_ctrl);
	//write_wb_reg(AARCH64_DBG_REG_BCR, i, ctrl);	
	//val = read_wb_reg(AARCH64_DBG_REG_BCR, i);
	//kprintf("AARCH64_DBG_REG_BCR (Linux): %lx\n", val);

	/* Enable EL2, EL1, EL0 for both secure and non-secure */
	/*
	 * See: Table D2-9 under D2.9.3 Execution conditions for
	 * which a breakpoint generates Breakpoint exceptions
	 */
	ctrl = 0;

	ctrl &= ~(0x1U << DBGBCR_HMC); // EL0 or EL0 and EL1
	//ctrl |= (0x1U << DBGBCR_HMC); // EL0, EL1, EL2 (non-secure)
	ctrl |= (0x1U << DBGBCR_HMC);

	ctrl &= ~(0x3U << DBGBCR_SSC);
	//ctrl |= (0x3U << DBGBCR_SSC); // EL0 only
	//ctrl |= (0x1U << DBGBCR_SSC); // EL0 and EL1
	//ctrl |= (0x1U << DBGBCR_SSC); // EL0, EL1, EL2 (non-secure)
	//ctrl |= (0x3U << DBGBCR_SSC);

	ctrl &= ~(0x3U << DBGBCR_PMC);
	//ctrl |= (0x2U << DBGBCR_PMC); // EL0 only
	//ctrl |= (0x3U << DBGBCR_PMC); // EL0 and EL1
	//ctrl |= (0x3U << DBGBCR_PMC); // EL0, EL1, EL2 (non-secure)
	ctrl |= (0x3U << DBGBCR_PMC);
	ctrl |= 0x1;
#endif

	write_wb_reg(AARCH64_DBG_REG_BVR, i, addr);

	ctrl = 0;
	ctrl |= (breakpoint_encondings[j].hmc << DBGBCR_HMC);
	ctrl |= (breakpoint_encondings[j].ssc << DBGBCR_SSC);
	ctrl |= (breakpoint_encondings[j].pmc << DBGBCR_PMC);
	ctrl |= 0x1;

	write_wb_reg(AARCH64_DBG_REG_BCR, i, ctrl);

	val = read_wb_reg(AARCH64_DBG_REG_BCR, i);
	kprintf("AARCH64_DBG_REG_BCR: %lx, HMC: %d, SSC: %d%d, PMC: %d%d\n",
		val,
		val & (1 << DBGBCR_HMC) ? 1 : 0,
		val & (1 << (DBGBCR_SSC + 1)) ? 1 : 0,
		val & (1 << (DBGBCR_SSC)) ? 1 : 0,
		val & (1 << (DBGBCR_PMC + 1)) ? 1 : 0,
		val & (1 << (DBGBCR_PMC)) ? 1 : 0
		);

	asm volatile(
		"msr	daifclr, #0xf		// local_daif_unmask"
		:
		:
		: "memory");

	/*
	asm("mrs %0, mdcr_el2" : "=r" (val));
	kprintf("MDCR_EL2: %lx\n", val);
	asm("mrs %0, hcr_el2" : "=r" (val));
	kprintf("HCR_EL2: %lx\n", val);
	asm("mrs %0, daif" : "=r" (val));
	kprintf("DAIF: %lx\n", val);
	*/

	kprintf("reg %d (mode: %d) set for addr: 0x%lx\n", i, j, addr);
}

