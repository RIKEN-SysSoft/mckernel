/* fault.c COPYRIGHT FUJITSU LIMITED 2015-2018 */

#include <ihk/context.h>
#include <ihk/debug.h>
#include <ptrace.h>
#include <esr.h>
#include <signal.h>
#include <arch-memory.h>
#include <thread_info.h>
#include <syscall.h>
#include <debug-monitors.h>

unsigned long __page_fault_handler_address;
extern int interrupt_from_user(void *);

static void do_bad_area(unsigned long addr, unsigned int esr, struct pt_regs *regs);
static int do_page_fault(unsigned long addr, unsigned int esr, struct pt_regs *regs);
static int do_translation_fault(unsigned long addr, unsigned int esr, struct pt_regs *regs);
static int do_bad(unsigned long addr, unsigned int esr, struct pt_regs *regs);
static int do_alignment_fault(unsigned long addr, unsigned int esr, struct pt_regs *regs);

static struct fault_info {
	int	(*fn)(unsigned long addr, unsigned int esr, struct pt_regs *regs);
	int	sig;
	int	code;
	const char *name;
} fault_info[] = {
	{ do_bad,		SIGBUS,  0,		"ttbr address size fault"	},
	{ do_bad,		SIGBUS,  0,		"level 1 address size fault"	},
	{ do_bad,		SIGBUS,  0,		"level 2 address size fault"	},
	{ do_bad,		SIGBUS,  0,		"level 3 address size fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 0 translation fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 1 translation fault"	},
	{ do_translation_fault,	SIGSEGV, SEGV_MAPERR,	"level 2 translation fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_MAPERR,	"level 3 translation fault"	},
	{ do_bad,		SIGBUS,  0,		"unknown 8"			},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 1 access flag fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 2 access flag fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 3 access flag fault"	},
	{ do_bad,		SIGBUS,  0,		"unknown 12"			},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 1 permission fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 2 permission fault"	},
	{ do_page_fault,	SIGSEGV, SEGV_ACCERR,	"level 3 permission fault"	},
	{ do_bad,		SIGBUS,  0,		"synchronous external abort"	},
	{ do_bad,		SIGBUS,  0,		"unknown 17"			},
	{ do_bad,		SIGBUS,  0,		"unknown 18"			},
	{ do_bad,		SIGBUS,  0,		"unknown 19"			},
	{ do_bad,		SIGBUS,  0,		"synchronous external abort (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous external abort (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous external abort (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous external abort (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous parity error"	},
	{ do_bad,		SIGBUS,  0,		"unknown 25"			},
	{ do_bad,		SIGBUS,  0,		"unknown 26"			},
	{ do_bad,		SIGBUS,  0,		"unknown 27"			},
	{ do_bad,		SIGBUS,  0,		"synchronous parity error (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous parity error (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous parity error (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"synchronous parity error (translation table walk)" },
	{ do_bad,		SIGBUS,  0,		"unknown 32"			},
	{ do_alignment_fault,	SIGBUS,  BUS_ADRALN,	"alignment fault"		},
	{ do_bad,		SIGBUS,  0,		"unknown 34"			},
	{ do_bad,		SIGBUS,  0,		"unknown 35"			},
	{ do_bad,		SIGBUS,  0,		"unknown 36"			},
	{ do_bad,		SIGBUS,  0,		"unknown 37"			},
	{ do_bad,		SIGBUS,  0,		"unknown 38"			},
	{ do_bad,		SIGBUS,  0,		"unknown 39"			},
	{ do_bad,		SIGBUS,  0,		"unknown 40"			},
	{ do_bad,		SIGBUS,  0,		"unknown 41"			},
	{ do_bad,		SIGBUS,  0,		"unknown 42"			},
	{ do_bad,		SIGBUS,  0,		"unknown 43"			},
	{ do_bad,		SIGBUS,  0,		"unknown 44"			},
	{ do_bad,		SIGBUS,  0,		"unknown 45"			},
	{ do_bad,		SIGBUS,  0,		"unknown 46"			},
	{ do_bad,		SIGBUS,  0,		"unknown 47"			},
	{ do_bad,		SIGBUS,  0,		"TLB conflict abort"		},
	{ do_bad,		SIGBUS,  0,		"unknown 49"			},
	{ do_bad,		SIGBUS,  0,		"unknown 50"			},
	{ do_bad,		SIGBUS,  0,		"unknown 51"			},
	{ do_bad,		SIGBUS,  0,		"implementation fault (lockdown abort)" },
	{ do_bad,		SIGBUS,  0,		"implementation fault (unsupported exclusive)" },
	{ do_bad,		SIGBUS,  0,		"unknown 54"			},
	{ do_bad,		SIGBUS,  0,		"unknown 55"			},
	{ do_bad,		SIGBUS,  0,		"unknown 56"			},
	{ do_bad,		SIGBUS,  0,		"unknown 57"			},
	{ do_bad,		SIGBUS,  0,		"unknown 58" 			},
	{ do_bad,		SIGBUS,  0,		"unknown 59"			},
	{ do_bad,		SIGBUS,  0,		"unknown 60"			},
	{ do_bad,		SIGBUS,  0,		"section domain fault"		},
	{ do_bad,		SIGBUS,  0,		"page domain fault"		},
	{ do_bad,		SIGBUS,  0,		"unknown 63"			},
};

static const char *fault_name(unsigned int esr)
{
	const struct fault_info *inf = fault_info + (esr & 63);
	return inf->name;
}

/*
 * Dispatch a data abort to the relevant handler.
 */
void do_mem_abort(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	const struct fault_info *inf = fault_info + (esr & 63);
	struct siginfo info;
	const int from_user = interrupt_from_user(regs);

	/* set_cputime called in inf->fn() */
	if (!inf->fn(addr, esr, regs))
		return;

	set_cputime(from_user ? CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);
	kprintf("Unhandled fault: %s (0x%08x) at 0x%016lx\n", inf->name, esr, addr);
	info.si_signo = inf->sig;
	info.si_errno = 0;
	info.si_code  = inf->code;
	info._sifields._sigfault.si_addr  = (void*)addr;

	arm64_notify_die("", regs, &info, esr);
	set_cputime(from_user ? CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);
}

/*
 * Handle stack alignment exceptions.
 */
void do_sp_pc_abort(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	struct siginfo info;
	const int from_user = interrupt_from_user(regs);

	set_cputime(from_user ? CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);

	info.si_signo = SIGBUS;
	info.si_errno = 0;
	info.si_code  = BUS_ADRALN;
	info._sifields._sigfault.si_addr  = (void*)addr;
	arm64_notify_die("", regs, &info, esr);
	set_cputime(from_user ? CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);
}

static void do_bad_area(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	struct siginfo info;
	const int from_user = interrupt_from_user(regs);

	set_cputime(from_user ? CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);
	/*
	 * If we are in kernel mode at this point, we have no context to
	 * handle this fault with.
	 */
	if (interrupt_from_user(regs)) {
		kprintf("unhandled %s (%d) at 0x%08lx, esr 0x%03x\n",
			fault_name(esr), SIGSEGV, addr, esr);

		current_thread_info()->fault_address = addr;
		current_thread_info()->fault_code = esr;
		info.si_signo = SIGSEGV;
		info.si_errno = 0;
		info.si_code = SEGV_MAPERR;
		info._sifields._sigfault.si_addr = (void *)addr;
		set_signal(SIGSEGV, regs, &info); 

	} else {
		kprintf("Unable to handle kernel %s at virtual address %08lx\n",
			 (addr < PAGE_SIZE) ? "NULL pointer dereference" : "paging request", addr);
		panic("OOps.");
	}
	set_cputime(from_user ? CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);
}

static int is_el0_instruction_abort(unsigned int esr)
{
	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_LOW;
}

static int do_page_fault(unsigned long addr, unsigned int esr,
				   struct pt_regs *regs)
{
	void (*page_fault_handler)(void *, uint64_t, void *);
	uint64_t reason = 0;
	int esr_ec_dfsc = (esr & 63);

	if (interrupt_from_user(regs)) {
		reason |= PF_USER;
	}

	if (is_el0_instruction_abort(esr)) {
		reason |= PF_INSTR;
	} else if ((esr & ESR_ELx_WNR) && !(esr & ESR_ELx_CM)) {
		reason |= PF_WRITE;
		if (13 <= esr_ec_dfsc && esr_ec_dfsc <= 15 ) {
			/* level [1-3] permission fault */
			reason |= PF_PROT;
		}
	}

	/* set_cputime() call in page_fault_handler() */
	page_fault_handler = (void *)__page_fault_handler_address;
	(*page_fault_handler)((void *)addr, reason, regs);

	return 0;
}

/*
 * First Level Translation Fault Handler
 *
 * We enter here because the first level page table doesn't contain a valid
 * entry for the address.
 *
 * If the address is in kernel space (>= TASK_SIZE), then we are probably
 * faulting in the vmalloc() area.
 *
 * If the init_task's first level page tables contains the relevant entry, we
 * copy the it to this task.  If not, we send the process a signal, fixup the
 * exception, or oops the kernel.
 *
 * NOTE! We MUST NOT take any locks for this case. We may be in an interrupt
 * or a critical region, and should only copy the information from the master
 * page table, nothing more.
 */
static int do_translation_fault(unsigned long addr,
					  unsigned int esr,
					  struct pt_regs *regs)
{
#ifdef ENABLE_TOFU
	// XXX: Handle kernel space page faults for Tofu driver
	//if (addr < USER_END)
#else
	if (addr < USER_END)
#endif
		return do_page_fault(addr, esr, regs);

	do_bad_area(addr, esr, regs);
	return 0;
}

static int do_alignment_fault(unsigned long addr, unsigned int esr,
			      struct pt_regs *regs)
{
	do_bad_area(addr, esr, regs);
	return 0;
}

extern int breakpoint_handler(unsigned long unused, unsigned int esr, struct pt_regs *regs);
extern int single_step_handler(unsigned long addr, unsigned int esr, struct pt_regs *regs);
extern int watchpoint_handler(unsigned long addr, unsigned int esr, struct pt_regs *regs);
extern int brk_handler(unsigned long addr, unsigned int esr, struct pt_regs *regs);
static struct fault_info debug_fault_info[] = {
	{ breakpoint_handler,	SIGTRAP,	TRAP_HWBKPT,	"hw-breakpoint handler"	},
	{ single_step_handler,	SIGTRAP,	TRAP_HWBKPT,	"single-step handler"	},
	{ watchpoint_handler,	SIGTRAP,	TRAP_HWBKPT,	"hw-watchpoint handler"	},
	{ do_bad,		SIGBUS,		0,		"unknown 3"		},
	{ do_bad,		SIGTRAP,	TRAP_BRKPT,	"aarch32 BKPT"		},
	{ do_bad,		SIGTRAP,	0,		"aarch32 vector catch"	},
	{ brk_handler,		SIGTRAP,	TRAP_BRKPT,	"ptrace BRK handler"	},
	{ do_bad,		SIGBUS,		0,		"unknown 7"		},
};

int do_debug_exception(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	const struct fault_info *inf = debug_fault_info + DBG_ESR_EVT(esr);
	struct siginfo info;
	const int from_user = interrupt_from_user(regs);
	int ret = -1;

	set_cputime(from_user ? CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);

	if (!inf->fn(addr, esr, regs)) {
		ret = 1;
		goto out;
	}

	kprintf("Unhandled debug exception: %s (0x%08x) at 0x%016lx\n",
		inf->name, esr, addr);

	info.si_signo = inf->sig;
	info.si_errno = 0;
	info.si_code  = inf->code;
	info._sifields._sigfault.si_addr = (void *)addr;

	arm64_notify_die("", regs, &info, 0);

	ret = 0;
out:
	set_cputime(from_user ? CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);
	return ret;
}

/*
 * This abort handler always returns "fault".
 */
static int do_bad(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	const int from_user = interrupt_from_user(regs);

	set_cputime(from_user ? CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);
	set_cputime(from_user ? CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);
	return 1;
}
