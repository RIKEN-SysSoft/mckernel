/* traps.c COPYRIGHT FUJITSU LIMITED 2015-2016 */
#include <ihk/context.h>
#include <ihk/debug.h>
#include <ptrace.h>
#include <signal.h>
#include <cpulocal.h>
#include <cls.h>
#include <syscall.h>

extern void arch_show_interrupt_context(const void *reg);
extern int interrupt_from_user(void *);

void arm64_notify_die(const char *str, struct pt_regs *regs, struct siginfo *info, int err)
{
	if (interrupt_from_user(regs)) {
		current_thread_info()->fault_address = 0;
		current_thread_info()->fault_code = err;
		set_signal(info->si_signo, regs, info); 
	} else {
		panic(str);
		kprintf("siginfo: signo(%d) code(%d)\n", info->si_signo, info->si_code);
	}
}

/*
 * Trapped FP/ASIMD access.
 */
void do_fpsimd_acc(unsigned int esr, struct pt_regs *regs)
{
	// /* TODO: implement lazy context saving/restoring */
	set_cputime(1);
	// WARN_ON(1);
	kprintf("WARNING: CPU: %d PID: %d Trapped FP/ASIMD access.\n",
		ihk_mc_get_processor_id(), cpu_local_var(current)->proc->pid);
	set_cputime(0);
}

/*
 * Raise a SIGFPE for the current process.
 */
#define FPEXC_IOF	(1 << 0)
#define FPEXC_DZF	(1 << 1)
#define FPEXC_OFF	(1 << 2)
#define FPEXC_UFF	(1 << 3)
#define FPEXC_IXF	(1 << 4)
#define FPEXC_IDF	(1 << 7)

void do_fpsimd_exc(unsigned int esr, struct pt_regs *regs)
{
	siginfo_t info;
	unsigned int si_code = 0;
	set_cputime(1);

	if (esr & FPEXC_IOF)
		si_code = FPE_FLTINV;
	else if (esr & FPEXC_DZF)
		si_code = FPE_FLTDIV;
	else if (esr & FPEXC_OFF)
		si_code = FPE_FLTOVF;
	else if (esr & FPEXC_UFF)
		si_code = FPE_FLTUND;
	else if (esr & FPEXC_IXF)
		si_code = FPE_FLTRES;

	info.si_signo = SIGFPE;
	info.si_errno = 0;
	info.si_code = si_code;
	info._sifields._sigfault.si_addr  = (void*)regs->pc;

	set_signal(SIGFPE, regs, &info);
	set_cputime(0);
}

void do_undefinstr(struct pt_regs *regs)
{
	siginfo_t info;

	set_cputime(interrupt_from_user(regs)? 1: 2);
	info.si_signo = SIGILL;
	info.si_errno = 0;
	info.si_code  = ILL_ILLOPC;
	info._sifields._sigfault.si_addr  = (void*)regs->pc;

	arm64_notify_die("Oops - undefined instruction", regs, &info, 0);
	set_cputime(0);
}

/*
 * bad_mode handles the impossible case in the exception vector.
 */
//asmlinkage void bad_mode(struct pt_regs *regs, int reason, unsigned int esr)
void bad_mode(struct pt_regs *regs, int reason, unsigned int esr)
{
	siginfo_t info;
	set_cputime(interrupt_from_user(regs)? 1: 2);
	kprintf("entering bad_mode !! (regs:0x%p, reason:%d, esr:0x%x)\n", regs, reason, esr);

	kprintf("esr Analyse:\n");
	kprintf("  Exception Class               : 0x%x\n",((esr >> 26) & 0x3f));
	kprintf("  Instruction Length            : %d (0:16-bit instruction, 1:32-bit instruction)\n",((esr >> 25) & 0x1));
	kprintf("  Instruction Specific Syndrome : 0x%x\n",(esr & 0x1ffffff));

	arch_show_interrupt_context(regs);

	info.si_signo = SIGILL;
	info.si_errno = 0;
	info.si_code  = ILL_ILLOPC;
	info._sifields._sigfault.si_addr  = (void*)regs->pc;

	arm64_notify_die("Oops - bad mode", regs, &info, 0);
	set_cputime(0);
}
