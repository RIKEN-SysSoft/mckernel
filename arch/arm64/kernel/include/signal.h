/* signal.h COPYRIGHT FUJITSU LIMITED 2015-2018 */
#ifndef __HEADER_ARM64_COMMON_SIGNAL_H
#define __HEADER_ARM64_COMMON_SIGNAL_H

#include <fpsimd.h>
#include <ihk/types.h>

#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS (_NSIG / _NSIG_BPW)

static inline int valid_signal(unsigned long sig)
{
	return sig <= _NSIG ? 1 : 0;
}

typedef unsigned long int __sigset_t;
#define __sigmask(sig)  (((__sigset_t) 1) << ((sig) - 1))

typedef struct {
	__sigset_t __val[_NSIG_WORDS];
} sigset_t;

#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2

struct sigaction {
	void (*sa_handler)(int);
	unsigned long sa_flags;
	void (*sa_restorer)(int);
	sigset_t sa_mask;
};

typedef void __sig_fn_t(int);
typedef __sig_fn_t *__sig_handler_t;
#define SIG_DFL (__sig_handler_t)0
#define SIG_IGN (__sig_handler_t)1
#define SIG_ERR (__sig_handler_t)-1

#define SA_NOCLDSTOP    0x00000001U
#define SA_NOCLDWAIT    0x00000002U
#define SA_NODEFER      0x40000000U
#define SA_ONSTACK      0x08000000U
#define SA_RESETHAND    0x80000000U
#define SA_RESTART      0x10000000U
#define SA_SIGINFO      0x00000004U

/* Required for AArch32 compatibility. */
#define SA_RESTORER	0x04000000U

struct k_sigaction {
        struct sigaction sa;
};

typedef struct sigaltstack {
	void	*ss_sp;
	int	ss_flags;
	size_t	ss_size;
} stack_t;

#define MINSIGSTKSZ 5120
#define SS_ONSTACK 1
#define SS_DISABLE 2

typedef union sigval {
	int sival_int;
	void *sival_ptr;
} sigval_t;

#define __SI_MAX_SIZE 128
#define __SI_PAD_SIZE ((__SI_MAX_SIZE / sizeof (int)) - 4)

typedef struct siginfo {
	int si_signo;		/* Signal number.  */
	int si_errno;		/* If non-zero, an errno value associated with
				   this signal, as defined in <errno.h>.  */
	int si_code;		/* Signal code.  */
#define SI_USER         0  /* sent by kill, sigsend, raise */
#define SI_KERNEL       0x80 /* sent by the kernel from somewhere */
#define SI_QUEUE        -1 /* sent by sigqueue */
#define SI_TIMER __SI_CODE(__SI_TIMER,-2) /* sent by timer expiration */
#define SI_MESGQ __SI_CODE(__SI_MESGQ,-3) /* sent by real time mesq state change
 */
#define SI_ASYNCIO      -4 /* sent by AIO completion */
#define SI_SIGIO        -5 /* sent by queued SIGIO */
#define SI_TKILL        -6 /* sent by tkill system call */
#define SI_DETHREAD     -7 /* sent by execve() killing subsidiary threads */

#define ILL_ILLOPC      1  /* illegal opcode */
#define ILL_ILLOPN      2  /* illegal operand */
#define ILL_ILLADR      3  /* illegal addressing mode */
#define ILL_ILLTRP      4  /* illegal trap */
#define ILL_PRVOPC      5  /* privileged opcode */
#define ILL_PRVREG      6  /* privileged register */
#define ILL_COPROC      7  /* coprocessor error */
#define ILL_BADSTK      8  /* internal stack error */

#define FPE_INTDIV      1  /* integer divide by zero */
#define FPE_INTOVF      2  /* integer overflow */
#define FPE_FLTDIV      3  /* floating point divide by zero */
#define FPE_FLTOVF      4  /* floating point overflow */
#define FPE_FLTUND      5  /* floating point underflow */
#define FPE_FLTRES      6  /* floating point inexact result */
#define FPE_FLTINV      7  /* floating point invalid operation */
#define FPE_FLTSUB      8  /* subscript out of range */

#define SEGV_MAPERR     1  /* address not mapped to object */
#define SEGV_ACCERR     2  /* invalid permissions for mapped object */

#define BUS_ADRALN      1  /* invalid address alignment */
#define BUS_ADRERR      2  /* non-existant physical address */
#define BUS_OBJERR      3  /* object specific hardware error */
/* hardware memory error consumed on a machine check: action required */
#define BUS_MCEERR_AR   4
/* hardware memory error detected in process but not consumed: action optional*/
#define BUS_MCEERR_AO   5

#define TRAP_BRKPT      1  /* process breakpoint */
#define TRAP_TRACE      2  /* process trace trap */
#define TRAP_BRANCH     3  /* process taken branch trap */
#define TRAP_HWBKPT     4  /* hardware breakpoint/watchpoint */

#define CLD_EXITED      1   /* child has exited */
#define CLD_KILLED      2   /* child was killed */
#define CLD_DUMPED      3   /* child terminated abnormally */
#define CLD_TRAPPED     4   /* traced child has trapped */
#define CLD_STOPPED     5   /* child has stopped */
#define CLD_CONTINUED   6   /* stopped child has continued */

#define POLL_IN         1   /* data input available */
#define POLL_OUT        2   /* output buffers available */
#define POLL_MSG        3   /* input message available */
#define POLL_ERR        4   /* i/o error */
#define POLL_PRI        5   /* high priority input available */
#define POLL_HUP        6   /* device disconnected */

#define SIGEV_SIGNAL    0   /* notify via signal */
#define SIGEV_NONE      1   /* other notification: meaningless */
#define SIGEV_THREAD    2   /* deliver via thread creation */
#define SIGEV_THREAD_ID 4   /* deliver to thread */

	union {
		int _pad[__SI_PAD_SIZE];

		/* kill().  */
		struct {
			int si_pid;/* Sending process ID.  */
			int si_uid;/* Real user ID of sending process.  */
		} _kill;

		/* POSIX.1b timers.  */
		struct {
			int si_tid;         /* Timer ID.  */
			int si_overrun;     /* Overrun count.  */
			sigval_t si_sigval; /* Signal value.  */
		} _timer;

		/* POSIX.1b signals.  */
		struct {
			int si_pid;     /* Sending process ID.  */
			int si_uid;     /* Real user ID of sending process.  */
			sigval_t si_sigval; /* Signal value.  */
		} _rt;

		/* SIGCHLD.  */
		struct {
			int si_pid;     /* Which child.  */
			int si_uid;     /* Real user ID of sending process.  */
			int si_status;      /* Exit value or signal.  */
			long si_utime;
			long si_stime;
		} _sigchld;

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
		struct {
			void *si_addr;      /* Faulting insn/memory ref.  */
		} _sigfault;

		/* SIGPOLL.  */
		struct {
			long int si_band;   /* Band event for SIGPOLL.  */
			int si_fd;
		} _sigpoll;
	} _sifields;
} siginfo_t;

struct signalfd_siginfo {
	unsigned int ssi_signo;
	int ssi_errno;
	int ssi_code;
	unsigned int ssi_pid;
	unsigned int ssi_uid;
	int ssi_fd;
	unsigned int ssi_tid;
	unsigned int ssi_band;
	unsigned int ssi_overrun;
	unsigned int ssi_trapno;
	int ssi_status;
	int ssi_int;
	unsigned long ssi_ptr;
	unsigned long ssi_utime;
	unsigned long ssi_stime;
	unsigned long ssi_addr;
	unsigned short ssi_addr_lsb;

	char __pad[46];
};


#define SIGHUP           1
#define SIGINT           2
#define SIGQUIT          3
#define SIGILL           4
#define SIGTRAP          5
#define SIGABRT          6
#define SIGIOT           6
#define SIGBUS           7
#define SIGFPE           8
#define SIGKILL          9
#define SIGUSR1         10
#define SIGSEGV         11
#define SIGUSR2         12
#define SIGPIPE         13
#define SIGALRM         14
#define SIGTERM         15
#define SIGSTKFLT       16
#define SIGCHLD         17
#define SIGCONT         18
#define SIGSTOP         19
#define SIGTSTP         20
#define SIGTTIN         21
#define SIGTTOU         22
#define SIGURG          23
#define SIGXCPU         24
#define SIGXFSZ         25
#define SIGVTALRM       26
#define SIGPROF         27
#define SIGWINCH        28
#define SIGIO           29
#define SIGPOLL         SIGIO
#define SIGPWR          30
#define SIGSYS          31
#define SIGUNUSED       31
#define SIGRTMIN        32

#ifndef SIGRTMAX
#define SIGRTMAX	_NSIG
#endif

#define PTRACE_EVENT_EXEC 4

/*
 * @ref.impl linux-linaro/arch/arm64/include/uapi/asm/sigcontext.h
 */
struct sigcontext {
	unsigned long fault_address;
	/* AArch64 registers */
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
	/* 4K reserved for FP/SIMD state and future expansion */
	unsigned char __reserved[4096] /*__attribute__((__aligned__(16)))*/;
};

/*
 * Header to be used at the beginning of structures extending the user
 * context. Such structures must be placed after the rt_sigframe on the stack
 * and be 16-byte aligned. The last structure must be a dummy one with the
 * magic and size set to 0.
 */
struct _aarch64_ctx {
	unsigned int magic;
	unsigned int size;
};

#define FPSIMD_MAGIC	0x46508001

struct fpsimd_context {
	struct _aarch64_ctx head;
	unsigned int fpsr;
	unsigned int fpcr;
	__uint128_t vregs[32];
};

/* ESR_EL1 context */
#define ESR_MAGIC	0x45535201

struct esr_context {
	struct _aarch64_ctx head;
	unsigned long esr;
};

#define EXTRA_MAGIC	0x45585401

struct extra_context {
	struct _aarch64_ctx head;
	void *data;	/* 16-byte aligned pointer to the extra space */
	uint32_t size;	/* size in bytes of the extra space */
};

#define SVE_MAGIC	0x53564501

#define fpsimd_sve_state(vq) {			\
	__uint128_t zregs[32][vq];		\
	uint16_t pregs[16][vq];			\
	uint16_t ffr[vq];			\
}

struct sve_context {
	struct _aarch64_ctx head;
	uint16_t vl;
	uint16_t __reserved[3];
};

/*
 * The SVE architecture leaves space for future expansion of the
 * vector length beyond its initial architectural limit of 2048 bits
 * (16 quadwords).
 */
#define SVE_VQ_MIN	1
#define SVE_VQ_MAX	0x200

#define SVE_VL_MIN	(SVE_VQ_MIN * 0x10)
#define SVE_VL_MAX	(SVE_VQ_MAX * 0x10)

#define SVE_NUM_ZREGS	32
#define SVE_NUM_PREGS	16

#define sve_vl_valid(vl) \
	((vl) % 0x10 == 0 && (vl) >= SVE_VL_MIN && (vl) <= SVE_VL_MAX)
#define sve_vq_from_vl(vl)	((vl) / 0x10)

/*
 * The total size of meaningful data in the SVE context in bytes,
 * including the header, is given by SVE_SIG_CONTEXT_SIZE(vq).
 *
 * Note: for all these macros, the "vq" argument denotes the SVE
 * vector length in quadwords (i.e., units of 128 bits).
 *
 * The correct way to obtain vq is to use sve_vq_from_vl(vl).  The
 * result is valid if and only if sve_vl_valid(vl) is true.  This is
 * guaranteed for a struct sve_context written by the kernel.
 *
 *
 * Additional macros describe the contents and layout of the payload.
 * For each, SVE_SIG_x_OFFSET(args) is the start offset relative to
 * the start of struct sve_context, and SVE_SIG_x_SIZE(args) is the
 * size in bytes:
 *
 *
 *	x	type				description
 *	-	----				-----------
 *	REGS					the entire SVE context
 *
 *	ZREGS	__uint128_t[SVE_NUM_ZREGS][vq]	all Z-registers
 *	ZREG	__uint128_t[vq]			individual Z-register Zn
 *
 *	PREGS	uint16_t[SVE_NUM_PREGS][vq]	all P-registers
 *	PREG	uint16_t[vq]			individual P-register Pn
 *
 *	FFR	uint16_t[vq]			first-fault status register
 *
 * Additional data might be appended in the future.
 */

#define SVE_SIG_ZREG_SIZE(vq)	((uint32_t)(vq) * 16)
#define SVE_SIG_PREG_SIZE(vq)	((uint32_t)(vq) * 2)
#define SVE_SIG_FFR_SIZE(vq)	SVE_SIG_PREG_SIZE(vq)

#define SVE_SIG_REGS_OFFSET	((sizeof(struct sve_context) + 15) / 16 * 16)

#define SVE_SIG_ZREGS_OFFSET	SVE_SIG_REGS_OFFSET
#define SVE_SIG_ZREG_OFFSET(vq, n) \
	(SVE_SIG_ZREGS_OFFSET + SVE_SIG_ZREG_SIZE(vq) * (n))
#define SVE_SIG_ZREGS_SIZE(vq) \
	(SVE_SIG_ZREG_OFFSET(vq, SVE_NUM_ZREGS) - SVE_SIG_ZREGS_OFFSET)

#define SVE_SIG_PREGS_OFFSET(vq) \
	(SVE_SIG_ZREGS_OFFSET + SVE_SIG_ZREGS_SIZE(vq))
#define SVE_SIG_PREG_OFFSET(vq, n) \
	(SVE_SIG_PREGS_OFFSET(vq) + SVE_SIG_PREG_SIZE(vq) * (n))
#define SVE_SIG_PREGS_SIZE(vq) \
	(SVE_SIG_PREG_OFFSET(vq, SVE_NUM_PREGS) - SVE_SIG_PREGS_OFFSET(vq))

#define SVE_SIG_FFR_OFFSET(vq) \
	(SVE_SIG_PREGS_OFFSET(vq) + SVE_SIG_PREGS_SIZE(vq))

#define SVE_SIG_REGS_SIZE(vq) \
	(SVE_SIG_FFR_OFFSET(vq) + SVE_SIG_FFR_SIZE(vq) - SVE_SIG_REGS_OFFSET)

#define SVE_SIG_CONTEXT_SIZE(vq) (SVE_SIG_REGS_OFFSET + SVE_SIG_REGS_SIZE(vq))

/*
 * @ref.impl linux-linaro/arch/arm64/include/asm/ucontext.h
 */
struct ucontext {
	unsigned long uc_flags;
	struct ucontext *uc_link;
	stack_t uc_stack;
	sigset_t uc_sigmask;
	/* glibc uses a 1024-bit sigset_t */
	unsigned char __unused[1024 / 8 - sizeof(sigset_t)];
	/* last for future expansion */
	struct sigcontext uc_mcontext;
};

void arm64_notify_die(const char *str, struct pt_regs *regs, struct siginfo *info, int err);
void set_signal(int sig, void *regs, struct siginfo *info);
void check_signal(unsigned long rc, void *regs, int num);
void check_signal_irq_disabled(unsigned long rc, void *regs, int num);

#endif /* __HEADER_ARM64_COMMON_SIGNAL_H */
