/**
 * \file arch/x86/kernel/include/signal.h
 *  License details are found in the file LICENSE.
 * \brief
 *  define signal
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 *      Copyright (C) 2012 - 2013 Hitachi, Ltd.
 */
/*
 * HISTORY:
 *  2012/02/11 bgerofi what kind of new features have been added
 */

#ifndef __HEADER_X86_COMMON_SIGNAL_H
#define __HEADER_X86_COMMON_SIGNAL_H

#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS (_NSIG / _NSIG_BPW)

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

#define SA_NOCLDSTOP    0x00000001u
#define SA_NOCLDWAIT    0x00000002u
#define SA_NODEFER      0x40000000u
#define SA_ONSTACK      0x08000000u
#define SA_RESETHAND    0x80000000u
#define SA_RESTART      0x10000000u
#define SA_SIGINFO      0x00000004u

struct k_sigaction {
        struct sigaction sa;
};

typedef struct sigaltstack {
	void	*ss_sp;
	int	ss_flags;
	size_t	ss_size;
} stack_t;

#define MINSIGSTKSZ 2048
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

#endif /*__HEADER_X86_COMMON_SIGNAL_H*/
