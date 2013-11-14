/**
 * \file arch/x86/kernel/include/signal.h
 *  Licence details are found in the file LICENSE.
 * \brief
 *  define signal
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 *      Copyright (C) 2012 - 2013 Hitachi, Ltd.
 */
/*
 * HISTORY:
 *  2012/02/11 bgerofi what kind of new features have been added
 */

#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS (_NSIG / _NSIG_BPW)

typedef struct {
        unsigned long sig[_NSIG_WORDS];
} sigset_t;

struct sigaction {
	void (*sa_handler)(int);
	unsigned long sa_flags;
	void (*sa_restorer)(int);
	sigset_t sa_mask;
};

struct k_sigaction {
        struct sigaction sa;
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
