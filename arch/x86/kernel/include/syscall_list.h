/**
 * \file syscall_list.h
 *  License details are found in the file LICENSE.
 * \brief
 *  define system calls
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

/*
 * SYSCALL_HANDLED(number, name)
 *     defines the system call that handled by McKernel.
 *     handler is defined with SYSCALL_DECLARE.
 *
 * SYSCALL_DELEGATED(number, name)
 *     defines the system call that is just delegated to the host.
 *     syscall_name[] only, no handler exists.
 */

SYSCALL_DELEGATED(0, read)
SYSCALL_DELEGATED(1, write)
SYSCALL_DELEGATED(2, open)
SYSCALL_DELEGATED(3, close)
SYSCALL_DELEGATED(4, stat)
SYSCALL_DELEGATED(5, fstat)
SYSCALL_DELEGATED(8, lseek)
SYSCALL_HANDLED(9, mmap)
SYSCALL_HANDLED(10, mprotect)
SYSCALL_HANDLED(11, munmap)
SYSCALL_HANDLED(12, brk)
SYSCALL_HANDLED(13, rt_sigaction)
SYSCALL_HANDLED(14, rt_sigprocmask)
SYSCALL_HANDLED(15, rt_sigreturn)
SYSCALL_DELEGATED(16, ioctl)
SYSCALL_DELEGATED(17, pread64)
SYSCALL_DELEGATED(18, pwrite64)
SYSCALL_DELEGATED(20, writev)
SYSCALL_DELEGATED(21, access)
SYSCALL_HANDLED(24, sched_yield)
SYSCALL_HANDLED(25, mremap)
SYSCALL_HANDLED(26, msync)
SYSCALL_HANDLED(28, madvise)
SYSCALL_HANDLED(34, pause)
SYSCALL_HANDLED(39, getpid)
SYSCALL_HANDLED(56, clone)
SYSCALL_DELEGATED(57, fork)
SYSCALL_HANDLED(58, vfork)
SYSCALL_HANDLED(59, execve)
SYSCALL_HANDLED(60, exit)
SYSCALL_HANDLED(61, wait4)
SYSCALL_HANDLED(62, kill)
SYSCALL_DELEGATED(63, uname)
SYSCALL_DELEGATED(72, fcntl)
SYSCALL_DELEGATED(79, getcwd)
SYSCALL_DELEGATED(89, readlink)
SYSCALL_DELEGATED(96, gettimeofday)
SYSCALL_HANDLED(97, getrlimit)
SYSCALL_HANDLED(101, ptrace)
SYSCALL_DELEGATED(102, getuid)
SYSCALL_DELEGATED(104, getgid)
SYSCALL_DELEGATED(107, geteuid)
SYSCALL_DELEGATED(108, getegid)
SYSCALL_HANDLED(109, setpgid)
SYSCALL_HANDLED(110, getppid)
SYSCALL_DELEGATED(111, getpgrp)
SYSCALL_HANDLED(127, rt_sigpending)
SYSCALL_HANDLED(128, rt_sigtimedwait)
SYSCALL_HANDLED(129, rt_sigqueueinfo)
SYSCALL_HANDLED(130, rt_sigsuspend)
SYSCALL_HANDLED(131, sigaltstack)
SYSCALL_HANDLED(142, sched_setparam)
SYSCALL_HANDLED(143, sched_getparam)
SYSCALL_HANDLED(144, sched_setscheduler)
SYSCALL_HANDLED(145, sched_getscheduler)
SYSCALL_HANDLED(146, sched_get_priority_max)
SYSCALL_HANDLED(147, sched_get_priority_min)
SYSCALL_HANDLED(148, sched_rr_get_interval)
SYSCALL_HANDLED(149, mlock)
SYSCALL_HANDLED(150, munlock)
SYSCALL_HANDLED(158, arch_prctl)
SYSCALL_HANDLED(160, setrlimit)
SYSCALL_HANDLED(186, gettid)
SYSCALL_DELEGATED(201, time)
SYSCALL_HANDLED(202, futex)
SYSCALL_HANDLED(203, sched_setaffinity)
SYSCALL_HANDLED(204, sched_getaffinity)
SYSCALL_HANDLED(216, remap_file_pages)
SYSCALL_DELEGATED(217, getdents64)
SYSCALL_HANDLED(218, set_tid_address)
SYSCALL_HANDLED(231, exit_group)
SYSCALL_HANDLED(234, tgkill)
SYSCALL_HANDLED(237, mbind)
SYSCALL_HANDLED(238, set_mempolicy)
SYSCALL_HANDLED(239, get_mempolicy)
SYSCALL_HANDLED(247, waitid)
SYSCALL_HANDLED(256, migrate_pages)
SYSCALL_HANDLED(273, set_robust_list)
SYSCALL_HANDLED(279, move_pages)
SYSCALL_HANDLED(282, signalfd)
SYSCALL_HANDLED(289, signalfd4)
#ifdef DCFA_KMOD
SYSCALL_HANDLED(303, mod_call)
#endif
SYSCALL_HANDLED(309, getcpu)
SYSCALL_HANDLED(601, pmc_init)
SYSCALL_HANDLED(602, pmc_start)
SYSCALL_HANDLED(603, pmc_stop)
SYSCALL_HANDLED(604, pmc_reset)
SYSCALL_HANDLED(700, get_cpu_id)

/**** End of File ****/
