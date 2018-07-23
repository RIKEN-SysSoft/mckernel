/* syscall_list.h COPYRIGHT FUJITSU LIMITED 2017 */
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

SYSCALL_HANDLED(0, read)
SYSCALL_DELEGATED(1, write)
SYSCALL_HANDLED(2, open)
SYSCALL_HANDLED(3, close)
SYSCALL_DELEGATED(4, stat)
SYSCALL_DELEGATED(5, fstat)
SYSCALL_DELEGATED(7, poll)
SYSCALL_DELEGATED(8, lseek)
SYSCALL_HANDLED(9, mmap)
SYSCALL_HANDLED(10, mprotect)
SYSCALL_HANDLED(11, munmap)
SYSCALL_HANDLED(12, brk)
SYSCALL_HANDLED(13, rt_sigaction)
SYSCALL_HANDLED(14, rt_sigprocmask)
SYSCALL_HANDLED(15, rt_sigreturn)
SYSCALL_HANDLED(16, ioctl)
SYSCALL_DELEGATED(17, pread64)
SYSCALL_DELEGATED(18, pwrite64)
SYSCALL_DELEGATED(20, writev)
SYSCALL_DELEGATED(21, access)
SYSCALL_DELEGATED(23, select)
SYSCALL_HANDLED(24, sched_yield)
SYSCALL_HANDLED(25, mremap)
SYSCALL_HANDLED(26, msync)
SYSCALL_HANDLED(27, mincore)
SYSCALL_HANDLED(28, madvise)
SYSCALL_HANDLED(29, shmget)
SYSCALL_HANDLED(30, shmat)
SYSCALL_HANDLED(31, shmctl)
SYSCALL_HANDLED(34, pause)
SYSCALL_HANDLED(35, nanosleep)
SYSCALL_HANDLED(36, getitimer)
SYSCALL_HANDLED(38, setitimer)
SYSCALL_HANDLED(39, getpid)
SYSCALL_HANDLED(56, clone)
SYSCALL_HANDLED(57, fork)
SYSCALL_HANDLED(58, vfork)
SYSCALL_HANDLED(59, execve)
SYSCALL_HANDLED(60, exit)
SYSCALL_HANDLED(61, wait4)
SYSCALL_HANDLED(62, kill)
SYSCALL_DELEGATED(63, uname)
SYSCALL_DELEGATED(65, semop)
SYSCALL_HANDLED(67, shmdt)
SYSCALL_DELEGATED(69, msgsnd)
SYSCALL_DELEGATED(70, msgrcv)
SYSCALL_HANDLED(72, fcntl)
SYSCALL_DELEGATED(79, getcwd)
SYSCALL_DELEGATED(87, unlink)
SYSCALL_DELEGATED(89, readlink)
SYSCALL_HANDLED(96, gettimeofday)
SYSCALL_HANDLED(97, getrlimit)
SYSCALL_HANDLED(98, getrusage)
SYSCALL_HANDLED(100, times)
SYSCALL_HANDLED(101, ptrace)
SYSCALL_HANDLED(102, getuid)
SYSCALL_HANDLED(104, getgid)
SYSCALL_HANDLED(105, setuid)
SYSCALL_HANDLED(106, setgid)
SYSCALL_HANDLED(107, geteuid)
SYSCALL_HANDLED(108, getegid)
SYSCALL_HANDLED(109, setpgid)
SYSCALL_HANDLED(110, getppid)
SYSCALL_DELEGATED(111, getpgrp)
SYSCALL_HANDLED(113, setreuid)
SYSCALL_HANDLED(114, setregid)
SYSCALL_HANDLED(117, setresuid)
SYSCALL_HANDLED(118, getresuid)
SYSCALL_HANDLED(119, setresgid)
SYSCALL_HANDLED(120, getresgid)
SYSCALL_HANDLED(122, setfsuid)
SYSCALL_HANDLED(123, setfsgid)
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
SYSCALL_HANDLED(151, mlockall)
SYSCALL_HANDLED(152, munlockall)
SYSCALL_HANDLED(158, arch_prctl)
SYSCALL_HANDLED(160, setrlimit)
SYSCALL_HANDLED(164, settimeofday)
SYSCALL_HANDLED(186, gettid)
SYSCALL_HANDLED(200, tkill)
SYSCALL_DELEGATED(201, time)
SYSCALL_HANDLED(202, futex)
SYSCALL_HANDLED(203, sched_setaffinity)
SYSCALL_HANDLED(204, sched_getaffinity)
SYSCALL_DELEGATED(208, io_getevents)
SYSCALL_HANDLED(216, remap_file_pages)
SYSCALL_DELEGATED(217, getdents64)
SYSCALL_HANDLED(218, set_tid_address)
SYSCALL_DELEGATED(220, semtimedop)
SYSCALL_HANDLED(228, clock_gettime)
SYSCALL_DELEGATED(230, clock_nanosleep)
SYSCALL_HANDLED(231, exit_group)
SYSCALL_DELEGATED(232, epoll_wait)
SYSCALL_HANDLED(234, tgkill)
SYSCALL_HANDLED(237, mbind)
SYSCALL_HANDLED(238, set_mempolicy)
SYSCALL_HANDLED(239, get_mempolicy)
SYSCALL_HANDLED(247, waitid)
SYSCALL_HANDLED(256, migrate_pages)
#ifdef POSTK_DEBUG_ARCH_DEP_62 /* Absorb the difference between open and openat args. */
SYSCALL_HANDLED(257, openat)
#endif  /* POSTK_DEBUG_ARCH_DEP_62 */
SYSCALL_DELEGATED(270, pselect6)
SYSCALL_DELEGATED(271, ppoll)
SYSCALL_HANDLED(273, set_robust_list)
SYSCALL_HANDLED(279, move_pages)
SYSCALL_DELEGATED(281, epoll_pwait)
SYSCALL_HANDLED(282, signalfd)
SYSCALL_HANDLED(289, signalfd4)
SYSCALL_HANDLED(298, perf_event_open)
#ifdef DCFA_KMOD
SYSCALL_HANDLED(303, mod_call)
#endif
SYSCALL_HANDLED(309, getcpu)
SYSCALL_HANDLED(310, process_vm_readv)
SYSCALL_HANDLED(311, process_vm_writev)
SYSCALL_HANDLED(700, get_cpu_id)
#ifdef PROFILE_ENABLE
SYSCALL_HANDLED(__NR_profile, profile)
#endif // PROFILE_ENABLE
SYSCALL_HANDLED(730, util_migrate_inter_kernel)
SYSCALL_HANDLED(731, util_indicate_clone)
SYSCALL_HANDLED(732, get_system)

/* McKernel Specific */
SYSCALL_HANDLED(801, swapout)
SYSCALL_HANDLED(802, linux_mlock)
SYSCALL_HANDLED(803, suspend_threads)
SYSCALL_HANDLED(804, resume_threads)
SYSCALL_HANDLED(811, linux_spawn)
/**** End of File ****/
