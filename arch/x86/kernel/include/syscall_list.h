/*
 * [x86] syscall_list.h
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
SYSCALL_HANDLED(2, open)
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
SYSCALL_DELEGATED(16, ioctl)
SYSCALL_DELEGATED(17, pread)
SYSCALL_DELEGATED(18, pwrite)
SYSCALL_DELEGATED(20, writev)
SYSCALL_DELEGATED(21, access)
SYSCALL_HANDLED(24, sched_yield)
SYSCALL_HANDLED(28, madvise)
SYSCALL_HANDLED(39, getpid)
SYSCALL_HANDLED(56, clone)
SYSCALL_HANDLED(60, exit)
SYSCALL_DELEGATED(63, uname)
SYSCALL_DELEGATED(72, fcntl)
SYSCALL_DELEGATED(79, getcwd)
SYSCALL_DELEGATED(89, readlink)
SYSCALL_DELEGATED(96, gettimeofday)
SYSCALL_HANDLED(97, getrlimit)
SYSCALL_DELEGATED(102, getuid)
SYSCALL_DELEGATED(104, getgid)
SYSCALL_DELEGATED(107, geteuid)
SYSCALL_DELEGATED(108, getegid)
SYSCALL_DELEGATED(110, getpgid)
SYSCALL_DELEGATED(111, getppid)
SYSCALL_HANDLED(158, arch_prctl)
SYSCALL_DELEGATED(201, time)
SYSCALL_HANDLED(202, futex)
SYSCALL_HANDLED(203, sched_setaffinity)
SYSCALL_HANDLED(204, sched_getaffinity)
SYSCALL_DELEGATED(217, getdents64)
SYSCALL_HANDLED(218, set_tid_address)
SYSCALL_HANDLED(231, exit_group)
SYSCALL_HANDLED(234, tgkill)
SYSCALL_HANDLED(273, set_robust_list)
#ifdef DCFA_KMOD
SYSCALL_HANDLED(303, mod_call)
#endif
SYSCALL_HANDLED(502, process_data_section)
SYSCALL_HANDLED(601, pmc_init)
SYSCALL_HANDLED(602, pmc_start)
SYSCALL_HANDLED(603, pmc_stop)
SYSCALL_HANDLED(604, pmc_reset)

/**** End of File ****/
