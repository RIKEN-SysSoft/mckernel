=============================================
What's new in version 1.7.0rc4 (Apr 15, 2020)
=============================================

----------------------
McKernel major updates
----------------------
1. arm64: Contiguous PTE support
2. arm64: Scalable Vector Extension (SVE) support
3. arm64: PMU overflow interrupt support
4. xpmem: Support large page attachment
5. arm64 port: Direct access to Mckernel memory from Linux
6. arm64 port: utility thread offloading, which spawns thread onto
   Linux CPU
7. eclair: support for live debug
8. Crash utility extension
9. Replace mcoverlayfs with a soft userspace overlay
10. Build system is switched to cmake
11. Core dump includes thread information

------------------------
McKernel major bug fixes
------------------------
1. shmobj: Fix rusage counting for large page
2. mcctrl control: task start_time changed to u64 nsec
3. mcctrl: add handling for one more level of page tables
4. Add kernel argument to turn on/off time sharing
5. flatten_string/process env: realign env and clear trailing bits
6. madvise: Add MADV_HUGEPAGE support
8. mcctrl: remove in-kernel calls to syscalls
9. arch_cpu_read_write_register: error return fix.
10. set_cputime(): interrupt enable/disable fix.
11. set_mempolicy(): Add mode check.
12. mbind(): Fix memory_range_lock deadlock.
13. ihk_ikc_recv: Record channel to packet for release
14. Add set_cputime() kernel to kernel case and mode enum.
15. execve: Call preempt_enable() before error-exit
16. memory/x86_64: fix linux safe_kernel_map
17. do_kill(): fix pids table when nr of threads is larger than num_processors
18. shmget: Use transparent huge pages when page size isn't specified
19. prctl: Add support for PR_SET_THP_DISABLE and PR_GET_THP_DISABLE
20. monitor_init: fix undetected hang on highest numbered core
21. init_process_stack: change premapped stack size based on arch
22. x86 syscalls: add a bunch of XXat() delegated syscalls
23. do_pageout: fix direct kernel-user access
24. stack: add hwcap auxval
25. perf counters: add arch-specific perf counters
26. Added check of nohost to terminate_host().
27. kmalloc: Fix address order in free list
28. sysfs: use nr_cpu_ids for cpumasks (fixes libnuma parsing error on ARM)
29. monitor_init: Use ihk_mc_cpu_info()
30. Fix ThunderX2 write-combined PTE flag insanity
31. ARM: eliminate zero page mapping (i.e, init_low_area())
32. eliminate futex_cmpxchg_enabled check (not used and dereffed a NULL pointer)
33. page_table: Fix return value of lookup_pte when ptl4 is blank
34. sysfs: add missing symlinks for cpu/node
35. Make Linux handler run when mmap to procfs.
36. Separate mmap area from program loading (relocation) area
37. move rusage into kernel ELF image (avoid dynamic alloc before NUMA init)
38. arm: turn off cpu on panic
39. page fault handler: protect thread accesses
40. Register PPD and release_handler at the same time.
41. fix to missing exclusive processing between terminate() and
    finalize_process().
42. perfctr_stop: add flags to no 'disable_intens'
43. fileobj, shmobj: free pages in object destructor (as opposed to page_unmap())
44. clear_range_l1, clear_range_middle: Fix handling contiguous PTE
45. do_mmap: don't pre-populate the whole file when asked for smaller segment
46. invalidate_one_page: Support shmobj and contiguous PTE
47. ubsan: fix undefined shifts
48. x86: disable zero mapping and add a boot pt for ap trampoline
49. rusage: Don't count PF_PATCH change
50. Fixed time processing.
51. copy_user_pte: vmap area not owned by McKernel
52. gencore: Zero-clear ELF header and memory range table
53. rpm: ignore CMakeCache.txt in dist and relax BuildRequires on cross build
54. gencore: Allocate ELF header to heap instead of stack
55. nanosleep: add cpu_pause() in spinwait loop
56. init_process: add missing initializations to proc struct
57. rus_vm_fault: always use a packet on the stack
58. process stack: use PAGE_SIZE in aux vector
59. copy_user_pte: base memobj copy on range & VR_PRIVATE
60. arm64: ptrace: Fix overwriting 1st argument with return value
61. page fault: use cow for private device mappings
62. reproductible builds: remove most install paths in c code
63. page fault: clear writable bit for non-dirtying access to shared ranges
64. mcreboot/mcstop+release: support for regular user execution
65. irqbalance_mck: replace extra service with service drop-in
66. do_mmap: give addr argument a chance even if not MAP_FIXED
67. x86: fix xchg() and cmpxchg() macros
68. IHK: support for using Linux work IRQ as IKC interrupt (optional)
69. MCS: fix ARM64 issue by using smp_XXX() functions (i.e., barrier()s)
70. procfs: add number of threads to stat and status
71. memory_range_lock: Fix deadlock in procfs/sysfs handler
72. flush instruction cache at context switch time if necessary
73. arm64: Fix PMU related functions
74. page_fault_process_memory_range: Disable COW for VM region with zeroobj
75. extend_process_region: Fall back to demand paging when not contiguous
76. munmap: fix deadlock with remote pagefault on vm range lock
77. procfs: if memory_range_lock fails, process later
78. migrate-cpu: Prevent migration target from calling schedule() twice
79. sched_request_migrate(): fix race condition between migration req and IRQs
80. get_one_cpu_topology: Renumber core_id (physical core id)
81. bb7e140 procfs cpuinfo: use sequence number as processor
82. set_host_vma(): do NOT read protect Linux VMA

===========================================
What's new in V1.6.0 (Nov 11, 2018)
===========================================

-----------------------------------------------
McKernel new features, improvements and changes
-----------------------------------------------
1. McKernel and Linux share one unified kernel virtual address space.
   That is, McKernel sections resides in Linux sections spared for
   modules.  In this way, Linux can access the McKernel kernel memory
   area.
2. hugetlbfs support
3. IHK is now included as a git submodule
4. Debug messages are turned on/off in per souce file basis at run-time.
5. It's prohibited for McKernel to access physical memory ranges which
   Linux didn't give to McKernel.
6. UTI (capability to spawn a thread on Linux CPU) improvement:
   * System calls issued from the thread are hooked by modifying
     binary in memory.

---------------------------
McKernel bug fixes (digest)
---------------------------
#<num> below corresponds to the redmine issue number
(https://postpeta.pccluster.org/redmine/).

1. #926: shmget: Hide object with IPC_RMID from shmget
2. #1028: init_process: Inherit parent cpu_set
3. #995: Fix shebang recorded in argv[0]
4. #1024: Fix VMAP virtual address leak
5. #1109: init_process_stack: Support "ulimit -s unlimited"
6. x86 mem init: do not map identity mapping
7. mcexec_wait_syscall: requeue potential request on interrupted wait
8. mcctrl_ikc_send_wait: fix interrupt with do_frees == NULL
9. pager_req_read: handle short read
10. kprintf: only call eventfd() if it is safe to interrupt
11. process_procfs_request: Add Pid to /proc/<PID>/status
12. terminate: fix oversubscribe hang when waiting for other threads on same CPU to die
13. mcexec: Do not close fd returned to mckernel side
14. #976: execve: Clear sigaltstack and fp_regs
15. #1002: perf_event: Specify counter by bit_mask on start/stop
16. #1027: schedule: Don't reschedule immediately when wake up on migrate
17. #mcctrl: lookup unexported symbols at runtime
18. __sched_wakeup_thread: Notify interrupt_exit() of re-schedule
19. futex_wait_queue_me: Spin-sleep when timeout and idle_halt is specified
20. #1167: ihk_os_getperfevent,setperfevent: Timeout IKC sent by mcctrl
21. devobj: fix object size (POSTK_DEBUG_TEMP_FIX_36)
22. mcctrl: remove rus page cache
23. #1021: procfs: Support multiple reads of e.g. /proc/*/maps
24. #1006: wait: Delay wake-up parent within switch context
25. #1164: mem: Check if phys-mem is within the range of McKernel memory
26. #1039: page_fault_process_memory_range: Remove ihk_mc_map_virtual for CoW of device map
27. partitioned execution: pass process rank to LWK
28. process/vm: implement access_ok()
29. spinlock: rewrite spinlock to use Linux ticket head/tail format
30. #986: Fix deadlock involving mmap_sem and memory_range_lock
31. Prevent one CPU from getting chosen by concurrent forks
32. #1009: check_signal: system call restart is done only once
33. #1176: syscall: the signal received during system call processing is not processed.
34. #1036 syscall_time: Handle by McKernel
35. #1165 do_syscall: Delegate system calls to the mcexec with the same pid
36. #1194 execve: Fix calling ptrace_report_signal after preemption is disabled
37. #1005 coredump: Exclude special areas
38. #1018 procfs: Fix pread/pwrite to procfs fail when specified size is bigger than 4MB
39. #1180 sched_setaffinity: Check migration after decrementing in_interrupt
40. #771, #1179, #1143 ptrace supports threads
41. #1189 procfs/do_fork: wait until procfs entries are registered
42. #1114 procfs: add '/proc/pid/stat' to mckernel side and fix its comm
43. #1116 mcctrl procfs: check entry was returned before using it
44. #1167 ihk_os_getperfevent,setperfevent: Return -ETIME when IKC timeouts
45. mcexec/execve: fix shebangs handling
46. procfs: handle 'comm' on mckernel side
47. ihk_os_setperfevent: Return number of registered events
48. mcexec: fix terminating zero after readlink()

===========================================
What's new in V1.5.1 (July 9, 2018)
===========================================

-----------------------------------------------
McKernel new features, improvements and changes
-----------------------------------------------
1. Watchdog timer to detect hang of McKernel
   mcexec prints out the following line to its stderr when a hang of
   McKernel is detected.

       mcexec detected hang of McKernel

   The watchdog timer is enabled by passing -i <timeout_in_sec> option
   to mcreboot.sh. <timeout_in_sec> specifies the interval of checking
   if McKernel is alive.
   Example: mcreboot.sh -i 600: Detect the hang with 10 minutes interval

   The detailed step of the hang detection is as follows.
   (1) mcexec acquires eventfd for notification from IHK and perform
       epoll() on it.
   (2) A daemon called ihkmond monitors the state of McKernel periodically
       with the interval specified by the -i option. It judges that
       McKernel is hanging and notifies mcexec by the eventfd if its
       state hasn't changed since the last check.

2. Documentation
   man page: Installed directory is changed to <install_dir>/share/man

---------------------------
McKernel bug fixes (digest)
---------------------------
1.  #1146: pager_req_map(): do not take mmap_sem if not needed
2.  #1135: prepare_process_ranges_args_envs(): fix saving cmdline
3.  #1144: fileobj/devobj: record path name
4.  #1145: fileobj: use MCS locks for per-file page hash
5.  #1076: mcctrl: refactor prepare_image into new generic ikc send&wait
6.  #1072: execve: fix execve with oversubscribing
7.  #1132: execve: use thread variable instead of cpu_local_var(current)
8.  #1117: mprotect: do not set page table writable for cow pages
9.  #1143: syscall wait4: add _WALL (POSTK_DEBUG_ARCH_DEP_44)
10. #1064: rusage: Fix initialization of rusage->num_processors
11. #1133: pager_req_unmap: Put per-process data at exit
12. #731: do_fork: Propagate error code returned by mcexec
13. #1149: execve: Reinitialize vm_regions's map area on execve
14. #1065: procfs: Show file names in /proc/<PID>/maps
15. #1112: mremap: Fix type of size arguments (from ssize_t to size_t)
16. #1121: sched_getaffinity: Check arguments in the same order as in Linux
17. #1137: mmap, mremap: Check arguments in the same order as in Linux
18. #1122: fix return value of sched_getaffinity
19. #732: fix: /proc/<PID>/maps outputs a unnecessary NULL character

===================================
What's new in V1.5.0 (Apr 5, 2018)
===================================

--------------------------------------
McKernel new features and improvements
--------------------------------------
1. Aid for Linux version migration: Detect /proc, /sys format change
   between two kernel verions
2. Swap out
   * Only swap-out anonymous pages for now
3. Improve support of /proc/maps
4. mcstat: Linux tool to show resource usage

---------------------------
McKernel bug fixes (digest)
---------------------------
1. #727: execve: Fix memory leak when receiving SIGKILL
2. #829: perf_event_open: Support PERF_TYPE_HARDWARE and PERF_TYPE_HW_CACHE
3. #906: mcexec: Check return code of fork()
4. #1038: mcexec: Timeout when incorrect value is given to -n option
5. #943 #945 #946 #960 $961: mcexec: Support strace
6. #1029: struct thread is not released with stress-test involving signal
          and futex
7. #863 #870: Respond immediately to terminating signal when
              offloading system call
8. #1119: translate_rva_to_rpa(): use 2MB blocks in 1GB pages on x86
11. #898: Shutdown OS only after no in-flight IKC exist
12. #882: release_handler: Destroy objects as the process which opened it
13. #882: mcexec: Make child process exit if the parent is killed during
          fork()
14. #925: XPMEM: Don't destroy per-process object of the parent
15. #885: ptrace: Support the case where a process attaches its child
16. #1031: sigaction: Support SA_RESETHAND
17. #923: rus_vm_fault: Return error when a thread not performing
          system call offloading causes remote page fault
18. #1032 #1033 #1034: getrusage: Fix ru_maxrss, RUSAGE_CHILDREN,
                       ru_stime related bugs
19. #1120: getrusage: Fix deadlock on thread->times_update
20. #1123: Fix deadlock related to wait_queue_head_list_node
21. #1124: Fix deadlock of calling terminate() from terminate()
22. #1125: Fix deadlock related to thread status
    * Related functions are: hold_thread(), do_kill() and terminate()
23. #1126: uti: Fix uti thread on the McKernel side blocks others in do_syscall()
24. #1066: procfs: Show Linux /proc/self/cgroup
25. #1127: prepare_process_ranges_args_envs(): fix generating saved_cmdline to
           avoid PF in strlen()
26. #1128: ihk_mc_map/unmap_virtual(): do proper TLB invalidation
27. #1043: terminate(): fix update_lock and threads_lock order to avoid deadlock
28. #1129: mcreboot.sh: Save /proc/irq/*/smp_affinity to /tmp/mcreboot
29. #1130: mcexec: drop READ_IMPLIES_EXEC from personality

--------------------
McKernel workarounds
--------------------
1. Forbid CPU oversubscription
   * It can be turned on by mcreboot.sh -O option


===================================
What's new in V1.4.0 (Oct 30, 2017)
===================================

-----------------------------------------------------------
Feature: Abstracted event type support in perf_event_open()
-----------------------------------------------------------
PERF_TYPE_HARDWARE and PERF_TYPE_CACHE types are supported.

----------------------------------
Clean-up: Direct user-space access
----------------------------------
Code lines using direct user-space access (e.g. passing user-space
pointer to memcpy()) becomes more portable across processor
architectures. The modification follows the following rules.

1. Move the code section as it is to the architecture dependent
   directory if it is a part of the critical-path.
2. Otherwise, rewrite the code section by using the portable methods.
   The methods include copy_from_user(), copy_to_user(),
   pte_get_phys() and phys_to_virt().

--------------------------------
Test: MPI and OpenMP micro-bench
--------------------------------
The performance figures of MPI and OpenMP primitives are compared with
those of Linux by using Intel MPI Benchmarks and EPCC OpenMP Micro
Benchmark.


===================================
What's new in V1.3.0 (Sep 30, 2017)
===================================

--------------------
Feature: Kernel dump
--------------------
1. A dump level of "only kernel memory" is added.

The following two levels are available now:
   0: Dump all
  24: Dump only kernel memory

The dump level can be set by -d option in ihkosctl or the argument
for ihk_os_makedumpfile(), as shown in the following examples:

   Command:		ihkosctl 0 dump -d 24
   Function call:	ihk_os_makedumpfile(0, NULL, 24, 0);

2. Dump file is created when Linux panics.

The dump level can be set by dump_level kernel argument, as shown in the
following example:

   ihkosctl 0 kargs "hidos dump_level=24"

The IHK dump function is registered to panic_notifier_list when creating
/dev/mcdX and called when Linux panics.

-----------------------------
Feature: Quick Process Launch
-----------------------------

MPI process launch time and some of the initialization time can be
reduced in application consisting of multiple MPI programs which are
launched in turn in the job script.

The following two steps should be performed to use this feature:
1. Replace mpiexec with ql_mpiexec_start and add some lines for
   ql_mpiexec_finalize in the job script
2. Modify the app so that it can repeat calculations and wait for the
   instructions from ql_mpiexec_{start,finalize} at the end of the
   loop

The first step is explained using an example. Assume the original job
script looks like this:

/* Execute ensamble simulation and then data assimilation, and repeat this
   ten times */
for i in {1..10}; do

     /* Each ensamble simulation execution uses 100 nodes, launch ten of them
        in parallel */
    for j in {1..10}; do
         mpiexec -n 100 -machinefile ./list1_$j p1.out a1 & pids[$i]=$!;
    done

    /* Wait until the ten ensamble simulation programs finish */
    for j in {1..10}; do wait ${pids[$j]}; done

    /* Launch one data assimilation program using 1000 nodes */
    mpiexec -n 1000 -machinefile ./list2 p2.out a2
done

The job script should be modified like this:

for i in {1..10}; do
    for j in {1..10}; do
        /*  Replace mpiexec with ql_mpiexec_start */
        ql_mpiexec_start -n 100 -machinefile ./list1_$j p1.out a1 & pids[$j]=$!;
    done

    for j in {1..10}; do wait ${pids[$j]}; done

    ql_mpiexec_start -n 1000 -machinefile ./list2 p2.out a2
done

/* p1.out and p2.out don't exit but are waiting for the next calculation.
   So tell them to exit */
for j in {1..10}; do
   ql_mpiexec_finalize -machinefile ./list1_$i p1.out a1;
done
ql_mpiexec_finalize -machinefile ./list2 p2.out a2;


The second step is explained using a pseudo-code.

    MPI_Init();
    Prepare data exchange with preceding / following MPI programs
loop:
    foreach Fortran module
        Initialize data using command-line argments, parameter files,
	environment variables
    Input data from preceding MPI programs / Read snap-shot
    Perform main calculation
    Output data to following MPI programs / Write snap-shot
    /* ql_client() waits for command of ql_mpiexec_{start,finish} */
    if (ql_client() == QL_CONTINUE) { goto loop; }
    MPI_Finalize();

qlmpilib.h should be included in the code and libql{mpi,fort}.so
should be linked to the executable file.


========================
Restrictions on McKernel
========================

 1. Pseudo devices such as /dev/mem and /dev/zero are not mmap()ed
    correctly even if the mmap() returns a success. An access of their
    mapping receives the SIGSEGV signal.

 2. clone() supports only the following flags. All the other flags
    cause clone() to return error or are simply ignored.

    * CLONE_CHILD_CLEARTID
    * CLONE_CHILD_SETTID
    * CLONE_PARENT_SETTID
    * CLONE_SETTLS
    * CLONE_SIGHAND
    * CLONE_VM

 3. PAPI has the following restriction.

    * Number of counters a user can use at the same time is up to the
      number of the physical counters in the processor.

 4. msync writes back only the modified pages mapped by the calling process.

 5. The following syscalls always return the ENOSYS error.

    * migrate_pages()
    * move_pages()
    * set_robust_list()

 6. The following syscalls always return the EOPNOTSUPP error.

    * arch_prctl(ARCH_SET_GS)
    * signalfd()

 7. signalfd4() returns a fd, but signal is not notified through the
    fd.

 8. set_rlimit sets the limit values but they are not enforced.

 9. Address randomization is not supported.

10. brk() extends the heap more than requestd when -h
    (--extend-heap-by=)<step> option of mcexec is used with the value
    larger than 4 KiB.  syscall_pwrite02 of LTP would fail for this
    reason. This is because the test expects that the end of the heap
    is set to the same address as the argument of sbrk() and expects a
    segmentation violation occurs when it tries to access the memory
    area right next to the boundary. However, the optimization sets
    the end to a value larger than the requested. Therefore, the
    expected segmentation violation doesn't occur.

11. setpriority()/getpriority() won't work. They might set/get the
    priority of a random mcexec thread. This is because there's no
    fixed correspondence between a McKernel thread which issues the
    system call and a mcexec thread which handles the offload request.

12. mbind() can set the policy but it is not used when allocating
    physical pages.

13. MPOL_F_RELATIVE_NODES and MPOL_INTERLEAVE flags for
    set_mempolicy()/mbind() are not supported.

14. The MPOL_BIND policy for set_mempolicy()/mbind() works as the same
    as the MPOL_PREFERRED policy. That is, the physical page allocator
    doesn't give up the allocation when the specified nodes are
    running out of pages but continues to search pages in the other
    nodes.

15. Kernel dump on Linux panic requires Linux kernel CentOS-7.4 and
    later. In addition, crash_kexec_post_notifiers kernel argument
    must be given to Linux kernel.

16. setfsuid()/setfsgid() cannot change the id of the calling thread.
    Instead, it changes that of the mcexec worker thread which takes
    the system-call offload request.

17. mmap (hugeTLBfs): The physical pages corresponding to a map are
    released when no McKernel process exist. The next map gets fresh
    physical pages.

18. Sticky bit on executable file has no effect.

19. Linux (RHEL-7 for x86_64) could hang when offlining CPUs in the
    process of booting McKernel due to the Linux bug, found in
    Linux-3.10 and fixed in the later version.  One way to circumvent
    this is to always assign the same CPU set to McKernel.

20. madvise:
    * MADV_HWPOISON and MADV_SOFT_OFFLINE always returns -EPERM.
    * MADV_MERGEABLE and MADV_UNMERGEABLE always returns -EINVAL.
    * MADV_HUGEPAGE and MADV_NOHUGEPAGE on file map returns -EINVAL
      (It succeeds on RHEL-8 for aarch64).

21. brk() and mmap() doesn't report out-of-memory through its return
    value. Instead, page-fault reports the error.

22. Anonymous mmap pre-maps requested number of pages when contiguous
    pages are available. Demand paging is used when not available.

23. Mixing page sizes in anonymous shared mapping is not allowed. mmap
    creates vm_range with one page size. And munmap or mremap that
    needs the reduced page size changes the sizes of all the pages of
    the vm_range.

24. ihk_os_getperfevent() could time-out when invoked from Fujitsu TCS
    (job-scheduler).

25. The behaviors of madvise and mbind are changed to do nothing and
    report success as a workaround for Fugaku.

26. mmap() allows unlimited overcommit. Note that it corresponds to
    setting sysctl ``vm.overcommit_memory`` to 1.
