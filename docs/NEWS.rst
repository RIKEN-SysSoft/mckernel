=============================================
Version 1.7.0rc4 (Apr 15, 2020)
=============================================

----------------------
McKernel major updates
----------------------
1. arm64: Contiguous PTE support
2. arm64: Scalable Vector Extension (SVE) support
3. arm64: PMU overflow interrupt support
4. xpmem: Support large page attachment
5. arm64 port: Direct access to Mckernel memory from Linux
6. arm64 port: utility thread offloading, which spawns thread onto Linux CPU
7. eclair: support for live debug
8. Crash utility extension
9. Replace mcoverlayfs with a soft userspace overlay
10. Build system is switched to cmake
11. Core dump includes thread information

------------------------
McKernel major bug fixes
------------------------
#. shmobj: Fix rusage counting for large page
#. mcctrl control: task start_time changed to u64 nsec
#. mcctrl: add handling for one more level of page tables
#. Add kernel argument to turn on/off time sharing
#. flatten_string / process env: realign env and clear trailing bits
#. madvise: Add MADV_HUGEPAGE support
#. mcctrl: remove in-kernel calls to syscalls
#. arch_cpu_read_write_register: error return fix.
#. set_cputime(): interrupt enable/disable fix.
#. set_mempolicy(): Add mode check.
#. mbind(): Fix memory_range_lock deadlock.
#. ihk_ikc_recv: Record channel to packet for release
#. Add set_cputime() kernel to kernel case and mode enum.
#. execve: Call preempt_enable() before error-exit
#. memory/x86_64: fix linux safe_kernel_map
#. do_kill(): fix pids table when nr of threads is larger than num_processors
#. shmget: Use transparent huge pages when page size isn't specified
#. prctl: Add support for PR_SET_THP_DISABLE and PR_GET_THP_DISABLE
#. monitor_init: fix undetected hang on highest numbered core
#. init_process_stack: change premapped stack size based on arch
#. x86 syscalls: add a bunch of XXat() delegated syscalls
#. do_pageout: fix direct kernel-user access
#. stack: add hwcap auxval
#. perf counters: add arch-specific perf counters
#. Added check of nohost to terminate_host().
#. kmalloc: Fix address order in free list
#. sysfs: use nr_cpu_ids for cpumasks (fixes libnuma parsing error on ARM)
#. monitor_init: Use ihk_mc_cpu_info()
#. Fix ThunderX2 write-combined PTE flag insanity
#. ARM: eliminate zero page mapping (i.e, init_low_area())
#. eliminate futex_cmpxchg_enabled check (not used and dereffed a NULL pointer)
#. page_table: Fix return value of lookup_pte when ptl4 is blank
#. sysfs: add missing symlinks for cpu/node
#. Make Linux handler run when mmap to procfs.
#. Separate mmap area from program loading (relocation) area
#. move rusage into kernel ELF image (avoid dynamic alloc before NUMA init)
#. arm: turn off cpu on panic
#. page fault handler: protect thread accesses
#. Register PPD and release_handler at the same time.
#. fix to missing exclusive processing between terminate() and finalize_process().
#. perfctr_stop: add flags to no 'disable_intens'
#. fileobj, shmobj: free pages in object destructor (as opposed to page_unmap())
#. clear_range_l1, clear_range_middle: Fix handling contiguous PTE
#. do_mmap: don't pre-populate the whole file when asked for smaller segment
#. invalidate_one_page: Support shmobj and contiguous PTE
#. ubsan: fix undefined shifts
#. x86: disable zero mapping and add a boot pt for ap trampoline
#. rusage: Don't count PF_PATCH change
#. Fixed time processing.
#. copy_user_pte: vmap area not owned by McKernel
#. gencore: Zero-clear ELF header and memory range table
#. rpm: ignore CMakeCache.txt in dist and relax BuildRequires on cross build
#. gencore: Allocate ELF header to heap instead of stack
#. nanosleep: add cpu_pause() in spinwait loop
#. init_process: add missing initializations to proc struct
#. rus_vm_fault: always use a packet on the stack
#. process stack: use PAGE_SIZE in aux vector
#. copy_user_pte: base memobj copy on range & VR_PRIVATE
#. arm64: ptrace: Fix overwriting 1st argument with return value
#. page fault: use cow for private device mappings
#. reproductible builds: remove most install paths in c code
#. page fault: clear writable bit for non-dirtying access to shared ranges
#. mcreboot/mcstop+release: support for regular user execution
#. irqbalance_mck: replace extra service with service drop-in
#. do_mmap: give addr argument a chance even if not MAP_FIXED
#. x86: fix xchg() and cmpxchg() macros
#. IHK: support for using Linux work IRQ as IKC interrupt (optional)
#. MCS: fix ARM64 issue by using smp_XXX() functions (i.e., barrier()s)
#. procfs: add number of threads to stat and status
#. memory_range_lock: Fix deadlock in procfs/sysfs handler
#. flush instruction cache at context switch time if necessary
#. arm64: Fix PMU related functions
#. page_fault_process_memory_range: Disable COW for VM region with zeroobj
#. extend_process_region: Fall back to demand paging when not contiguous
#. munmap: fix deadlock with remote pagefault on vm range lock
#. procfs: if memory_range_lock fails, process later
#. migrate-cpu: Prevent migration target from calling schedule() twice
#. sched_request_migrate(): fix race condition between migration req and IRQs
#. get_one_cpu_topology: Renumber core_id (physical core id)
#. bb7e140 procfs cpuinfo: use sequence number as processor
#. set_host_vma(): do NOT read protect Linux VMA

===========================================
Version 1.6.0 (Nov 11, 2018)
===========================================

-----------------------------------------------
McKernel major updates
-----------------------------------------------
#. McKernel and Linux share one unified kernel virtual address space.
   That is, McKernel sections resides in Linux sections spared for
   modules.  In this way, Linux can access the McKernel kernel memory area.
#. hugetlbfs support
#. IHK is now included as a git submodule
#. Debug messages are turned on/off in per souce file basis at run-time.
#. It's prohibited for McKernel to access physical memory ranges which Linux didn't give to McKernel.
#. UTI (capability to spawn a thread on Linux CPU) improvement:

   * System calls issued from the thread are hooked by modifying binary in memory.

---------------------------
McKernel major bug fixes
---------------------------
#<digits> below denotes the redmine issue number (https://postpeta.pccluster.org/redmine/).

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
23. #1021: procfs: Support multiple reads of e.g. ``/proc/*/maps``
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
Version 1.5.1 (July 9, 2018)
===========================================

-----------------------------------------------
McKernel major updates
-----------------------------------------------

Watchdog timer to detect hang of McKernel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

mcexec prints out the following line to its stderr when a hang of McKernel is detected.

::
   
       mcexec detected hang of McKernel

The watchdog timer is enabled by passing -i <timeout_in_sec> option to mcreboot.sh. <timeout_in_sec> specifies the interval of checking if McKernel is alive.

For example, specify ``-i 600`` to detect the hang with 10 minutes interval:

::

   mcreboot.sh -i 600

The detailed step of the hang detection is as follows.
   #. mcexec acquires eventfd for notification from IHK and perform epoll() on it.
   #. A daemon called ihkmond monitors the state of McKernel periodically with the interval specified by the -i option. It judges that McKernel is hanging and notifies mcexec by the eventfd if its state hasn't changed since the last check.

---------------------------
McKernel major bug fixes
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
Version 1.5.0 (Apr 5, 2018)
===================================

--------------------------------------
McKernel major updates
--------------------------------------
1. Aid for Linux version migration: Detect /proc, /sys format change
   between two kernel verions
2. Swap out
   * Only swap-out anonymous pages for now
3. Improve support of /proc/maps
4. mcstat: Linux tool to show resource usage

---------------------------
McKernel major bug fixes
---------------------------
#. #727: execve: Fix memory leak when receiving SIGKILL
#. #829: perf_event_open: Support PERF_TYPE_HARDWARE and PERF_TYPE_HW_CACHE
#. #906: mcexec: Check return code of fork()
#. #1038: mcexec: Timeout when incorrect value is given to -n option
#. #943 #945 #946 #960 #961: mcexec: Support strace
#. #1029: struct thread is not released with stress-test involving signal and futex
#. #863 #870 : Respond immediately to terminating signal when offloading system call
#. #1119: translate_rva_to_rpa(): use 2MB blocks in 1GB pages on x86
#. #898: Shutdown OS only after no in-flight IKC exist
#. #882: release_handler: Destroy objects as the process which opened it
#. #882: mcexec: Make child process exit if the parent is killed during fork()
#. #925: XPMEM: Don't destroy per-process object of the parent
#. #885: ptrace: Support the case where a process attaches its child
#. #1031: sigaction: Support SA_RESETHAND
#. #923: rus_vm_fault: Return error when a thread not performing system call offloading causes remote page fault
#. #1032 #1033 #1034: getrusage: Fix ru_maxrss, RUSAGE_CHILDREN, ru_stime related bugs
#. #1120: getrusage: Fix deadlock on thread->times_update
#. #1123: Fix deadlock related to wait_queue_head_list_node
#. #1124: Fix deadlock of calling terminate() from terminate()
#. #1125: Fix deadlock related to thread status

   * Related functions are: hold_thread(), do_kill() and terminate()

#. #1126: uti: Fix uti thread on the McKernel side blocks others in do_syscall()
#. #1066: procfs: Show Linux /proc/self/cgroup
#. #1127: prepare_process_ranges_args_envs(): fix generating saved_cmdline to avoid PF in strlen()
#. #1128: ihk_mc_map/unmap_virtual(): do proper TLB invalidation
#. #1043: terminate(): fix update_lock and threads_lock order to avoid deadlock
#. #1129: mcreboot.sh: Save ``/proc/irq/*/smp_affinity`` to ``/tmp/mcreboot``
#. #1130: mcexec: drop READ_IMPLIES_EXEC from personality

--------------------
McKernel workarounds
--------------------
#. Forbid CPU oversubscription

   * It can be turned on by mcreboot.sh -O option


===================================
Version 1.4.0 (Oct 30, 2017)
===================================

-----------------------------------------------------------
Abstracted event type support in perf_event_open()
-----------------------------------------------------------

PERF_TYPE_HARDWARE and PERF_TYPE_CACHE types are supported.

----------------------------------
Direct user-space access
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
MPI and OpenMP micro-bench tests
--------------------------------
The performance figures of MPI and OpenMP primitives are compared with
those of Linux by using Intel MPI Benchmarks and EPCC OpenMP Micro
Benchmark.


===================================
Version 1.3.0 (Sep 30, 2017)
===================================

--------------------
Kernel dump
--------------------
#. A dump level of "only kernel memory" is added.

The following two levels are available now:

+--+-----------------------+
| 0|Dump all               |
+--+-----------------------+
|24|Dump only kernel memory|
+--+-----------------------+

The dump level can be set by -d option in ihkosctl or the argument
for ihk_os_makedumpfile(), as shown in the following examples:

::

   Command:		ihkosctl 0 dump -d 24
   Function call:	ihk_os_makedumpfile(0, NULL, 24, 0);

#. Dump file is created when Linux panics.

The dump level can be set by dump_level kernel argument, as shown in the
following example:

::

   ihkosctl 0 kargs "hidos dump_level=24"

The IHK dump function is registered to panic_notifier_list when creating /dev/mcdX and called when Linux panics.

-----------------------------
Quick Process Launch
-----------------------------

MPI process launch time and some of the initialization time can be
reduced in application consisting of multiple MPI programs which are
launched in turn in the job script.

The following two steps should be performed to use this feature:
#. Replace mpiexec with ql_mpiexec_start and add some lines for ql_mpiexec_finalize in the job script
#. Modify the app so that it can repeat calculations and wait for the instructions from ql_mpiexec_{start,finalize} at the end of the loop

The first step is explained using an example. Assume the original job script looks like this:

.. code-block:: none
   
   /* Execute ensamble simulation and then data assimilation, and repeat this ten times */
   for i in {1..10}; do
   
      /* Each ensamble simulation execution uses 100 nodes, launch ten of them in parallel */
      for j in {1..10}; do
         mpiexec -n 100 -machinefile ./list1_$j p1.out a1 & pids[$i]=$!;
      done

      /* Wait until the ten ensamble simulation programs finish */
      for j in {1..10}; do wait ${pids[$j]}; done
      
      /* Launch one data assimilation program using 1000 nodes */
      mpiexec -n 1000 -machinefile ./list2 p2.out a2
   done
   
The job script should be modified like this:

.. code-block:: none

   for i in {1..10}; do
      for j in {1..10}; do
         /*  Replace mpiexec with ql_mpiexec_start */
         ql_mpiexec_start -n 100 -machinefile ./list1_$j p1.out a1 & pids[$j]=$!;
      done
      
      for j in {1..10}; do wait ${pids[$j]}; done
      
      ql_mpiexec_start -n 1000 -machinefile ./list2 p2.out a2
   done
   
   /* p1.out and p2.out don't exit but are waiting for the next calculation. So tell them to exit */
   for j in {1..10}; do
      ql_mpiexec_finalize -machinefile ./list1_$i p1.out a1;
   done
   
   ql_mpiexec_finalize -machinefile ./list2 p2.out a2;

The second step is explained using a pseudo-code.

.. code-block:: none

   MPI_Init();
   Prepare data exchange with preceding / following MPI programs
   loop:
   foreach Fortran module
      Initialize data using command-line argments, parameter files, environment variables
      Input data from preceding MPI programs / Read snap-shot
      Perform main calculation
      Output data to following MPI programs / Write snap-shot
      /* ql_client() waits for command of ql_mpiexec_{start,finish} */
      if (ql_client() == QL_CONTINUE) { goto loop; }
      MPI_Finalize();

qlmpilib.h should be included in the code and libql{mpi,fort}.so should be linked to the executable file.
