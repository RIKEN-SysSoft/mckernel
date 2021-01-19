.. sectnum::
   :suffix: .
   :depth: 3

Architectural Overview
======================

See `Quick Guide -- Architectural Overview <quick.html#architectural-overview>`__.

Running Programs
================

You need to check if your application and pre-/post-processing programs are suited to run with McKernel.
Follow the guide below to choose to run the whole on McKernel, or run the whole on Linux, or run pre-/post-processing on Linux and the application on McKernel:

* Application

  - Run the whole on Linux if it issues system calls frequently and becoming the bottleneck with McKernel, e.g., those performing many file I/O operations.
  - Otherwise, run it on McKernel.

* Pre-/Post-processing

  - Run it on McKernel if it consumes a large amount of memory or the execution time isn't prolonged prohivitively with McKernel. The reason for the first condition is that the resource could be limited for Linux CPUs in the nodes for McKernel.
  - Otherwise, run it on Linux.


Modify job script
-----------------

When using job submission system, you need to modify the job scripts so that the job script itself is going to run on Linux.
For example, with Fujitsu Technical Computing Suite (TCS), you need to specify ``jobenv=mck1`` by inserting the following line into the job script:

.. code-block:: none

   #PJM -L jobenv=mck1

(Optional, Fujitsu TCS only) Specify boot parameters
----------------------------------------------------

You can specify the boot parameters by defining environmental variables and pass them to Fujitsu TCS.
The parameters include the resource reservation settings, resource reservation amount, kernel arguments and routing of message channels between McKernel CPUs and Linux CPUs.
See `IHK Specifications - ihk_create_os_str() <spec/ihk.html>`__ for the parameter names and allowed values.
The example of setting the memory amount is shown below.

.. code-block:: none

   export IHK_MEM="7G@4,7G@5,7G@6,7G@7"
   pjsub -X run.sh

Insert ``mcexec`` into the command line
---------------------------------------

You need to insert ``mcexec`` into the command lines invoking the programs that you chose to run on McKernel:

Non-MPI programs
~~~~~~~~~~~~~~~~

Insert ``mcexec`` before an executable:

::

   mcexec ./a.out

MPI programs
~~~~~~~~~~~~

Insert ``mcexec -n <processes-per-node>`` **after mpirun** and before an
executable:

::

   mpirun -n <number-of-MPI-processes> mcexec -n <processes-per-node> ./a.out

``<processes-per-node>`` is the number of the processes per node and
calculated by (number of MPI processes) / (number of nodes).

For example, ``<processes-per-node>`` equals to 4 (=32/8) when
specifying the number of processes and nodes as follows with
Fujitsu Technical Computing Suite.

.. code-block:: none

   #PJM --mpi "proc=32"
   #PJM -L "node=8"

Limitations
===========

1.  Pseudo devices such as /dev/mem and /dev/zero are not mmap()ed
    correctly even if the mmap() returns a success. An access of their
    mapping receives the SIGSEGV signal.

2.  clone() supports only the following flags. All the other flags cause
    clone() to return error or are simply ignored.

    -  CLONE_CHILD_CLEARTID
    -  CLONE_CHILD_SETTID
    -  CLONE_PARENT_SETTID
    -  CLONE_SETTLS
    -  CLONE_SIGHAND
    -  CLONE_VM

3.  PAPI has the following restriction.

    -  Number of counters a user can use at the same time is up to the
       number of the physical counters in the processor.

4.  msync writes back only the modified pages mapped by the calling
    process.

5.  The following syscalls always return the ENOSYS error.

    -  migrate_pages()
    -  move_pages()
    -  set_robust_list()

6.  The following syscalls always return the EOPNOTSUPP error.

    -  arch_prctl(ARCH_SET_GS)
    -  signalfd()

7.  signalfd4() returns a fd, but signal is not notified through the fd.

8.  set_rlimit sets the limit values but they are not enforced.

9.  Address randomization is not supported.

10. brk() extends the heap more than requestd when -h (–extend-heap-by=)
    option of mcexec is used with the value larger than 4 KiB.
    syscall_pwrite02 of LTP would fail for this reason. This is because
    the test expects that the end of the heap is set to the same address
    as the argument of sbrk() and expects a segmentation violation
    occurs when it tries to access the memory area right next to the
    boundary. However, the optimization sets the end to a value larger
    than the requested. Therefore, the expected segmentation violation
    doesn’t occur.

11. setpriority()/getpriority() won’t work. They might set/get the
    priority of a random mcexec thread. This is because there’s no fixed
    correspondence between a McKernel thread which issues the system
    call and a mcexec thread which handles the offload request.

12. mbind() can set the policy but it is not used when allocating
    physical pages.

13. MPOL_F_RELATIVE_NODES and MPOL_INTERLEAVE flags for
    set_mempolicy()/mbind() are not supported.

14. The MPOL_BIND policy for set_mempolicy()/mbind() works as the same
    as the MPOL_PREFERRED policy. That is, the physical page allocator
    doesn’t give up the allocation when the specified nodes are running
    out of pages but continues to search pages in the other nodes.

15. Kernel dump on Linux panic requires Linux kernel CentOS-7.4 and
    later. In addition, crash_kexec_post_notifiers kernel argument must
    be given to Linux kernel.

16. setfsuid()/setfsgid() cannot change the id of the calling thread.
    Instead, it changes that of the mcexec worker thread which takes the
    system-call offload request.

17. mmap (hugeTLBfs): The physical pages corresponding to a map are
    released when no McKernel process exist. The next map gets fresh
    physical pages.

18. Sticky bit on executable file has no effect.

19. Linux (RHEL-7 for x86_64) could hang when offlining CPUs in the
    process of booting McKernel due to the Linux bug, found in
    Linux-3.10 and fixed in the later version. One way to circumvent
    this is to always assign the same CPU set to McKernel.

20. madvise:

    -  MADV_HWPOISON and MADV_SOFT_OFFLINE always returns -EPERM.
    -  MADV_MERGEABLE and MADV_UNMERGEABLE always returns -EINVAL.
    -  MADV_HUGEPAGE and MADV_NOHUGEPAGE on file map returns -EINVAL
       except on RHEL-8 for aarch64.

21. brk() and mmap() doesn’t report out-of-memory through its return
    value. Instead, page-fault reports the error.

22. Anonymous mmap pre-maps requested number of pages when contiguous
    pages are available. Demand paging is used when not available.

23. Mixing page sizes in anonymous shared mapping is not allowed. mmap
    creates vm_range with one page size. And munmap or mremap that needs
    the reduced page size changes the sizes of all the pages of the
    vm_range.

24. ihk_os_getperfevent() could time-out when invoked from Fujitsu TCS
    (job-scheduler).

25. The behaviors of madvise and mbind are changed to do nothing and
    report success as a workaround for Fugaku.

26. mmap() allows unlimited overcommit. Note that it corresponds to
    setting sysctl ``vm.overcommit_memory`` to 1.
