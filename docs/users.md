## Architectural Overview

At the heart of the stack is a low-level software infrastructure called Interface for Heterogeneous Kernels (IHK). IHK is a general framework that provides capabilities for partitioning resources in a many-core environment (e.g.,CPU cores and physical memory) and it enables management of lightweight kernels. IHK can allocate and release host resources dynamically and no reboot of the host machine is required when altering configuration. IHK also provides a low-level inter-kernel messaging infrastructure, called the Inter-Kernel Communication (IKC) layer. An architectural overview of the main system components is shown below.


![arch](mckernel.png)


McKernel is a lightweight kernel written from scratch. It is designed for HPC and is booted from IHK. McKernel retains a binary compatible ABI with Linux, however, it implements only a small set of performance sensitive system calls and the rest are offloaded to Linux. Specifically, McKernel has its own memory management, it supports processes and multi-threading with a simple round-robin cooperative (tick-less) scheduler, and it implements signaling. It also allows inter-process memory mappings and it provides interfaces to hardware performance counters.

### Functionality

An overview of some of the principal functionalities of the IHK/McKernel stack is provided below.

#### System Call Offloading

System call forwarding in McKernel is implemented as follows. When an offloaded system call occurs, McKernel marshals the system call number along with its arguments and sends a message to Linux via a dedicated IKC channel. The corresponding proxy process running on Linux is by default waiting for system call requests through an ioctl() call into IHK’s system call delegator kernel module. The delegator kernel module’s IKC interrupt handler wakes up the proxy process, which returns to userspace and simply invokes the requested system call. Once it obtains the return value, it instructs the delegator module to send the result back to McKernel, which subsequently passes the value to user-space.

#### Unified Address Space

The unified address space model in IHK/McKernel ensures that offloaded system calls can seamlessly resolve arguments even in case of pointers. This mechanism is depicted below and is implemented as follows.


![unified_ap](unified_address_space_en.png)


First, the proxy process is compiled as a position independent binary, which enables us to map the code and data segments specific to the proxy process to an address range which is explicitly excluded from McKernel’s user space. The grey box on the right side of the figure demonstrates the excluded region. Second, the entire valid virtual address range of McKernel’s application user-space is covered by a special mapping in the proxy process for which we use a pseudo file mapping in Linux. This mapping is indicated by the blue box on the left side of the figure.

## Running Programs

### Non-MPI programs

Insert `mcexec` before an executable:

~~~~
mcexec ./a.out
~~~~

### MPI programs

Insert `mcexec -n <processes-per-node>` **after mpirun** and before an executable:

~~~~
mpirun -n 32 mcexec -n 8 ./a.out
~~~~

`<processes-per-node>` is the number of the processes per node and calculated by (number of MPI processes) / (number of nodes).

## Limitations

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
    * MADV_HUGEPAGE and MADV_NOHUGEPAGE on file map returns -EINVAL except on RHEL-8 for aarch64.

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
