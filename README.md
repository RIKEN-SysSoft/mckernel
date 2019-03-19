![McKernel Logo](https://www.sys.r-ccs.riken.jp/members_files/bgerofi/mckernel-logo.png)
-------------------------

IHK/McKernel is a light-weight multi-kernel operating system designed for high-end supercomputing. It runs Linux and McKernel, a light-weight kernel (LWK), side-by-side inside compute nodes and aims at the following:

- Provide scalable and consistent execution of large-scale parallel scientific applications, but at the same time maintain the ability to rapidly adapt to new hardware features and emerging programming models
- Provide efficient memory and device management so that resource contention and data movement are minimized at the system level
- Eliminate OS noise by isolating OS services in Linux and provide jitter free execution on the LWK
- Support the full POSIX/Linux APIs by selectively offloading (slow-path) system calls to Linux

## Contents

- [Background](#background-and-motivation)
- [Architectural Overview](#architectural-overview)
- [Installation](#installation)
- [The Team](#the-team)

## Background and Motivation

With the growing complexity of high-end supercomputers, the current system software stack faces significant challenges as we move forward to exascale and beyond. The necessity to deal with extreme degree of parallelism, heterogeneous architectures, multiple levels of memory hierarchy, power constraints, etc., advocates operating systems that can rapidly adapt to new hardware requirements, and that can support novel programming paradigms and runtime systems. On the other hand, a new class of more dynamic and complex applications are also on the horizon, with an increasing demand for application constructs such as in-situ analysis, workflows, elaborate monitoring and performance tools. This complexity relies not only on the rich features of POSIX, but also on the Linux APIs (such as the */proc*, */sys* filesystems, etc.) in particular.


##### Two Traditional HPC OS Approaches

Traditionally, light-weight operating systems specialized for HPC followed two approaches to tackle scalable execution of large-scale applications. In the full weight kernel (FWK) approach, a full Linux environment is taken as the basis, and features that inhibit attaining HPC scalability are removed, i.e., making it light-weight. The pure light-weight kernel (LWK) approach, on the other hand, starts from scratch and effort is undertaken to add sufficient functionality so that it provides a familiar API, typically something close to that of a general purpose OS, while at the same time it retains the desired scalability and reliability attributes. Neither of these approaches yields a fully Linux compatible environment.


##### The Multi-kernel Approach

A hybrid approach recognized recently by the system software community is to run Linux simultaneously with a lightweight kernel on compute nodes and multiple research projects are now pursuing this direction. The basic idea is that simulations run on an HPC tailored lightweight kernel, ensuring the necessary isolation for noiseless execution of parallel applications, but Linux is leveraged so that the full POSIX API is supported. Additionally, the small code base of the LWK can also facilitate rapid prototyping for new, exotic hardware features. Nevertheless, the questions of how to share node resources between the two types of kernels, where do device drivers execute, how exactly do the two kernels interact with each other and to what extent are they integrated, remain subjects of ongoing debate.



## Architectural Overview

At the heart of the stack is a low-level software infrastructure called Interface for Heterogeneous Kernels (IHK). IHK is a general framework that provides capabilities for partitioning resources in a many-core environment (e.g.,CPU cores and physical memory) and it enables management of lightweight kernels. IHK can allocate and release host resources dynamically and no reboot of the host machine is required when altering configuration. IHK also provides a low-level inter-kernel messaging infrastructure, called the Inter-Kernel Communication (IKC) layer. An architectural overview of the main system components is shown below.


![arch](https://www.sys.r-ccs.riken.jp/members_files/bgerofi/mckernel.png)


McKernel is a lightweight kernel written from scratch. It is designed for HPC and is booted from IHK. McKernel retains a binary compatible ABI with Linux, however, it implements only a small set of performance sensitive system calls and the rest are offloaded to Linux. Specifically, McKernel has its own memory management, it supports processes and multi-threading with a simple round-robin cooperative (tick-less) scheduler, and it implements signaling. It also allows inter-process memory mappings and it provides interfaces to hardware performance counters.

### Functionality

An overview of some of the principal functionalities of the IHK/McKernel stack is provided below.

#### System Call Offloading

System call forwarding in McKernel is implemented as follows. When an offloaded system call occurs, McKernel marshals the system call number along with its arguments and sends a message to Linux via a dedicated IKC channel. The corresponding proxy process running on Linux is by default waiting for system call requests through an ioctl() call into IHK’s system call delegator kernel module. The delegator kernel module’s IKC interrupt handler wakes up the proxy process, which returns to userspace and simply invokes the requested system call. Once it obtains the return value, it instructs the delegator module to send the result back to McKernel, which subsequently passes the value to user-space.

#### Unified Address Space

The unified address space model in IHK/McKernel ensures that offloaded system calls can seamlessly resolve arguments even in case of pointers. This mechanism is depicted below and is implemented as follows.


![unified_ap](https://www.sys.r-ccs.riken.jp/members_files/bgerofi/img/unified_address_space_en.png)


First, the proxy process is compiled as a position independent binary, which enables us to map the code and data segments specific to the proxy process to an address range which is explicitly excluded from McKernel’s user space. The grey box on the right side of the figure demonstrates the excluded region. Second, the entire valid virtual address range of McKernel’s application user-space is covered by a special mapping in the proxy process for which we use a pseudo file mapping in Linux. This mapping is indicated by the blue box on the left side of the figure.


## Installation

For a smooth experience, we recommend the following combination of OS distributions and platforms:

- CentOS 7.3+ running on Intel Xeon / Xeon Phi


##### 1. Change SELinux settings
Log in as the root and disable SELinux:

~~~~
vim /etc/selinux/config
~~~~

Change the file to SELINUX=disabled

##### 2. Reboot the host machine
~~~~
sudo reboot
~~~~

##### 3. Prepare packages, kernel symbol table file
You will need the following packages installed:

~~~~
sudo yum install cmake kernel-devel binutils-devel systemd-devel numactl-devel
~~~~

Grant read permission to the System.map file of your kernel version:

~~~~
sudo chmod a+r /boot/System.map-`uname -r`
~~~~

##### 4. Obtain sources and compile the kernel

Clone the source code:

~~~~
mkdir -p ~/src/ihk+mckernel/
cd ~/src/ihk+mckernel/
git clone --recursive git@github.com:RIKEN-SysSoft/mckernel.git
~~~~

Configure and compile:

~~~~
mkdir -p build && cd build
cmake -DCMAKE_INSTALL_PREFIX=${HOME}/ihk+mckernel $HOME/src/ihk+mckernel/mckernel
make -j install
~~~~

The IHK kernel modules and McKernel kernel image should be installed under the **ihk+mckernel** folder in your home directory.

##### 5. Boot McKernel

A boot script called mcreboot.sh is provided under sbin in the install folder. To boot on logical CPU 1 with 512MB of memory, use the following invocation:

~~~~
export TOP=${HOME}/ihk+mckernel/
cd ${TOP}
sudo ./sbin/mcreboot.sh -c 1 -m 512m
~~~~

You should see something similar like this if you display the McKernel's kernel message log:


~~~~
./sbin/ihkosctl 0 kmsg

IHK/McKernel started.
[ -1]: no_execute_available: 1
[ -1]: map_fixed: phys: 0xfee00000 => 0xffff860000009000 (1 pages)
[ -1]: setup_x86 done.
[ -1]: ns_per_tsc: 385
[ -1]: KCommand Line: hidos    dump_level=24
[ -1]: Physical memory: 0x1ad3000 - 0x21000000, 525520896 bytes, 128301 pages available @ NUMA: 0
[ -1]: NUMA: 0, Linux NUMA: 0, type: 1, available bytes: 525520896, pages: 128301
[ -1]: NUMA 0 distances: 0 (10),
[ -1]: map_fixed: phys: 0x28000 => 0xffff86000000a000 (2 pages)
[ -1]: Trampoline area: 0x28000
[ -1]: map_fixed: phys: 0x0 => 0xffff86000000c000 (1 pages)
[ -1]: # of cpus : 1
[ -1]: locals = ffff880001af6000
[  0]: BSP: 0 (HW ID: 1 @ NUMA 0)
[  0]: BSP: booted 0 AP CPUs
[  0]: Master channel init acked.
[  0]: vdso is enabled
IHK/McKernel booted.
~~~~


##### 5. Run a simple program on McKernel

The mcexec command line tool (which is also the Linux proxy process) can be used for executing applications on McKernel:

~~~~
./bin/mcexec hostname
centos-vm
~~~~


##### 6. Shutdown McKernel

Finally, to shutdown McKernel and release CPU/memory resources back to Linux use the following command:

~~~~
sudo ./sbin/mcstop+release.sh
~~~~

## The Team

The McKernel project was started at The University of Tokyo and currently it is mainly developed at RIKEN.
Some of our collaborators include:

- Hitachi
- Fujitsu
- CEA (France)
- NEC


## License

McKernel is GPL licensed, as found in the LICENSE file.
