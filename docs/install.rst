.. highlight:: bash

Installation
============

The following OS distributions and platforms are recommended:

* OS distribution

  * CentOS 7.3 or later
  * RHEL 7.3 or later

* Platform

  * Intel Xeon
  * Intel Xeon Phi
  * Fujitsu A64FX

Prepare files for building McKernel
-----------------------------------

Grant read permission to the System.map file of your kernel version on the build machine:

::

   sudo chmod a+r /boot/System.map-`uname -r`

Install the following packages to the build machine:

::

   cmake kernel-devel binutils-devel systemd-devel numactl-devel gcc make nasm git libdwarf-devel

When having access to repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On RHEL 8, enable the CodeReady Linux Builder (CLB) repository:

::

   sudo subscription-manager repos --enable codeready-builder-for-rhel-8-$(/bin/arch)-rpms

On CentOS 8, enable the PowerTools repository:

::

   sudo dnf config-manager --set-enabled PowerTools

Install with yum:

::

   sudo yum install cmake kernel-devel binutils-devel systemd-devel numactl-devel gcc make nasm git libdwarf-devel

When not having access to repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ask the system administrator to install them. Note that ``libdwarf-devel`` is in the CodeReady Linux Builder repository on RHEL 8 or in the PowerTools repository on CentOS 8.

Clone, compile, install
--------------------------

Clone the source code:

::

   mkdir -p ~/src/ihk+mckernel/
   cd ~/src/ihk+mckernel/
   git clone --recursive -b development https://github.com/RIKEN-SysSoft/mckernel.git

(Optional) Checkout to the specific branch or version:

::

   cd mckernel
   git checkout <pathspec>
   git submodule update

Foe example, if you want to try the development branch, use
“development” as the pathspec. If you want to try the prerelease version
1.7.0-0.2, use “1.7.0-0.2”.

Move to build directory:

::

   mkdir -p ~/src/ihk+mckernel/build && cd ~/src/ihk+mckernel/build

Run cmake:

When not cross-compiling:
~~~~~~~~~~~~~~~~~~~~~~~~~

::

   cmake -DCMAKE_INSTALL_PREFIX=${HOME}/ihk+mckernel ../mckernel

When cross-compiling:
~~~~~~~~~~~~~~~~~~~~~

::

   cmake -DCMAKE_INSTALL_PREFIX=${HOME}/ihk+mckernel \
     -DUNAME_R=<target_uname_r> \
     -DKERNEL_DIR=<kernnel_dir> \
     -DBUILD_TARGET=smp-arm64 \
     -DCMAKE_TOOLCHAIN_FILE=../mckernel/cmake/cross-aarch64.cmake \
     ../mckernel

Install with cmake
~~~~~~~~~~~~~~~~~~~~~~

Install with make:

::

   make -j install

The kernel modules and McKernel kernel image should be installed
under the **ihk+mckernel** folder in your home directory.

Install with rpm
~~~~~~~~~~~~~~~~~~~~

Create the tarball and the spec file:

::

   make dist
   cp mckernel-<version>.tar.gz <rpmbuild>/SOURCES

(optional) Insert a line into ``scripts/mckernel.spec`` to specify
cmake options. For example:

::

   %cmake -DCMAKE_BUILD_TYPE=Release \
	-DUNAME_R=%{kernel_version} \
	-DKERNEL_DIR=%{kernel_dir} \
	%{?cmake_libdir:-DCMAKE_INSTALL_LIBDIR=%{cmake_libdir}} \
	%{?build_target:-DBUILD_TARGET=%{build_target}} \
	%{?toolchain_file:-DCMAKE_TOOLCHAIN_FILE=%{toolchain_file}} \
	-DENABLE_TOFU=ON -DENABLE_FUGAKU_HACKS=ON -DENABLE_KRM_WORKAROUND=OFF -DWITH_KRM=ON -DENABLE_FUGAKU_DEBUG=OFF \
	.

Create the rpm package:

When not cross-compiling:
"""""""""""""""""""""""""

Then build the rpm:

::

   rpmbuild -ba scripts/mckernel.spec

When cross-compiling:
"""""""""""""""""""""

::

   rpmbuild -ba scripts/mckernel.spec --target <target_uname_m> -D 'kernel_version <target_uname_r>' -D 'kernel_dir <kernel_source>'

Install the rpm package:

::

   sudo rpm -ivh <rpmbuild>/RPMS/<arch>/mckernel-<version>-<release>_<linux_kernel_ver>_<dist>.<arch>.rpm

The kernel modules and McKernel kernel image are installed under the
standard system directories.

Prepare files and change settings for installing McKernel
---------------------------------------------------------

Disable SELinux of the compute nodes:

::

   sudo vim /etc/selinux/config

Change the file to SELINUX=disabled. And then reboot the compute nodes:

::

   sudo reboot

Install the following packages to the compute nodes:

::

   systemd-libs numactl-libs libdwarf

When having access to repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On RHEL 8, enable the CodeReady Linux Builder (CLB) repository:

::

   sudo subscription-manager repos --enable codeready-builder-for-rhel-8-$(/bin/arch)-rpms

On CentOS 8, enable the PowerTools repository:

::

   sudo dnf config-manager --set-enabled PowerTools

Install with yum:

::

   sudo yum install systemd-libs numactl-libs libdwarf

When not having access to repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ask the system administrator to install them. Note that ``libdwarf`` is in the CodeReady Linux Builder repository on RHEL 8 or in the PowerTools repository on CentOS 8.
