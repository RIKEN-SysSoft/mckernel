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

   cmake kernel-devel binutils-devel systemd-devel numactl-devel gcc make nasm git libdwarf-devel capstone-devel

When having access to repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On RHEL 8, enable the CodeReady Linux Builder (CLB) repository:

::

   sudo subscription-manager repos --enable codeready-builder-for-rhel-8-$(/bin/arch)-rpms

On CentOS 8, enable the PowerTools repository:

::

   sudo dnf config-manager --set-enabled PowerTools

Enable EPEL repository:

::

   sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

Install with yum:

::

   sudo yum install cmake kernel-devel binutils-devel systemd-devel numactl-devel gcc make nasm git libdwarf-devel capstone-devel

When not having access to repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``libdwarf-devel``
""""""""""""""""""

Ask the system administrator to install them. Note that ``libdwarf-devel`` is in the CodeReady Linux Builder repository on RHEL 8 or in the PowerTools repository on CentOS 8.

``capstone-devel``
""""""""""""""""""

A. Ask the system administrator to install ``capstone-devel``. Note that it is in the EPEL repository.

B. Download the rpm with the machine in which you are the administrator:

::

   sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
   sudo yum install yum-utils
   yumdownloader capstone-devel

And then install it to your home directory:

::

   cd $HOME/$(uname -p)
   rpm2cpio capstone-devel-4.0.1-9.el8.aarch64.rpm | cpio -idv
   sed -i 's#/usr/#'"$HOME"'/'"$(uname -p)"'/usr/#' $HOME/$(uname -p)/usr/lib64/pkgconfig/capstone.pc


Clone, compile, install
--------------------------

Clone the source code:

::

   mkdir -p ~/src/ihk+mckernel/
   cd ~/src/ihk+mckernel/
   git clone --recursive -b development https://github.com/ihkmckernel/mckernel.git

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

   CMAKE_PREFIX_PATH=${HOME}/$(uname -p)/usr \
     cmake -DCMAKE_INSTALL_PREFIX=${HOME}/ihk+mckernel \
     -DENABLE_UTI=ON \
     ../mckernel

Note that ``CMAKE_PREFIX_PATH=${HOME}/$(uname -p)/usr`` is required only when ``capstone-devel`` is installed to your home directory.

When cross-compiling:
~~~~~~~~~~~~~~~~~~~~~

::

   cmake -DCMAKE_INSTALL_PREFIX=${HOME}/ihk+mckernel \
     -DUNAME_R=<target_uname_r> \
     -DKERNEL_DIR=<kernnel_dir> \
     -DBUILD_TARGET=smp-arm64 \
     -DCMAKE_TOOLCHAIN_FILE=../mckernel/cmake/cross-aarch64.cmake \
     -DENABLE_UTI=ON \
     ../mckernel

Install with cmake
~~~~~~~~~~~~~~~~~~

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

   systemd-libs numactl-libs libdwarf capstone

When having access to repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On RHEL 8, enable the CodeReady Linux Builder (CLB) repository:

::

   sudo subscription-manager repos --enable codeready-builder-for-rhel-8-$(/bin/arch)-rpms

On CentOS 8, enable the PowerTools repository:

::

   sudo dnf config-manager --set-enabled PowerTools

Enable EPEL repository:

::

   sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

Install with yum:

::

   sudo yum install systemd-libs numactl-libs libdwarf capstone

When not having access to repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``libdwarf``
""""""""""""

Ask the system administrator to install them. Note that ``libdwarf`` is in the CodeReady Linux Builder repository on RHEL 8 or in the PowerTools repository on CentOS 8.

``capstone``
""""""""""""

A. Ask the system administrator to install ``capstone``. Note that it is in the EPEL repository.

B. Download the rpm with the machine in which you are the administrator:

::

   sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
   sudo yum install yum-utils
   yumdownloader capstone

and then install it to your home directory:

::

   cd $HOME/$(uname -p)
   rpm2cpio capstone-4.0.1-9.el8.aarch64.rpm | cpio -idv


Notes for Fujitsu TCS/KRM based A64FX systems (e.g., Fugaku/Wisteria)
---------------------------------------------------------------------

When building McKernel for Fujitsu TCS/KRM one needs to pass the following flags to cmake:

::

   cmake -DCMAKE_INSTALL_PREFIX=${HOME}/ihk+mckernel/ -DENABLE_TOFU=ON -DENABLE_FUGAKU_HACKS=ON -DENABLE_FUGAKU_DEBUG=OFF -DENABLE_KRM_WORKAROUND=OFF -DWITH_KRM=ON -DENABLE_FJMPI_WORKAROUND=ON ~/src/mckernel/

Then build the kernel and create the source package for rpmbuild:

::

   make -j 32 install
   make dist
   cp mckernel-1.8.0.tar.gz ~/rpmbuild/SOURCES/
   rpmbuild -ba scripts/mckernel.spec

This will create a set of mckernel rpms similar to what has been described above.

Compute nodes:
~~~~~~~~~~~~~~

On the compute nodes one needs to install the mckernel packages along with Fujitsu's TCS/KRM IHK/McKernel extensions, for example:

::

   rpm -i --nodeps FJSVpxkrm-plugin-mckernel-4.0.1-24.13.2.0.el8.aarch64.rpm FJSVpxpwrm_api_mck-3.0.1-02_4.18.0_240.el8.aarch64.rpm FJSVxoshpcpwr-plugin-mckernel-0.0.0.3-0_4.18.0_240.el8.aarch64.rpm FJSVxosmck-0.0.7-1.el8.aarch64.rpm

Specail care must be taken to the config file /etc/opt/FJSVtcs/krm/mck_common.conf which needs to specify the correct NUMA nodes used for the LWK:

::

   JobNUMANodes             = [4,5,6,7];
