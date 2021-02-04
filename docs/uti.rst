Advanced: Enable Utility Thread offloading Interface (UTI)
-------------------------------------------------------------

UTI enables a runtime such as MPI runtime to spawn utility threads such
as MPI asynchronous progress threads to Linux cores.

Install ``capstone`` and ``capstone-devel``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When compute nodes don't have access to EPEL repository
"""""""""""""""""""""""""""""""""""""""""""""""""""""""

Install EPEL ``capstone`` and ``capstone-devel``:

::

   sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
   sudo yum install capstone capstone-devel


When compute nodes don't have access to EPEL repository
"""""""""""""""""""""""""""""""""""""""""""""""""""""""

A. Ask the system administrator to install ``capstone`` and ``capstone-devel``. Note that it is in the EPEL repository.

B. Download the rpm with the machine in which you are the administrator:

::

   sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
   sudo yum install yum-utils
   yumdownloader capstone capstone-devel

and then install it to your home directory of the login node:

::

   cd $HOME/$(uname -p)
   rpm2cpio capstone-4.0.1-9.el8.aarch64.rpm | cpio -idv
   rpm2cpio capstone-devel-4.0.1-9.el8.aarch64.rpm | cpio -idv
   sed -i 's#/usr/#'"$HOME"'/'"$(uname -p)"'/usr/#' $HOME/$(uname -p)/usr/lib64/pkgconfig/capstone.pc


Install syscall_intercept
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   git clone https://github.com/RIKEN-SysSoft/syscall_intercept.git
   mkdir build && cd build

When ``capstone`` and ``capstone-devel`` are installed into the system directory:

::

   cmake ../syscall_intercept/arch/aarch64 -DCMAKE_INSTALL_PREFIX=${HOME}/$(uname -p)/usr -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DTREAT_WARNINGS_AS_ERRORS=OFF

When ``capstone`` and ``capstone-devel`` are installed into your home directory:

::

   CMAKE_PREFIX_PATH=${HOME}/$(uname -p)/usr cmake ../syscall_intercept/arch/aarch64 -DCMAKE_INSTALL_PREFIX=${HOME}/$(uname -p)/usr -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DTREAT_WARNINGS_AS_ERRORS=OFF

Install:

::

   make && make install && make test

Install UTI for McKernel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install:

.. code-block:: none

   git clone https://github.com/RIKEN-SysSoft/uti.git
   mkdir build && cd build
   ../uti/configure --prefix=<mckernel-install> --with-rm=mckernel
   make && make install

Install McKernel
~~~~~~~~~~~~~~~~~~~~

``cmake`` with the additional options:

::

   CMAKE_PREFIX_PATH=${HOME}/$(uname -p)/usr cmake -DCMAKE_INSTALL_PREFIX=${HOME}/ihk+mckernel -DENABLE_UTI=ON $HOME/src/ihk+mckernel/mckernel
   make -j install

Run programs
~~~~~~~~~~~~~~~~

``mcexec`` with ``--enable-uti`` option:

::

   mcexec --enable-uti <command>

Install UTI for Linux
~~~~~~~~~~~~~~~~~~~~~~~~~

You should skip this step if it's already installed as with, for example, Fujitsu Technical Computing Suite.

Install by make
"""""""""""""""

.. code-block:: none

   git clone https://github.com/RIKEN-SysSoft/uti.git
   mkdir build && cd build
   ../uti/configure --prefix=<uti-install> --with-rm=linux
   make && make install

Install by rpm
""""""""""""""

.. code-block:: none

   git clone https://github.com/RIKEN-SysSoft/uti.git
   mkdir build && cd build
   ../uti/configure --prefix=<uti-install> --with-rm=linux
   rm -f ~/rpmbuild/SOURCES/<version>.tar.gz
   rpmbuild -ba ./scripts/uti.spec
   rpm -Uvh uti-<version>-<release>-<arch>.rpm
