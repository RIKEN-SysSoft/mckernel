Advanced: Enable Utility Thread offloading Interface (UTI)
-------------------------------------------------------------

UTI enables a runtime such as MPI runtime to spawn utility threads such
as MPI asynchronous progress threads to Linux cores.

Install capstone
~~~~~~~~~~~~~~~~~~~~

When compute nodes don't have access to repositories
""""""""""""""""""""""""""""""""""""""""""""""""""""

Install EPEL capstone-devel:

::

   sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
   sudo yum install capstone-devel


When compute nodes don't have access to repositories
""""""""""""""""""""""""""""""""""""""""""""""""""""

Ask the system administrator to install ``capstone-devel``. Note that it is in the EPEL repository.


Install syscall_intercept
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   git clone https://github.com/RIKEN-SysSoft/syscall_intercept.git
   mkdir build && cd build
   cmake <syscall_intercept>/arch/aarch64 -DCMAKE_INSTALL_PREFIX=<syscall-intercept-install> -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DTREAT_WARNINGS_AS_ERRORS=OFF

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

Add ``-DENABLE_UTI=ON`` option to ``cmake``:

::

   CMAKE_PREFIX_PATH=<syscall-intercept-install> cmake -DCMAKE_INSTALL_PREFIX=${HOME}/ihk+mckernel -DENABLE_UTI=ON $HOME/src/ihk+mckernel/mckernel

Run programs
~~~~~~~~~~~~~~~~

Add ``--enable-uti`` option to ``mcexec``:

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
