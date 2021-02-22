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


Install McKernel
~~~~~~~~~~~~~~~~~~~~

``cmake`` with the additional options:

::

   cmake -DCMAKE_INSTALL_PREFIX=${HOME}/ihk+mckernel -DENABLE_UTI=ON $HOME/src/ihk+mckernel/mckernel
   make -j install

Run programs
~~~~~~~~~~~~

``mcexec`` with ``--enable-uti`` option:

::

   mcexec --enable-uti <command>

(Optional) Install UTI for Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can skip this step if you don't want to develop a run-time using UTI, or if it's already installed with, for example, Fujitsu Technical Computing Suite.

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

(Optional) Install UTI for McKernel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can skip this step if you don't want to develop a run-time using UTI.
Execute the commands above for installing UTI for Linux, with ``--with-rm=linux`` replaced with ``--with-rm=mckernel``.
