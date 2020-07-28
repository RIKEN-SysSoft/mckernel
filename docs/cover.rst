|McKernel Logo|
===============

IHK/McKernel is a light-weight multi-kernel operating system designed
for high-end supercomputing. It runs Linux and McKernel, a light-weight
kernel (LWK), side-by-side inside compute nodes and aims at the
following:

-  Provide scalable and consistent execution of large-scale parallel
   scientific applications, but at the same time maintain the ability to
   rapidly adapt to new hardware features and emerging programming
   models
-  Provide efficient memory and device management so that resource
   contention and data movement are minimized at the system level
-  Eliminate OS noise by isolating OS services in Linux and provide
   jitter free execution on the LWK
-  Support the full POSIX/Linux APIs by selectively offloading
   (slow-path) system calls to Linux

See "Installation" in "Quick Guide" for how to install it.

.. |McKernel Logo| image:: https://www.sys.r-ccs.riken.jp/members_files/bgerofi/mckernel-logo.png
