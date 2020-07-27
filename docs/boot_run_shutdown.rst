Boot McKernel
----------------

A boot script called ``mcreboot.sh`` is provided under ``sbin`` in the install
folder. To boot on logical CPU 1 with 512MB of memory, use the following
invocation:

::

   export TOP=${HOME}/ihk+mckernel/
   cd ${TOP}
   sudo ./sbin/mcreboot.sh -c 1 -m 512m

You should see something similar like this if you display the McKernel’s
kernel message log:

.. code-block:: none

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

Run a simple program on McKernel
-----------------------------------

The mcexec command line tool (which is also the Linux proxy process) can
be used for executing applications on McKernel:

::

   ./bin/mcexec hostname
   centos-vm

Shutdown McKernel
--------------------

Finally, to shutdown McKernel and release CPU/memory resources back to
Linux use the following command:

::

   sudo ./sbin/mcstop+release.sh
