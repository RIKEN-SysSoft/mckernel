#!/bin/bash
# \file arch/x86/tools/mcshutdown-attached-mic.sh.in
#  License details are found in the file LICENSE.
# \brief
#  mckernel shutdown script
#
# \author McKernel Development Team
#

prefix="/opt/ppos"
BINDIR="/opt/ppos/bin"
SBINDIR="/opt/ppos/sbin"
KMODDIR="/opt/ppos/kmod"
KERNDIR="/opt/ppos/attached/kernel"

"$SBINDIR/ihkosctl" 0 shutdown
