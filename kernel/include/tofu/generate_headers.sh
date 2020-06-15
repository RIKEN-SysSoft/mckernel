#!/bin/bash

SCRIPT="`readlink -f ${BASH_SOURCE[0]:-}`"
SCRIPT_DIR=$(dirname ${SCRIPT})
CURRENT_DIR=`pwd`

cd ${SCRIPT_DIR}

DWARF_TOOL=~/src/mckernel-apollo+a64fx/mckernel/tools/dwarf-extract-struct/dwarf-extract-struct

KMODULE=tof_utofu.ko 
if ! tar zxvf /lib/modules/`uname -r`+debug/extra/tof_module.tar.gz ${KMODULE} 2>&1 > /dev/null; then
	echo "error: uncompressing kernel module with debug symbols"
	cd -
	exit 1
fi

${DWARF_TOOL} ${KMODULE} tof_utofu_device enabled > tofu_generated-tof_utofu_device.h
${DWARF_TOOL} ${KMODULE} tof_utofu_cq common tni cqid trans steering mb num_stag | sed "s/struct FILL_IN_MANUALLY trans;/#include \"tof_utofu_cq_trans.h\"/g" > tofu_generated-tof_utofu_cq.h
${DWARF_TOOL} ${KMODULE} tof_utofu_mbpt ucq iova sg nsgents mbptstart pgsz kref > tofu_generated-tof_utofu_mbpt.h
rm ${KMODULE}

KMODULE=tof_core.ko 
if ! tar zxvf /lib/modules/`uname -r`+debug/extra/tof_module.tar.gz ${KMODULE} 2>&1 > /dev/null; then
	echo "error: uncompressing kernel module with debug symbols"
	cd -
	exit 1
fi

${DWARF_TOOL} ${KMODULE} tof_core_cq reg | sed "s/struct FILL_IN_MANUALLY reg;/#include \"tof_core_cq_reg.h\"/g" > tofu_generated-tof_core_cq.h 
rm ${KMODULE}

#cat tofu_generated*.h
cd -
