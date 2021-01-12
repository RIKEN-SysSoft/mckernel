#!/bin/bash

SCRIPT="`readlink -f ${BASH_SOURCE[0]:-}`"
SCRIPT_DIR=$(dirname ${SCRIPT})
CURRENT_DIR=`pwd`

cd ${SCRIPT_DIR}

DWARF_TOOL=${SCRIPT_DIR}/../../../tools/dwarf-extract-struct/dwarf-extract-struct
if [ ! -x ${DWARF_TOOL} ]; then
	echo "error: couldn't find DWARF extractor executable (${DWARF_TOOL}), have you compiled it?"
	cd -
	exit 1
fi

echo "Looking for Tofu driver debug symbols..."
if [ "`find /lib/modules/ -name "tof_module.tar.gz" | xargs -r ls -t | head -n 1 | wc -l`" == "0" ]; then
	echo "error: couldn't find Tofu modules with debug symbols"
	cd -
	exit 1
fi

MODULE_TAR_GZ=`find /lib/modules/ -name "tof_module.tar.gz" | xargs ls -t | head -n 1`
echo "Using Tofu driver debug symbols: ${MODULE_TAR_GZ}"

KMODULE=tof_utofu.ko 
if ! tar zxvf ${MODULE_TAR_GZ} ${KMODULE} 2>&1 > /dev/null; then
	echo "error: uncompressing kernel module with debug symbols"
	cd -
	exit 1
fi

${DWARF_TOOL} ${KMODULE} tof_utofu_device enabled subnet gpid > tofu_generated-tof_utofu_device.h
${DWARF_TOOL} ${KMODULE} tof_utofu_cq common tni cqid trans steering mb num_stag | sed "s/struct FILL_IN_MANUALLY trans;/#include \"tof_utofu_cq_trans.h\"/g" > tofu_generated-tof_utofu_cq.h
${DWARF_TOOL} ${KMODULE} tof_utofu_mbpt ucq iova sg nsgents mbptstart pgsz kref > tofu_generated-tof_utofu_mbpt.h
${DWARF_TOOL} ${KMODULE} tof_utofu_bg common tni bgid bch | sed "s/struct FILL_IN_MANUALLY bch;/#include \"tof_utofu_bg_bch.h\"/g" > tofu_generated-tof_utofu_bg.h
rm ${KMODULE}

KMODULE=tof_core.ko 
if ! tar zxvf ${MODULE_TAR_GZ} ${KMODULE} 2>&1 > /dev/null; then
	echo "error: uncompressing kernel module with debug symbols"
	cd -
	exit 1
fi

${DWARF_TOOL} ${KMODULE} tof_core_cq reg | sed "s/struct FILL_IN_MANUALLY reg;/#include \"tof_core_cq_reg.h\"/g" > tofu_generated-tof_core_cq.h 
${DWARF_TOOL} ${KMODULE} tof_core_bg lock reg irq subnet gpid sighandler | sed "s/struct FILL_IN_MANUALLY reg;/#include \"tof_core_bg_reg.h\"/g" > tofu_generated-tof_core_bg.h 
rm ${KMODULE}

#cat tofu_generated*.h
cd - > /dev/null
