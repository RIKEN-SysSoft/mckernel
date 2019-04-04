#!/usr/bin/bash

. ../../common.sh

sudo insmod ${HOME}/usr/lib/modules/`uname -r`/xpmem.ko
sudo chmod og+rw /dev/xpmem

log_file="./C1259.log"

${MCEXEC} ./C1259 > ${log_file}
#./C1259

${IHKOSCTL} 0 kmsg >> ${log_file}

XPMEM_ADDR=`grep xpmem_attachment_addr ${log_file} | awk '{ print $3; }'`

if grep 'large page allocation' ${log_file} | grep -c $XPMEM_ADDR > /dev/null; then
    echo "[ OK ] xpmem_addr ($XPMEM_ADDR) is allocated using large pages"
else
    echo "[ NG ] xpmem_addr ($XPMEM_ADDR) isn't allocated using large pages"
fi

sudo rmmod xpmem
