#!/bin/sh

if [ $# -lt 1 ]; then
        echo "Error: too few arguments."
        echo "usage: `basename $0` <param_file>"
fi

# read config
source ./config

# read testcase param
source $1

# mcexec processのkill
./utils/kill_mcexec.sh &> /dev/null

# stop mckernel
sudo ${MCMOD_DIR}/sbin/mcstop+release.sh

# boot mckernel
echo "${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT%,}"
sudo ${MCMOD_DIR}/sbin/mcreboot.sh ${MCRBT_OPT%,}

sleep 1

if [ ! -e "/dev/mcos0" ]; then
	echo "Error: failed to mcreboot"
	exit 1
fi

# exec mckernel test program
for mc_proc in ${USR_PROC}
do
	echo "${MCMOD_DIR}/bin/mcexec ${mc_proc}"
	${MCMOD_DIR}/bin/mcexec ${mc_proc} &
done
# wait mmap
sleep 5

if [ "X${DUMP_FILE}" = "X" ]; then
	dump_cnt=`find ./ -maxdepth 1 -name "mcdump_*" | wc -l`
fi

# do dump
echo "${MCMOD_DIR}/sbin/ihkosctl ${OS_IDX} dump ${DUMP_OPT} ${DUMP_FILE}"
SECONDS=0
if [ "X${NO_SUDO}" = "X" ]; then
	sudo ${MCMOD_DIR}/sbin/ihkosctl ${OS_IDX} dump ${DUMP_OPT} ${DUMP_FILE}
else
	${MCMOD_DIR}/sbin/ihkosctl ${OS_IDX} dump ${DUMP_OPT} ${DUMP_FILE}
fi
rc=$?

echo "Dump takes ${SECONDS} secs."

if [ "X${ERROR_CASE}" = "X" ]; then
	# Normal case
	if [ ${rc} -ne 0 ]; then
		echo "Error: dump returns not 0"
		exit 1
	fi

	if [ "X${DUMP_FILE}" = "X" ]; then
		if [ ${dump_cnt} -eq `find ./ -maxdepth 1 -name "mcdump_*" | wc -l` ]; then
			echo "Error: default dump_file is not created"
			echo "$dump_cnt `ls`"
			exit 1
		else
			out_dump_file=`ls -1 ./mcdump_*`
		fi
	else 
		if [ ! -e ${DUMP_FILE} ]; then
			echo "Error: specified dump_file, ${DUMP_FILE} is not created"
			exit 1
		else
			out_dump_file=${DUMP_FILE}
		fi
	fi
	# show dump_file info
	./utils/show_mckdump.sh ${out_dump_file}
else
	# Error case
	if [ ${rc} -eq 0 ]; then
		echo "dump return 0"
		exit 1
	fi
	if [ "X${DUMP_FILE}" = "X" ]; then
		if [ ${dump_cnt} -ne `find ./ -maxdepth 1 -name "mcdump_*" | wc -l` ]; then
			echo "Error: default dump_file is created"
			exit 1
		fi
	else 
		if [ -e ${DUMP_FILE} ]; then
			echo "Error: specified dump_file, ${DUMP_FILE} is created"
			exit 1
		fi
	fi
fi

exit 0
