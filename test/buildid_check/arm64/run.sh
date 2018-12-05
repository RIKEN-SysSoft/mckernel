#!/bin/sh
## run.sh COPYRIGHT FUJITSU LIMITED 2018 ##

USELTP=0
USEOSTEST=0
MCSTOP=0
MCREBOOT=0

. ../../common.sh

result=0

REBOOT="$SBIN/mcreboot.sh"
STOP="$SBIN/mcstop+release.sh"

########################################
## ihk, mckernel, mcexec buildid test ##
########################################

output=`${REBOOT} ${BOOTPARAM} 2>&1`
if [ `echo $?` != 0 ]; then
	echo "${output}" | grep -q "didn't match McKernel build-id"

	if [ `echo $?` == 0 ]; then
		echo "TEST001: OK"
	else
		echo "TEST001: NG, Buildid mismatch mcreboot.sh (other error)."
		echo "${output}"
		result=-1
	fi
else
	echo "TEST001: NG, Buildid mismatch mcreboot.sh (succeeded)."
	result=-1
fi

${STOP}

MCKIMG="${BIN}/../smp-arm64/kernel/mckernel.img"
IHKMOD="${BIN}/../kmod/ihk.ko"
SMPMOD="${BIN}/../kmod/ihk-smp-arm64.ko"
SMPMOD_PARAM="ihk_start_irq=60 ihk_nr_irq=4"
MCCTRLMOD="${BIN}/../kmod/mcctrl.ko"

PARAM_ARRAY=(${BOOTPARAM})

CORE="4-7"
MEMORY="512M@0"

loop=0
for OPT in "${PARAM_ARRAY[@]}"
do
	loop=`expr ${loop} + 1`
	case "${OPT}" in
		'-c')
			CORE="${PARAM_ARRAY[${loop}]}"
			;;
		'-m')
			MEMORY="${PARAM_ARRAY[${loop}]}"
			;;
		*)
			;;
	esac
done

insmod ${IHKMOD}
insmod ${SMPMOD} ${SMPMOD_PARAM}
insmod ${MCCTRLMOD}
${IHKCONFIG} 0 reserve cpu ${CORE}
${IHKCONFIG} 0 reserve mem ${MEMORY}
${IHKCONFIG} 0 create
${IHKOSCTL} 0 assign cpu ${CORE}
${IHKOSCTL} 0 assign mem ${MEMORY}
${IHKOSCTL} 0 kargs hidos
${IHKOSCTL} 0 load ${MCKIMG}
${IHKOSCTL} 0 boot

sleep 1

output=`${MCEXEC} ls 2>&1`
if [ `echo $?` != 0 ]; then
	echo "${output}" | grep -q "didn't match that of IHK"

	if [ `echo $?` == 0 ]; then
		echo "TEST002: OK"
	else
		echo "TEST002: NG, Buildid mismatch mcexec (other error)."
		echo "${output}"
		result=-1
	fi

else
	echo "TEST002: NG, Buildid mismatch mcexec (succeeded)."
	result=-1
fi

exit ${result}
