#!/bin/sh

NUMAS=$1
MEM_SIZE=$2
REP=$3
CHUNKS=""

for numa in ${NUMAS}
do
	for rep in `seq 1 ${REP}`
	do
		CHUNKS="${CHUNKS}${MEM_SIZE}@${numa},"
	done
done

echo ${CHUNKS%,}
