#!/bin/bash

N=${1}
shift

for i in `seq 1 ${N}`; do
        $@ &
done

wait
