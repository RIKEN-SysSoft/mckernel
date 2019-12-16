#!/bin/env bash
# run.sh COPYRIGHT FUJITSU LIMITED 2019
test_dir=$(dirname "${BASH_SOURCE[0]}")
result_dir="$test_dir/results"

# read config
. "${test_dir}/../common.sh"

# settings
test_bin="$test_dir/perf_overflow"
test_cases=`cat << __EOF__
000 1
001 2
002 3
003 4
010 5 -c READ,RESET,REFRESH
011 5 -c READ,READ,REFRESH
012 5 -c RESET,RESET,READ
013 5 -c REFRESH,REFRESH,RESET
014 5 -c REFRESH,READ,READ
__EOF__`

mkdir -p "$result_dir"
while read num args
do
	"$test_bin" $args > "$result_dir/${num}.host"
	"${MCEXEC}" 0 "$test_bin" $args > "$result_dir/${num}.mck"

	diff -q "$result_dir/${num}.host" "$result_dir/${num}.mck"
	if [ $? -eq 0 ]; then
		echo "$num: OK"
	else
		echo "$num: NG"
	fi
done <<EOF
$test_cases
EOF
