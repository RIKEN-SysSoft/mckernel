#!/bin/bash

if [ $# -lt 2 ]; then
        echo "$0 option error" >&2
        echo "Usage: $0 category test_exp" >&2
        exit 1
fi

cat=$1
test_exp=$2

gdb_installdir=/usr
if [ "X$gdb_builddir" = X ];then
	echo gdb_builddir was not set >&2
	exit 1
fi
if [ "X$MCEXEC" = X ];then
	echo MCEXEC was not set >&2
	exit 1
fi

log_dir="$gdb_builddir/gdb/testsuite"

if ! which runtest > /dev/null 2>&1; then
	echo no runtest found >&2
	exit 1
fi

result=`pwd`/gdb-result
result_raw=`pwd`/gdb-result/raw
export PATH=`pwd`:$PATH

cd ${gdb_builddir}

echo "======== ${test_exp} ========"
# exec by linux
make check RUNTESTFLAGS="--verbose gdb.${cat}/${test_exp}.exp" &> /dev/null
mv ${log_dir}/gdb.log ${result_raw}/linux/${test_exp}.log
mv ${log_dir}/gdb.sum ${result_raw}/linux/${test_exp}.sum

# exec by mcexec
make check RUNTESTFLAGS="--verbose GDB=mcexec_gdb.sh gdb.${cat}/${test_exp}.exp" &> /dev/null
mv ${log_dir}/gdb.log ${result_raw}/mck/${test_exp}.log
mv ${log_dir}/gdb.sum ${result_raw}/mck/${test_exp}.sum

# extract important part
sed -n '/gdb tests/,/expected passes/p' ${result_raw}/linux/${test_exp}.sum > ${result}/linux/${test_exp}.sum
sed -n '/gdb tests/,/expected passes/p' ${result_raw}/mck/${test_exp}.sum > ${result}/mck/${test_exp}.sum

grep -e '^(gdb) [a-zA-Z0-9]' ${result_raw}/linux/${test_exp}.log > ${result}/linux/${test_exp}.log
grep -e '^(gdb) [a-zA-Z0-9]' ${result_raw}/mck/${test_exp}.log > ${result}/mck/${test_exp}.log

diff -u ${result}/linux/${test_exp}.sum ${result}/mck/${test_exp}.sum > /dev/null
if [ $? -eq 0 ]; then
	echo "【SAME】${test_exp}: Summary."
else
	echo "【DIFF】${test_exp} : Summary Difference ---"
	diff -u ${result}/linux/${test_exp}.sum ${result}/mck/${test_exp}.sum
fi

diff -u ${result}/linux/${test_exp}.log ${result}/mck/${test_exp}.log > /dev/null
if [ $? -eq 0 ]; then
	echo "【SAME】${test_exp} : Log."
else
	echo "【DIFF】${test_exp} : Log Difference ---"
	diff -u ${result}/linux/${test_exp}.log ${result}/mck/${test_exp}.log
fi

diff -u <(grep 'of expected passes' ${result}/linux/${test_exp}.sum) <(grep 'of expected passes' ${result}/mck/${test_exp}.sum) > /dev/null
if [ $? -eq 0 ]; then
	echo "【PASS】${test_exp}"
else
	echo "【FAIL】${test_exp}"
	diff -u <(grep 'of expected passes' ${result}/linux/${test_exp}.sum) <(grep 'of expected passes' ${result}/mck/${test_exp}.sum) > /dev/null
fi
