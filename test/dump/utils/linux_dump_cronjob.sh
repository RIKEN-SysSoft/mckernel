#!/bin/sh

sleep 3

export TERM=xterm-256color

export DUMP_TEST_HOME=$(cd `dirname $0`/.. && pwd -P)
cd ${DUMP_TEST_HOME}
./go_linux_dump_test.sh
