echo "Don't forget to apply patch.mck and patch.ihk"

. $HOME/.mck_test_config

BOOTPARAM="-c 4-7 -m 512M@0"

. ../../common.sh

$BIN/mcexec ./get_rusage 0
$BIN/mcexec ./issue_1325
$BIN/mcexec ./get_rusage 0

$SBIN/ihkosctl 0 kmsg > ./log
cat ./log | perl match.pl > ./diff
