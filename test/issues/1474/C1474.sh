ELTP=1
USEOSTEST=0

. ../../common.sh

################################################################################
uname -m
dd if=/dev/zero of=testfile bs=4096 count=1
$MCEXEC ./C1474T01
rm -f outfile
$MCEXEC ./C1474T02
rm -f outfile
$MCEXEC ./C1474T03
rm -f outfile
$MCEXEC --enable-uti ./C1474T04
rm -f outfile
$MCEXEC --enable-uti ./C1474T05
rm -f outfile
$MCEXEC --enable-uti ./C1474T06
rm -f outfile
rm -f testfile
