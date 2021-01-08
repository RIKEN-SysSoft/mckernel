# Common test framework, source this file to get config and basic variables:
# BIN/SBIN are the mckernel install paths
# if USELTP is set,
#     LTP is the root of the ltp install directory
#     LTPBIN is the testcases bin dir
# if USEOSTEST is set,
#     OSTEST is the root of the ostest repo after install
#     TESTMCK is the test_mck binary
# MCEXEC, IHKCONFIG, IHKOSCTL are the corresponding binaries
# mcreboot and mcstop are functions that perform the action with prints/checks
#
# Additionally, the following parameters can be provided through environment:
# BOOTPARAM to override mcreboot options
# MCREBOOT and MCSTOP can be set to 0/empty to not run the action at start


# Unfortunately, there is no standard way to get sourced file's path
# use bash-specific feature.
TEST_BASE=$(dirname "${BASH_SOURCE[0]}")

if [ -f "$HOME/.mck_test_config" ]; then
        . "$HOME/.mck_test_config"
elif [ -f "$TEST_BASE/../mck_test_config.sample" ]; then
	. "$TEST_BASE/../mck_test_config.sample"
fi


if [[ -z "$BIN" ]]; then
	if [ -f ../../../config.h ]; then
		BIN=$(awk -F\" '/^#define BINDIR/ { print $2; exit }' \
			  "$TEST_BASE/../config.h")
	fi
fi

if [[ -z "$SBIN" ]]; then
	if [ -f ../../../Makefile ]; then
		SBIN=$(awk -F\" '/^#define SBINDIR/ { print $2; exit }' \
			  "$TEST_BASE/../config.h")
	fi
fi

if [[ ! -x "$BIN/mcexec" ]]; then
	echo no mckernel found $BIN >&2
	exit 1
fi
MCEXEC="$BIN/mcexec"
IHKOSCTL="$SBIN/ihkosctl"
IHKCONFIG="$SBIN/ihkconfig"

if ((USELTP)); then
	if [[ -z "$LTP" ]]; then
		if [[ -f "$HOME/ltp/testcases/bin/fork01" ]]; then
			LTP="$HOME/ltp"
		fi
	fi

	if [[ ! -x "$LTP/testcases/bin/fork01" ]]; then
		echo no LTP found $LTP >&2
		exit 1
	fi
	LTPBIN="$LTP/testcases/bin"
fi

if ((USEOSTEST)); then
	if [[ -z "$OSTEST" ]]; then
		if [[ -f "$HOME/ostest/bin/test_mck" ]]; then
			OSTEST="$HOME/ostest"
		fi
	fi

	if [[ ! -x "$OSTEST"/bin/test_mck ]]; then
		echo no ostest found $OSTEST >&2
		exit 1
	fi
	TESTMCK="$OSTEST/bin/test_mck"
fi

if ((USESTRESSTEST)); then
	if [[ -z "$STRESS_TEST" ]]; then
		if [[ -f "$HOME/stress_test/bin/signalonfork" ]]; then
			STRESS_TEST="$HOME/stress_test"
		fi
	fi

	if [[ ! -x "$STRESS_TEST/bin/signalonfork" ]]; then
		echo no STRESS_TEST found $STRESS_TEST >&2
		exit 1
	fi
	STRESSTESTBIN="$STRESS_TEST/bin"
fi

# compat variables
BINDIR="$BIN"
SBINDIR="$SBIN"
LTPDIR="$LTP"
OSTESTDIR="$OSTEST"

if [[ ! -x "$SBIN/mcstop+release.sh" ]]; then
	echo mcstop+release: not found >&2
	exit 1
fi

if [[ ! -x "$SBIN/mcreboot.sh" ]]; then
	echo mcreboot: not found >&2
	exit 1
fi

mcstop() {
	echo -n "mcstop+release.sh ... "
	"$SBIN/mcstop+release.sh"
	echo "done"

	if lsmod | grep mcctrl > /dev/null 2>&1; then
		echo mckernel shutdown failed >&2
		exit 1
	fi
}

mcreboot() {
	echo -n "mcreboot.sh $BOOTPARAM ... "
	"$SBIN/mcreboot.sh" $BOOTPARAM
	echo "done"

	if ! lsmod | grep mcctrl > /dev/null 2>&1; then
		echo mckernel boot failed >&2
		exit 1
	fi
}

((${MCSTOP-1})) && mcstop
((${MCREBOOT-1})) && mcreboot
