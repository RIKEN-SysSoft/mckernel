# configure.ac COPYRIGHT FUJITSU LIMITED 2015-2016
AC_PREREQ(2.63)
m4_define([IHK_VERSION_m4],[1.5.0])dnl
m4_define([MCKERNEL_VERSION_m4],[1.5.0])dnl
m4_define([IHK_RELEASE_DATE_m4],[2018-04-05])dnl
m4_define([MCKERNEL_RELEASE_DATE_m4],[2018-04-05])dnl

AC_INIT([mckernel], MCKERNEL_VERSION_m4)

dnl *** PAC_APPEND_FLAG is copied from aclocal_util.m4 of mpich-3.3a2 ***
dnl Usage: PAC_APPEND_FLAG([-02], [CFLAGS])
dnl appends the given argument to the specified shell variable unless the
dnl argument is already present in the variable
AC_DEFUN([PAC_APPEND_FLAG],[
	AC_REQUIRE([AC_PROG_FGREP])
	AS_IF(
		[echo "$$2" | $FGREP -e "\<$1\>" >/dev/null 2>&1],
		[echo "$2(='$$2') contains '$1', not appending" >&AS_MESSAGE_LOG_FD],
		[echo "$2(='$$2') does not contain '$1', appending" >&AS_MESSAGE_LOG_FD
		$2="$$2 $1"]
	)
])

dnl *** PAC_SET_HEADER_LIB_PATH is copied from aclocal_libs.m4 of mpich-3.3a2 ***
dnl PAC_SET_HEADER_LIB_PATH(with_option,[default_path])
dnl This macro looks for the --with-xxx=, --with-xxx-include and --with-xxx-lib=
dnl options and sets the library and include paths.
dnl
dnl TODO as written, this macro cannot handle a "with_option" arg that has "-"
dnl characters in it.  Use AS_TR_SH (and possibly AS_VAR_* macros) to handle
dnl this case if it ever arises.
AC_DEFUN([PAC_SET_HEADER_LIB_PATH],[
    AC_ARG_WITH([$1],
                [AC_HELP_STRING([--with-$1=PATH],
                                [specify path where $1 include directory and lib directory can be found])],

                [AS_CASE(["$withval"],
                         [yes|no|''],
                         [AC_MSG_WARN([--with[out]-$1=PATH expects a valid PATH])
                          with_$1=""])],
                [with_$1=$2])
    AC_ARG_WITH([$1-include],
                [AC_HELP_STRING([--with-$1-include=PATH],
                                [specify path where $1 include directory can be found])],
                [AS_CASE(["$withval"],
                         [yes|no|''],
                         [AC_MSG_WARN([--with[out]-$1-include=PATH expects a valid PATH])
                          with_$1_include=""])],
                [])
    AC_ARG_WITH([$1-lib],
                [AC_HELP_STRING([--with-$1-lib=PATH],
                                [specify path where $1 lib directory can be found])],
                [AS_CASE(["$withval"],
                         [yes|no|''],
                         [AC_MSG_WARN([--with[out]-$1-lib=PATH expects a valid PATH])
                          with_$1_lib=""])],
                [])

    # The args have been sanitized into empty/non-empty values above.
    # Now append -I/-L args to CPPFLAGS/LDFLAGS, with more specific options
    # taking priority

    AS_IF([test -n "${with_$1_include}"],
          [PAC_APPEND_FLAG([-I${with_$1_include}],[CPPFLAGS])],
          [AS_IF([test -n "${with_$1}"],
                 [PAC_APPEND_FLAG([-I${with_$1}/include],[CPPFLAGS])])])

    AS_IF([test -n "${with_$1_lib}"],
          [PAC_APPEND_FLAG([-L${with_$1_lib}],[LDFLAGS])],
          [AS_IF([test -n "${with_$1}"],
                 dnl is adding lib64 by default really the right thing to do?  What if
                 dnl we are on a 32-bit host that happens to have both lib dirs available?
                 [PAC_APPEND_FLAG([-L${with_$1}/lib],[LDFLAGS])
                  AS_IF([test -d "${with_$1}/lib64"],
		        [PAC_APPEND_FLAG([-L${with_$1}/lib64],[LDFLAGS])])
                 ])
          ])
])

AC_DEFUN([PAC_SET_HEADER_LIB_PATH_SYSCALL_INTERCEPT],[
    AC_ARG_WITH([$1],
                [AC_HELP_STRING([--with-$1=PATH],
                                [specify path where $1 include directory and lib directory can be found])],

                [AS_CASE(["$withval"],
                         [yes|no|''],
                         [AC_MSG_WARN([--with[out]-$1=PATH expects a valid PATH])
                          with_$1=""])],
                [with_$1=$2])
    AC_ARG_WITH([$1-include],
                [AC_HELP_STRING([--with-$1-include=PATH],
                                [specify path where $1 include directory can be found])],
                [AS_CASE(["$withval"],
                         [yes|no|''],
                         [AC_MSG_WARN([--with[out]-$1-include=PATH expects a valid PATH])
                          with_$1_include=""])],
                [])
    AC_ARG_WITH([$1-lib],
                [AC_HELP_STRING([--with-$1-lib=PATH],
                                [specify path where $1 lib directory can be found])],
                [AS_CASE(["$withval"],
                         [yes|no|''],
                         [AC_MSG_WARN([--with[out]-$1-lib=PATH expects a valid PATH])
                          with_$1_lib=""])],
                [])

    # The args have been sanitized into empty/non-empty values above.
    # Now append -I/-L args to CPPFLAGS/LDFLAGS, with more specific options
    # taking priority

    AS_IF([test -n "${with_$1_include}"],
          [PAC_APPEND_FLAG([-I${with_$1_include}],[CPPFLAGS_SYSCALL_INTERCEPT])],
          [AS_IF([test -n "${with_$1}"],
                 [PAC_APPEND_FLAG([-I${with_$1}/include],[CPPFLAGS_SYSCALL_INTERCEPT])])])

    AS_IF([test -n "${with_$1_lib}"],
          [PAC_APPEND_FLAG([-L${with_$1_lib} -Wl,-rpath,${with_$1_lib}],[LDFLAGS_SYSCALL_INTERCEPT])],
          [AS_IF([test -n "${with_$1}"],
                 dnl is adding lib64 by default really the right thing to do?  What if
                 dnl we are on a 32-bit host that happens to have both lib dirs available?
                 [PAC_APPEND_FLAG([-L${with_$1}/lib -Wl,-rpath,${with_$1}/lib],[LDFLAGS_SYSCALL_INTERCEPT])
                  AS_IF([test -d "${with_$1}/lib64"],
		        [PAC_APPEND_FLAG([-L${with_$1}/lib64 -Wl,-rpath,${with_$1}/lib64],[LDFLAGS_SYSCALL_INTERCEPT])])
                 ])
          ])

    AS_IF([test -n "${with_$1}" || test -n "${with_$1_include}" || test -n "${with_$1_lib}"],
	      [WITH_SYSCALL_INTERCEPT=yes],
	      [WITH_SYSCALL_INTERCEPT=no])
])

IHK_VERSION=IHK_VERSION_m4
MCKERNEL_VERSION=MCKERNEL_VERSION_m4
DCFA_VERSION=DCFA_VERSION_m4
IHK_RELEASE_DATE=IHK_RELEASE_DATE_m4
MCKERNEL_RELEASE_DATE=MCKERNEL_RELEASE_DATE_m4
DCFA_RELEASE_DATE=DCFA_RELEASE_DATE_m4

AC_PREFIX_DEFAULT([/opt/ppos])

AC_CHECK_HEADER([numa.h],[numa_header_found=yes])
AS_IF([test "x$numa_header_found" != "xyes"],
	[AC_MSG_ERROR([Unable to find numa.h header file, missing numactl-devel?])])
AC_CHECK_LIB([numa],[numa_run_on_node],[numa_lib_found=yes])
AS_IF([test "x$numa_lib_found" != "xyes"],
	[AC_MSG_ERROR([Unable to find NUMA library, missing numactl-devel?])])

PAC_SET_HEADER_LIB_PATH([mpi])

PAC_SET_HEADER_LIB_PATH_SYSCALL_INTERCEPT([syscall_intercept])

if test "x$WITH_SYSCALL_INTERCEPT" == "xno" ; then
	AC_CHECK_LIB([syscall_intercept],[syscall_no_intercept],[syscall_intercept_lib_found=yes],[syscall_intercept_lib_found=no],[-lcapstone -ldl])
	AS_IF([test "x$syscall_intercept_lib_found" != "xyes"],
		[AC_MSG_NOTICE([libsyscall_intercept.so not found])])

	AC_CHECK_HEADER([libsyscall_intercept_hook_point.h],[syscall_intercept_header_found=yes],[syscall_intercept_header_found=no])
	AS_IF([test "x$syscall_intercept_header_found" != "xyes"],
		[AC_MSG_NOTICE([libsyscall_intercept_hook_point.h not found])])

	AS_IF([test "x$syscall_intercept_lib_found" == "xyes" && test "x$syscall_intercept_header_found" == "xyes"],
		[WITH_SYSCALL_INTERCEPT=yes],
		[WITH_SYSCALL_INTERCEPT=no])
fi


AC_ARG_WITH([kernelsrc],
  AC_HELP_STRING(
    [--with-kernelsrc=path],[Path to 'kernel src', default is /lib/modules/uname_r/build]),
  [WITH_KERNELSRC=$withval],[WITH_KERNELSRC=yes])

AC_ARG_WITH([target],
  AC_HELP_STRING(
    [--with-target={attached-mic | builtin-mic | builtin-x86 | smp-x86}],[target, default is attached-mic]),
  [WITH_TARGET=$withval],[WITH_TARGET=yes])

AC_ARG_WITH([system_map],
  AS_HELP_STRING(
    [--with-system_map=path],[Path to 'System.map file', default is /boot/System.map-uname_r]),
  [WITH_SYSTEM_MAP=$withval],[WITH_SYSTEM_MAP=yes])

AC_ARG_ENABLE([dcfa],
  [AS_HELP_STRING(
  	[--enable-dcfa],[Enable DCFA modules])],[],[enable_dcfa=no])

AC_ARG_ENABLE([memdump],
	      AC_HELP_STRING([--enable-memdump],
			     [enable dumping memory and analyzing a dump]),
	      [ENABLE_MEMDUMP=$enableval],
	      [ENABLE_MEMDUMP=default])

AC_ARG_ENABLE([mcoverlayfs],
	      AC_HELP_STRING([--enable-mcoverlayfs],
			     [enable mcoverlayfs implementation]),
	      [ENABLE_MCOVERLAYFS=$enableval],
	      [ENABLE_MCOVERLAYFS=yes])

AC_ARG_ENABLE([rusage],
	      AC_HELP_STRING([--enable-rusage],
			     [enable rusage implementation]),
	      [ENABLE_RUSAGE=$enableval],
	      [ENABLE_RUSAGE=yes])

AC_ARG_ENABLE([perf],
	      AC_HELP_STRING([--enable-perf],
			     [enable perf_event implementation]),
	      [ENABLE_PERF=$enableval],
	      [ENABLE_PERF=yes])

AC_ARG_ENABLE([qlmpi],
	      AC_HELP_STRING([--enable-qlmpi],
			     [enable qlmpi implementation]),
	      [ENABLE_QLMPI=$enableval],
	      [ENABLE_QLMPI=no])

AC_ARG_WITH([uname_r],
  AC_HELP_STRING(
    [--with-uname_r=uname_r],[Value of '`uname -r`' on the target platform, default is local value]),
  [WITH_UNAME_R=$withval],[WITH_UNAME_R=yes])

case "X$WITH_UNAME_R" in
    Xyes | Xno | X)
	WITH_UNAME_R='`uname -r`'
	;;
esac

case "X$WITH_KERNELSRC" in
    Xyes | Xno | X)
	WITH_KERNELSRC="/lib/modules/`uname -r`/build"
	;;
    X/*)
	;;
    *)
	WITH_KERNELSRC="`pwd`/$WITH_KERNELSRC"
	;;
esac

if test "X$WITH_TARGET" = Xyes -o "X$WITH_TARGET" = Xno; then
	WITH_TARGET=attached-mic
fi

test "x$prefix" = xNONE && prefix="$ac_default_prefix"
AC_DEFINE_UNQUOTED(ROOTFSDIR,"$prefix/rootfs",[Path of bind-mount source directory])

case $WITH_TARGET in
# POSTK_DEBUG_ARCH_DEP_30, Expansion of the branch.
#    attached-mic|builtin-x86|smp-x86)
#	ARCH=`uname -m`
#	AC_PROG_CC
#	XCC=$CC
#	;;
    attached-mic|builtin-x86|smp-*)
	case $WITH_TARGET in
	    attached-mic|builtin-x86|smp-x86)
		ARCH=`uname -m`
		;;
	    smp-arm64)
		ARCH=arm64
		;;
	esac
	AC_PROG_CC
	XCC=$CC
	CFLAGS="$CFLAGS -ffreestanding -fno-tree-loop-distribute-patterns"
	;;
    builtin-mic)
	ARCH=k1om
	AC_CHECK_PROG(XCC,
		[x86_64-$ARCH-linux-gcc],
		[x86_64-$ARCH-linux-gcc],
		[no])
	CC=$XCC
	;;
    smp-arm64)
	ARCH=arm64
	AC_CHECK_PROG(XCC,
		[${CROSS_COMPILE}gcc],
		[${CROSS_COMPILE}gcc],
		[no])
	CC=$XCC
	;;
    *)
	AC_MSG_ERROR([target $WITH_TARGET is unknwon])
	;;
esac

case $WITH_TARGET in
    attached-mic)
	if test "X$KERNDIR" = X; then
		KERNDIR="$prefix/attached/kernel"
	fi
	if test "X$BINDIR" = X; then
		BINDIR="$prefix/bin"
	fi
	if test "X$SBINDIR" = X; then
		SBINDIR="$prefix/sbin"
	fi
	if test "X$KMODDIR" = X; then
		KMODDIR="$prefix/kmod"
	fi
	if test "X$MANDIR" = X; then
		MANDIR="$prefix/share/man"
	fi
	;;
    builtin-mic)
	if test "X$KERNDIR" = X; then
		KERNDIR="$prefix/attached/kernel"
	fi
	if test "X$BINDIR" = X; then
		BINDIR="$prefix/attached/bin"
	fi
	if test "X$SBINDIR" = X; then
		SBINDIR="$prefix/attached/sbin"
	fi
	if test "X$KMODDIR" = X; then
		KMODDIR="$prefix/attached/kmod"
	fi
	if test "X$MANDIR" = X; then
		MANDIR="$prefix/share/man"
	fi
	;;
    builtin-x86)
	if test "X$KERNDIR" = X; then
		KERNDIR="$prefix/attached/kernel"
	fi
	if test "X$BINDIR" = X; then
		BINDIR="$prefix/bin"
	fi
	if test "X$SBINDIR" = X; then
		SBINDIR="$prefix/sbin"
	fi
	if test "X$KMODDIR" = X; then
		KMODDIR="$prefix/kmod"
	fi
	if test "X$MANDIR" = X; then
		MANDIR="$prefix/share/man"
	fi
	;;
    smp-x86)
	if test "X$KERNDIR" = X; then
		KERNDIR="$prefix/smp-x86/kernel"
	fi
	if test "X$BINDIR" = X; then
		BINDIR="$prefix/bin"
	fi
	if test "X$SBINDIR" = X; then
		SBINDIR="$prefix/sbin"
	fi
	if test "X$MCKERNEL_INCDIR" = X; then
		MCKERNEL_INCDIR="$prefix/include"
	fi
        if test "X$MCKERNEL_LIBDIR" = X; then
                MCKERNEL_LIBDIR="$prefix/lib"
        fi
	if test "X$INCDIR" = X; then
		INCDIR="$prefix/include"
	fi
	if test "X$ETCDIR" = X; then
		ETCDIR="$prefix/etc"
	fi
	if test "X$INCLUDEDIR" = X; then
		INCLUDEDIR="$prefix/include"
	fi
	if test "X$KMODDIR" = X; then
		KMODDIR="$prefix/kmod"
	fi
	if test "X$MANDIR" = X; then
		MANDIR="$prefix/share/man"
	fi
	;;
    smp-arm64)
	if test "X$KERNDIR" = X; then
		KERNDIR="$prefix/smp-arm64/kernel"
	fi
	if test "X$BINDIR" = X; then
		BINDIR="$prefix/bin"
	fi
	if test "X$SBINDIR" = X; then
		SBINDIR="$prefix/sbin"
	fi
	if test "X$MCKERNEL_INCDIR" = X; then
		MCKERNEL_INCDIR="$prefix/include"
	fi
        if test "X$MCKERNEL_LIBDIR" = X; then
                MCKERNEL_LIBDIR="$prefix/lib"
        fi
	if test "X$INCDIR" = X; then
		INCDIR="$prefix/include"
	fi
	if test "X$ETCDIR" = X; then
		ETCDIR="$prefix/etc"
	fi
	if test "X$INCLUDEDIR" = X; then
		INCLUDEDIR="$prefix/include"
	fi
	if test "X$KMODDIR" = X; then
		KMODDIR="$prefix/kmod"
	fi
	if test "X$MANDIR" = X; then
		MANDIR="$prefix/share/man"
	fi
	;;
    *)
	AC_MSG_ERROR([target $WITH_TARGET is unknwon])
	;;
esac

KDIR="$WITH_KERNELSRC"
UNAME_R="$WITH_UNAME_R"
TARGET="$WITH_TARGET"

case $ENABLE_MEMDUMP in
	yes|no|auto)
		;;
	default)
# POSTK_DEBUG_ARCH_DEP_30, Expansion of the branch.
#		if test "x$WITH_TARGET" = "xsmp-x86" ; then
		if test "x$WITH_TARGET" = "xsmp-x86" -o "x$WITH_TARGET" = "xsmp-arm64" ; then
			ENABLE_MEMDUMP=auto
		else
			ENABLE_MEMDUMP=no
		fi
		;;
	*)
		AC_MSG_ERROR([unknown memdump argument: $ENABLE_MEMDUMP])
		;;
esac

if test "x$ENABLE_MEMDUMP" != "xno" ; then
	enableval=yes
# POSTK_DEBUG_ARCH_DEP_32, AC_CHECK_LIB for libiberty
	AC_CHECK_LIB([iberty],[hex_init],[],[enableval=no])
	AC_CHECK_LIB([bfd],[bfd_init],[],[enableval=no])
	AC_CHECK_HEADER([bfd.h],[],[enableval=no])

	if test "x$ENABLE_MEMDUMP" = "xyes" -a "x$enableval" = "xno" ; then
		AC_MSG_ERROR([memdump feature needs bfd.h and libbfd a.k.a bunutils-devel])
	fi
	ENABLE_MEMDUMP=$enableval
fi

if test "x$ENABLE_MEMDUMP" = "xyes" ; then
	AC_MSG_NOTICE([memdump feature is enabled])
	AC_DEFINE([ENABLE_MEMDUMP],[1],[whether memdump feature is enabled])
	uncomment_if_ENABLE_MEMDUMP=''
else
	AC_MSG_NOTICE([memdump feature is disabled])
	uncomment_if_ENABLE_MEMDUMP='#'
fi

if test "x$ENABLE_MCOVERLAYFS" = "xyes" ; then
	AC_DEFINE([ENABLE_MCOVERLAYFS],[1],[whether mcoverlayfs is enabled])
	AC_MSG_NOTICE([mcoverlayfs is enabled])
else
	AC_MSG_NOTICE([mcoverlayfs is disabled])
fi

if test "x$ENABLE_QLMPI" = "xyes" ; then
	AC_DEFINE([ENABLE_QLMPI],[1],[whether qlmpi is enabled])
	AC_MSG_NOTICE([qlmpi is enabled])
else
	AC_MSG_NOTICE([qlmpi is disabled])
fi

case $ENABLE_RUSAGE in
	yes|no)
		;;
	default)
		ENABLE_RUSAGE=yes
		;;
	*)
		AC_MSG_ERROR([unknown rusage argument: $ENABLE_RUSAGE])
		;;
esac

if test "x$ENABLE_RUSAGE" = "xyes" ; then
	AC_MSG_NOTICE([rusage is enabled])
	AC_DEFINE([ENABLE_RUSAGE],[1],[whether rusage is enabled])
else
	AC_MSG_NOTICE([rusage is disabled])
fi

if test "x$ENABLE_PERF" = "xyes" ; then
	AC_DEFINE([ENABLE_PERF],[1],[whether perf is enabled])
	AC_MSG_NOTICE([perf is enabled])
else
	AC_MSG_NOTICE([perf is disabled])
fi

if test "x$WITH_SYSCALL_INTERCEPT" = "xyes" ; then
	AC_DEFINE([WITH_SYSCALL_INTERCEPT],[1],[whether or not syscall_intercept library is linked])
	AC_MSG_NOTICE([syscall_intercept library is linked])
else
	AC_MSG_NOTICE([syscall_intercept library isn't linked])
fi

if test "x$MCKERNEL_INCDIR" != "x" ; then
   AC_DEFINE_UNQUOTED(MCKERNEL_INCDIR,"$MCKERNEL_INCDIR",[McKernel specific headers])
fi

if test "x$MCKERNEL_LIBDIR" != "x" ; then
   AC_DEFINE_UNQUOTED(MCKERNEL_LIBDIR,"$MCKERNEL_LIBDIR",[McKernel specific libraries])
fi

AC_DEFINE_UNQUOTED(BINDIR,"$BINDIR",[Path of install directory for binary])
AC_DEFINE_UNQUOTED(SBINDIR,"$SBINDIR",[Path of install directory for system binary])

AC_DEFINE_UNQUOTED(IHK_VERSION,"$IHK_VERSION",[IHK version string])
AC_DEFINE_UNQUOTED(MCKERNEL_VERSION,"$MCKERNEL_VERSION",[McKernel version string])

ABS_SRCDIR=$( cd $( dirname $0 ); pwd )
IHK_ABS_SRCDIR=${ABS_SRCDIR}/../ihk
BUILDID=$( git --git-dir=$IHK_ABS_SRCDIR/.git rev-parse --short HEAD 2>/dev/null || echo $IHK_VERSION )
AC_MSG_NOTICE([BUILDID=$BUILDID])
if test "x$BUILDID" != "x" ; then
   AC_DEFINE_UNQUOTED(BUILDID,"$BUILDID",[IHK build-id to confirm IHK and McKernel built at the same time are used])
fi
AC_SUBST(BUILDID)

AC_SUBST(CC)
AC_SUBST(XCC)
AC_SUBST(ARCH)
AC_SUBST(KDIR)
AC_SUBST(UNAME_R)
AC_SUBST(TARGET)
AC_SUBST(BINDIR)
AC_SUBST(SBINDIR)
AC_SUBST(MCKERNEL_INCDIR)
AC_SUBST(MCKERNEL_LIBDIR)
AC_SUBST(INCDIR)
AC_SUBST(ETCDIR)
AC_SUBST(INCLUDEDIR)
AC_SUBST(KMODDIR)
AC_SUBST(KERNDIR)
AC_SUBST(MANDIR)
AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS_SYSCALL_INTERCEPT)
AC_SUBST(LDFLAGS_SYSCALL_INTERCEPT)
AC_SUBST(ENABLE_MCOVERLAYFS)
AC_SUBST(ENABLE_RUSAGE)
AC_SUBST(ENABLE_QLMPI)
AC_SUBST(WITH_SYSCALL_INTERCEPT)

AC_SUBST(IHK_VERSION)
AC_SUBST(MCKERNEL_VERSION)
AC_SUBST(DCFA_VERSION)
AC_SUBST(IHK_RELEASE_DATE)
AC_SUBST(MCKERNEL_RELEASE_DATE)
AC_SUBST(DCFA_RESEASE_DATE)
AC_SUBST(uncomment_if_ENABLE_MEMDUMP)

AC_CONFIG_HEADERS([config.h])
# POSTK_DEBUG_ARCH_DEP_37
# AC_CONFIG_FILES arch dependfiles separate
AC_CONFIG_FILES([
	Makefile
	executer/user/Makefile
	executer/user/mcexec.1:executer/user/mcexec.1in
	executer/user/vmcore2mckdump
	executer/user/arch/$ARCH/Makefile
	executer/user/arch/x86_64/Makefile
	executer/kernel/mcctrl/Makefile
	executer/kernel/mcctrl/arch/$ARCH/Makefile
	executer/kernel/mcoverlayfs/Makefile
	executer/kernel/mcoverlayfs/linux-3.10.0-327.36.1.el7/Makefile
	executer/kernel/mcoverlayfs/linux-4.0.9/Makefile
	executer/kernel/mcoverlayfs/linux-4.6.7/Makefile
	executer/kernel/mcoverlayfs/linux-4.18.14/Makefile
	executer/include/qlmpilib.h
	kernel/Makefile
	kernel/Makefile.build
	kernel/include/swapfmt.h
	arch/x86_64/tools/mcreboot-attached-mic.sh
	arch/x86_64/tools/mcshutdown-attached-mic.sh
	arch/x86_64/tools/mcreboot-builtin-x86.sh
	arch/x86_64/tools/mcreboot-smp-x86.sh
	arch/x86_64/tools/mcstop+release-smp-x86.sh
	arch/x86_64/tools/mcoverlay-destroy-smp-x86.sh
	arch/x86_64/tools/mcoverlay-create-smp-x86.sh
	arch/x86_64/tools/eclair-dump-backtrace.exp
	arch/x86_64/tools/mcshutdown-builtin-x86.sh
	arch/x86_64/tools/mcreboot.1:arch/x86_64/tools/mcreboot.1in
	arch/x86_64/tools/irqbalance_mck.service
	arch/x86_64/tools/irqbalance_mck.in
	tools/mcstat/mcstat.1:tools/mcstat/mcstat.1in
	tools/mcstat/Makefile
])

if test -e "${ABS_SRCDIR}/test"; then
AC_CONFIG_FILES([
mck_test_config.sample:test/mck_test_config.sample.in
])
fi

if test "$TARGET" = "smp-x86"; then
AC_CONFIG_FILES([
	arch/x86_64/kernel/Makefile.arch
])
fi

if test "$TARGET" = "smp-arm64"; then
AC_CONFIG_FILES([
	kernel/config/config.smp-arm64
	arch/arm64/kernel/vdso/Makefile
	arch/arm64/kernel/Makefile.arch
])
fi

AS_IF([test "x$enable_dcfa" = xyes], [
        AC_CONFIG_FILES([kernel/Makefile.dcfa])])
    
AC_OUTPUT
