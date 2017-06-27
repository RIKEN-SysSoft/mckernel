AC_PREREQ(2.63)
m4_define([IHK_VERSION_m4],[0.9.0])dnl
m4_define([MCKERNEL_VERSION_m4],[0.9.0])dnl
m4_define([DCFA_VERSION_m4],[0.9.0])dnl
m4_define([IHK_RELEASE_DATE_m4],[2013-11-18])dnl
m4_define([MCKERNEL_RELEASE_DATE_m4],[2013-11-18])dnl
m4_define([DCFA_RELEASE_DATE_m4],[2013-11-18])dnl

AC_INIT([mckernel], MCKERNEL_VERSION_m4)

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
	WITH_KERNELSRC='/lib/modules/`uname -r`/build'
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
    attached-mic|builtin-x86|smp-x86)
	ARCH=`uname -m`
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
		MANDIR="$prefix/man"
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
		MANDIR="$prefix/attached/man"
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
		MANDIR="$prefix/attached/man"
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
        if test "X$MCKERNEL_LIBDIR" = X; then
                MCKERNEL_LIBDIR="$prefix/lib"
        fi
	if test "X$ETCDIR" = X; then
		ETCDIR="$prefix/etc"
	fi
	if test "X$KMODDIR" = X; then
		KMODDIR="$prefix/kmod"
	fi
	if test "X$MANDIR" = X; then
		MANDIR="$prefix/smp-x86/man"
	fi
	;;
    *)
	AC_MSG_ERROR([target $WITH_TARGET is unknwon])
	;;
esac

KDIR="$WITH_KERNELSRC"
UNAME_R="$WITH_UNAME_R"
TARGET="$WITH_TARGET"

MCCTRL_LINUX_SYMTAB=""
case "X$WITH_SYSTEM_MAP" in
    Xyes | Xno | X)
	MCCTRL_LINUX_SYMTAB=""
	;;
    *)
	MCCTRL_LINUX_SYMTAB="$WITH_SYSTEM_MAP"
	;;
esac

AC_MSG_CHECKING([[for System.map]])
if test -f "$MCCTRL_LINUX_SYMTAB"; then
	MCCTRL_LINUX_SYMTAB="$MCCTRL_LINUX_SYMTAB"
elif test -f "/boot/System.map-`uname -r`"; then
	MCCTRL_LINUX_SYMTAB="/boot/System.map-`uname -r`"
elif test -f "$KDIR/System.map"; then
	MCCTRL_LINUX_SYMTAB="$KDIR/System.map"
fi

if test "$MCCTRL_LINUX_SYMTAB" == ""; then
	AC_MSG_ERROR([could not find])
fi

if test -z "`eval cat $MCCTRL_LINUX_SYMTAB`"; then
	AC_MSG_ERROR([could not read System.map file, no read permission?])
fi
AC_MSG_RESULT([$MCCTRL_LINUX_SYMTAB])

MCCTRL_LINUX_SYMTAB_CMD="cat $MCCTRL_LINUX_SYMTAB"

# MCCTRL_FIND_KSYM(SYMBOL)
# ------------------------------------------------------
# Search System.map for address of the given symbol and
# do one of three things in config.h:
# If not found, leave MCCTRL_KSYM_foo undefined
# If found to be exported, "#define MCCTRL_KSYM_foo 0"
# If found not to be exported, "#define MCCTRL_KSYM_foo 0x<value>"
AC_DEFUN([MCCTRL_FIND_KSYM],[
  AC_MSG_CHECKING([[System.map for symbol $1]])
  mcctrl_addr=`eval $MCCTRL_LINUX_SYMTAB_CMD | grep " $1\$" | cut -d\  -f1`
  if test -z $mcctrl_addr; then
    AC_MSG_RESULT([not found])
  else
    mcctrl_result=$mcctrl_addr
    mcctrl_addr="0x$mcctrl_addr"
    m4_ifval([$2],[],[
      if `eval $MCCTRL_LINUX_SYMTAB_CMD | grep " __ksymtab_$1\$" >/dev/null`; then
        mcctrl_result="exported"
        mcctrl_addr="0"
      fi
    ])
    AC_MSG_RESULT([$mcctrl_result])
    AC_DEFINE_UNQUOTED(MCCTRL_KSYM_[]$1,$mcctrl_addr,[Define to address of kernel symbol $1, or 0 if exported])
  fi
])

MCCTRL_FIND_KSYM([sys_mount])
MCCTRL_FIND_KSYM([sys_umount])
MCCTRL_FIND_KSYM([sys_unshare])
MCCTRL_FIND_KSYM([zap_page_range])
MCCTRL_FIND_KSYM([vdso_image_64])
MCCTRL_FIND_KSYM([vdso_start])
MCCTRL_FIND_KSYM([vdso_end])
MCCTRL_FIND_KSYM([vdso_pages])
MCCTRL_FIND_KSYM([__vvar_page])
MCCTRL_FIND_KSYM([hpet_address])
MCCTRL_FIND_KSYM([hv_clock])
MCCTRL_FIND_KSYM([sys_readlink])

case $ENABLE_MEMDUMP in
	yes|no|auto)
		;;
	default)
		if test "x$WITH_TARGET" = "xsmp-x86" ; then
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

if test "x$MCKERNEL_LIBDIR" != "x" ; then
   AC_DEFINE_UNQUOTED(MCKERNEL_LIBDIR,"$MCKERNEL_LIBDIR",[McKernel specific libraries])
fi

AC_SUBST(CC)
AC_SUBST(XCC)
AC_SUBST(ARCH)
AC_SUBST(KDIR)
AC_SUBST(UNAME_R)
AC_SUBST(TARGET)
AC_SUBST(BINDIR)
AC_SUBST(SBINDIR)
AC_SUBST(MCKERNEL_LIBDIR)
AC_SUBST(ETCDIR)
AC_SUBST(KMODDIR)
AC_SUBST(KERNDIR)
AC_SUBST(MANDIR)
AC_SUBST(CFLAGS)
AC_SUBST(ENABLE_MCOVERLAYFS)
AC_SUBST(ENABLE_RUSAGE)

AC_SUBST(IHK_VERSION)
AC_SUBST(MCKERNEL_VERSION)
AC_SUBST(DCFA_VERSION)
AC_SUBST(IHK_RELEASE_DATE)
AC_SUBST(MCKERNEL_RELEASE_DATE)
AC_SUBST(DCFA_RESEASE_DATE)
AC_SUBST(uncomment_if_ENABLE_MEMDUMP)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	executer/user/Makefile
	executer/user/arch/x86_64/Makefile
	executer/kernel/mcctrl/Makefile
	executer/kernel/mcctrl/arch/x86_64/Makefile
	executer/kernel/mcoverlayfs/Makefile
	executer/kernel/mcoverlayfs/linux-3.10.0-327.36.1.el7/Makefile
	executer/kernel/mcoverlayfs/linux-4.0.9/Makefile
	executer/kernel/mcoverlayfs/linux-4.6.7/Makefile
	kernel/Makefile
	kernel/Makefile.build
	arch/x86/tools/mcreboot-attached-mic.sh
	arch/x86/tools/mcshutdown-attached-mic.sh
	arch/x86/tools/mcreboot-builtin-x86.sh
	arch/x86/tools/mcreboot-smp-x86.sh
	arch/x86/tools/mcstop+release-smp-x86.sh
	arch/x86/tools/eclair-dump-backtrace.exp
	arch/x86/tools/mcshutdown-builtin-x86.sh
	arch/x86/tools/mcreboot.1:arch/x86/tools/mcreboot.1in
	arch/x86/tools/irqbalance_mck.service
	arch/x86/tools/irqbalance_mck.in
])

AS_IF([test "x$enable_dcfa" = xyes], [
        AC_CONFIG_FILES([kernel/Makefile.dcfa])])
    
AC_OUTPUT
