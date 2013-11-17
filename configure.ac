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

AC_ARG_WITH([kernelsrc],
  AC_HELP_STRING(
    [--with-kernelsrc=path],[Path to 'kernel src', default is /lib/modules/uname_r/build]),
  [WITH_KERNELSRC=$withval],[WITH_KERNELSRC=yes])

AC_ARG_WITH([target],
  AC_HELP_STRING(
    [--with-target={attached-mic | builtin-mic | builtin-x86}],[target, default is attached-mic]),
  [WITH_TARGET=$withval],[WITH_TARGET=yes])

AC_ARG_ENABLE([dcfa],
  [AS_HELP_STRING(
  	[--enable-dcfa],[Enable DCFA modules])],[],[enable_dcfa=no])

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

case $WITH_TARGET in
    attached-mic)
	ARCH=`uname -m`
	AC_PROG_CC
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
	;;
    builtin-mic)
	ARCH=k1om
	AC_CHECK_PROG(XCC,
		[x86_64-$ARCH-linux-gcc],
		[x86_64-$ARCH-linux-gcc],
		[no])
	CC=$XCC
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
	;;
    builtin-x86)
	ARCH=`uname -m`
	AC_PROG_CC
	XCC=$CC
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
	;;
    *)
	AC_MSG_ERROR([target $WITH_TARGET is unknwon])
	;;
esac

KDIR="$WITH_KERNELSRC"
TARGET="$WITH_TARGET"

AC_SUBST(CC)
AC_SUBST(XCC)
AC_SUBST(ARCH)
AC_SUBST(KDIR)
AC_SUBST(TARGET)
AC_SUBST(BINDIR)
AC_SUBST(SBINDIR)
AC_SUBST(KMODDIR)
AC_SUBST(KERNDIR)

AC_SUBST(IHK_VERSION)
AC_SUBST(MCKERNEL_VERSION)
AC_SUBST(DCFA_VERSION)
AC_SUBST(IHK_RELEASE_DATE)
AC_SUBST(MCKERNEL_RELEASE_DATE)
AC_SUBST(DCFA_RESEASE_DATE)

AC_CONFIG_FILES([
	Makefile
	executer/user/Makefile
	executer/kernel/Makefile
	kernel/Makefile
	arch/x86/tools/mcreboot-attached-mic.sh
	mcreboot.1:mcreboot.1in
])

AS_IF([test "x$enable_dcfa" = xyes], [
        AC_CONFIG_FILES([kernel/Makefile.dcfa])])
    
AC_OUTPUT
