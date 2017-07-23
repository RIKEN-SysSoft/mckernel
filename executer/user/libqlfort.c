#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

static int *mck_ql_argc;
static char ***mck_ql_argv;
static int (*intel_iargc)();
static int (*intel_getarg)(int *, char *, int, int);
static int (*gfortran_iargc)();
static int (*gfortran_getarg)(int *, char *, int);
static void (*mpi_init)(int *);
static int dl_init_flag;

static inline void
init()
{
	if (dl_init_flag)
		return;

	mck_ql_argc = dlsym(RTLD_NEXT, "mck_ql_argc");
	mck_ql_argv = dlsym(RTLD_NEXT, "mck_ql_argv");
	intel_iargc = dlsym(RTLD_NEXT, "for_iargc");
	intel_getarg = dlsym(RTLD_NEXT, "for_getarg");
	gfortran_iargc = dlsym(RTLD_NEXT, "_gfortran_iargc");
	gfortran_getarg = dlsym(RTLD_NEXT, "_gfortran_getarg_i4");
	mpi_init = dlsym(RTLD_NEXT, "mpi_init_");
	dl_init_flag = 1;
}

// for GNU Fortran
int
_gfortran_iargc()
{
	init();

	if (mck_ql_argc && mck_ql_argv && *mck_ql_argv)
		return *mck_ql_argc - 1;
	if (gfortran_iargc)
		return gfortran_iargc();
	return 0;
}

void
_gfortran_getarg_i4(int *n, char *arg, int arg_len)
{
	int l;

	init();
	if (mck_ql_argc && mck_ql_argv && *mck_ql_argv) {
		memset(arg, ' ', arg_len);
		if (*n < 0 || *n > *mck_ql_argc)
			return;
		l = strlen((*mck_ql_argv)[*n]);
		if (l > arg_len)
			l = arg_len;
		strncpy(arg, (*mck_ql_argv)[*n], l);
		return;
	}
	if (gfortran_getarg) {
		gfortran_getarg(n, arg, arg_len);
		return;
	}
	return;
}

// for Intel Fortran
int
for_iargc()
{
	init();
	if (mck_ql_argc && mck_ql_argv && *mck_ql_argv)
		return *mck_ql_argc - 1;
	if (intel_iargc)
		return intel_iargc();
	return 0;
}

void
for_getarg(int *n, char *arg, int dmy1, int arg_len)
{
	int l;

	init();
	if (mck_ql_argc && mck_ql_argv && *mck_ql_argv) {
		memset(arg, ' ', arg_len);
		if (*n < 0 || *n > *mck_ql_argc)
			return;
		l = strlen((*mck_ql_argv)[*n]);
		if (l > arg_len)
			l = arg_len;
		strncpy(arg, (*mck_ql_argv)[*n], l);
		return;
	}
	if (intel_getarg) {
		intel_getarg(n, arg, dmy1, arg_len);
		return;
	}
	return;
}
