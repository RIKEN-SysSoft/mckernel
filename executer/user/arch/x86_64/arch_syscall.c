#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <elf.h>
#include <dirent.h>
#include "../../../include/uprotocol.h"
#include "../../archdep.h"

//#define DEBUG
#ifndef DEBUG
#define __dprint(msg, ...)
#define __dprintf(arg, ...)
#define __eprint(msg, ...)
#define __eprintf(format, ...)
#else
#define __dprint(msg, ...)  {printf("%s: " msg, __FUNCTION__);fflush(stdout);}
#define __dprintf(format, ...)  {printf("%s: " format, __FUNCTION__, \
					__VA_ARGS__);fflush(stdout);}
#define __eprint(msg, ...)  {fprintf(stderr, "%s: " msg, __FUNCTION__);\
					fflush(stderr);}
#define __eprintf(format, ...)  {fprintf(stderr, "%s: " format, __FUNCTION__, \
					__VA_ARGS__);fflush(stderr);}
#endif

extern char *chgpath(char *, char *);
extern long do_strncpy_from_user(int, void *, void *, unsigned long);
extern int fd;

#define SET_ERR(ret) if (ret == -1) ret = -errno

int
archdep_syscall(struct syscall_wait_desc *w, long *ret)
{
	char *fn;
	char pathbuf[PATH_MAX];
	char tmpbuf[PATH_MAX];

	switch (w->sr.number) {
		case __NR_open:
			*ret = do_strncpy_from_user(fd, pathbuf,
			                       (void *)w->sr.args[0], PATH_MAX);
			if (*ret >= PATH_MAX) {
				*ret = -ENAMETOOLONG;
			}
			if (*ret < 0) {
				return 0;
			}
			__dprintf("open: %s\n", pathbuf);

			fn = chgpath(pathbuf, tmpbuf);

			*ret = open(fn, w->sr.args[1], w->sr.args[2]);
			SET_ERR(*ret);
			return 0;
	}
	return -1;
}
