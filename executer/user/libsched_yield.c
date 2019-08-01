#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/time.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>

#undef sched_yield

typedef int (*int_void_fn)(void);

static int_void_fn orig_sched_yield = 0;

int sched_yield(void)
{
#if 0
	if (!orig_sched_yield) {
		orig_sched_yield = (int_void_fn)dlsym(RTLD_NEXT, "sched_yield");
	}

	printf("sched_yield() called\n");
#endif

	return 0;
}



#undef pthread_create

typedef int (*__pthread_create_fn)(pthread_t *thread,
		const pthread_attr_t *attr,
		void *(*start_routine) (void *),
		void *arg);

static __pthread_create_fn orig_pthread_create = 0;


#define PROCMAPS_MAX_LEN	8192

char *addr_to_lib(void *addr)
{
	char maps_path[PATH_MAX];
	char buf[PROCMAPS_MAX_LEN];
	int fd;
	void *start, *end;
	char perms[4];
	unsigned long offset;
	unsigned long dev[2];
	int inode;
	char path[PATH_MAX];
	char *line;

	sprintf(maps_path,"/proc/self/maps");
	fd = open(maps_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr,"error: cannot open the memory maps, %s\n",
				strerror(errno));
		return NULL;
	}

	memset(buf, 0, PROCMAPS_MAX_LEN);
	read(fd, buf, PROCMAPS_MAX_LEN);
	line = strtok(buf, "\n");
	while (line) {
		memset(path, 0, sizeof(path));
		sscanf(line, "%012lx-%012lx %4s %lx %lx:%lx %d\t\t\t%[^\n]",
			&start, &end, perms, &offset, &dev[0], &dev[1], &inode, path);

		if (start <= addr && end > addr) {
			close(fd);
			return strlen(path) > 0 ? strdup(path) : NULL;
		}

		line = strtok(NULL, "\n");
	}

	close(fd);
	return NULL;
}

int pthread_create(pthread_t *thread,
		const pthread_attr_t *attr,
		void *(*start_routine) (void *),
		void *arg)
{
	char *lib = NULL;
	int util_thread = 1;

	if (!orig_pthread_create) {
		orig_pthread_create =
			(__pthread_create_fn)dlsym(RTLD_NEXT, "pthread_create");
	}

	lib = addr_to_lib(start_routine);
	if (lib && (strstr(lib, "iomp") || strstr(lib, "psm"))) {
		util_thread = 0;
	}

	if (util_thread) {
		//printf("%s: 0x%lx is util thread in %s\n",
		//	__func__, start_routine, lib);
		/* McKernel util_indicate_clone() */
		syscall(731);
	}

	if (lib)
		free(lib);

	return orig_pthread_create(thread, attr, start_routine, arg);
}
