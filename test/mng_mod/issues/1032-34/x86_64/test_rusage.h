#ifndef __TEST_RUSAGE_H__
#define __TEST_RUSAGE_H__

#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>

#define ONE_SEC 1000000
#define M_BYTE 1024 * 1024

#define cpu_pause()                     \
	({                          \
		__asm__ __volatile__("pause" ::: "memory"); \
	})

int sig_count;

long get_rusage_utime(struct rusage *usage)
{
	if (!usage) {
		return -1;
	}

	return (usage->ru_utime.tv_sec * ONE_SEC) + usage->ru_utime.tv_usec;
}

long get_rusage_stime(struct rusage *usage)
{
	if (!usage) {
		return -1;
	}

	return (usage->ru_stime.tv_sec * ONE_SEC) + usage->ru_stime.tv_usec;
}

long get_rusage_maxrss(struct rusage *usage)
{
	if (!usage) {
		return -1;
	}

	return usage->ru_maxrss;
}

void alrm_handler(int sig)
{
	sig_count = 1;
}

void add_utime(int sec)
{
	int rc;
	struct sigaction sa;

	/* flag clear */
	sig_count = 0;
	
	/* set sighandler */
	sa.sa_handler = alrm_handler;
	rc = sigaction(SIGALRM, &sa, NULL);

	alarm(sec);

	while (!sig_count) {
		cpu_pause();
	}
}

void add_stime(int sec)
{
	int fd;

	fd = open("/dev/test_rusage", O_RDWR);
	ioctl(fd, sec, NULL);
	close(fd);
}

#endif /*__TEST_RUSAGE_H__*/
