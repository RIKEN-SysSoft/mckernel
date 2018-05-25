#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/futex.h>

#define NLOOP 10
#define TS2NS(sec, nsec) ((unsigned long)(sec) * 1000000000ULL + (unsigned long)(nsec))
#define SZCHUNK 4096
#define IHK_DEVICE_CREATE_OS          0x112900
#define IHK_DEVICE_DESTROY_OS         0x112901

pthread_mutex_t mutex;
pthread_cond_t cond;
int sem;
int futex_flag;
pthread_t thr;

int syscall_numbers[] = {
	__NR_gettid,
	__NR_futex,
	__NR_brk,
	__NR_mmap,
	__NR_munmap,
	__NR_mprotect,
	__NR_mremap,
	__NR_getuid,
	__NR_open,
	__NR_ioctl,
	__NR_read,
	__NR_write
};

char *syscall_names[] = {
	"gettid",
	"futex",
	"brk",
	"mmap",
	"munmap",
	"mprotect",
	"mremap",
	"getuid",
	"open",
	"ioctl",
	"read",
	"write"
};

void *util_thread(void *arg) {
	int i, j;
	int rc;
	uid_t uid;
	int osnum;
	int fds[NLOOP];
	void *mems[NLOOP];
	void *memremaps[NLOOP];
	void *brk_cur;
	char* buf = malloc(SZCHUNK*NLOOP);
	struct timespec start, end;
	long nsec;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stdout, "CT11001 running on Liux OK\n");
	else {
		fprintf(stdout, "CT11001 running on Linux NG (%d)\n", rc);
	}
	errno = 0;

	for (i = 0; i < sizeof(syscall_numbers) / sizeof(int); i++) { 
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);

		switch (syscall_numbers[i]) {
		case __NR_brk:
			brk_cur = sbrk(0);
			break;
		case __NR_mprotect:
			if((mems[0] = mmap(0, SZCHUNK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == (void*)-1) {
				fprintf(stderr, "mmap failed: %s\n", strerror(errno));
			}
		case __NR_munmap:
		case __NR_mremap:
			for (j = 0; j < NLOOP; j++) {
				if((mems[j] = mmap(0, SZCHUNK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == (void*)-1) {
					fprintf(stderr, "mmap failed: %s\n", strerror(errno));
				}
			}
			break;
		case __NR_ioctl:
			if((fds[0] = open("/dev/hello", O_RDWR)) < 0) {
				fprintf(stderr, "ioctl, open failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		case __NR_read:
		case __NR_write:
			if((fds[0] = open("./file", O_RDWR)) < 0) {
				fprintf(stderr, "write, open failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		default:
			break;
		}

		for (j = 0; j < NLOOP; j++) {
			switch (syscall_numbers[i]) {
			case __NR_gettid:
				if((rc = syscall(syscall_numbers[i])) < 0) {
					fprintf(stderr, "%s failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_futex: 
				futex_flag = 1;
				if((rc = syscall(__NR_futex, &futex_flag, FUTEX_WAKE, 1, NULL, NULL, 0)) < 0) {
					fprintf(stderr, "%s failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_brk:
				if((rc = brk(brk_cur)) < 0) {
					fprintf(stderr, "%s failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_mmap:
				if((mems[j] = mmap(0, SZCHUNK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == (void*)-1) {
					fprintf(stderr, "%s failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_munmap:
				if((rc = munmap(mems[j], SZCHUNK)) < 0) {
					fprintf(stderr, "%s failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_mprotect:
				if((rc = mprotect(mems[0], SZCHUNK, PROT_READ)) < 0) {
					fprintf(stderr, "%s failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_mremap:
				if((memremaps[j] = mremap(mems[j], SZCHUNK, 8192, MREMAP_MAYMOVE)) == (void*)-1) {
					fprintf(stderr, "%s failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_getuid:
				if((uid = getuid()) < 0) {
					fprintf(stderr, "%s failed: uid=%d,%s\n", syscall_names[i], uid, strerror(errno));
				}
				break;
			case __NR_open:
				if((fds[j] = open("./file", O_RDONLY)) < 0) {
					fprintf(stderr, "%s ./file failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_ioctl:
				if((rc = ioctl(fds[0], 0, 0)) < 0) {
					fprintf(stderr, "%s failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_read:
				if((rc = read(fds[0], buf + j * SZCHUNK, SZCHUNK)) < 0) {
					fprintf(stderr, "%s failed: %s\n", syscall_names[i], strerror(errno));
				}
				break;
			case __NR_write:
				if((rc = write(fds[0], buf + j * SZCHUNK, SZCHUNK)) < 0) {
					fprintf(stderr, "%s failed: rc=%d,%s\n", syscall_names[i], rc, strerror(errno));
				}
				break;
			}
		}
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
		nsec = (TS2NS(end.tv_sec, end.tv_nsec) - TS2NS(start.tv_sec, start.tv_nsec));
		fprintf(stderr, "%s %ld nsec\n", syscall_names[i], nsec / NLOOP);

		switch (syscall_numbers[i]) {
		case __NR_mmap:
			for (j = 0; j < NLOOP; j++) {
				if((rc = munmap(mems[j], SZCHUNK)) < 0) {
					fprintf(stderr, "munmap failed: %s\n", strerror(errno));
				}
			}
			break;
		case __NR_mprotect:
			if((rc = munmap(mems[0], SZCHUNK)) < 0) {
				fprintf(stderr, "munmap failed: %s\n", strerror(errno));
			}
			break;
		case __NR_mremap:
			for (j = 0; j < NLOOP; j++) {
				if((rc = munmap(memremaps[j], SZCHUNK)) < 0) {
					fprintf(stderr, "munmap failed: %s\n", strerror(errno));
				}
			}
			break;
		case __NR_open:
			for (j = 0; j < NLOOP; j++) {
				if((rc = close(fds[j])) < 0) {
					fprintf(stderr, "close failed: %s\n", strerror(errno));
				}
			}
			break;
		case __NR_ioctl:
		case __NR_read:
		case __NR_write:
			if((rc = close(fds[0])) < 0) {
				fprintf(stderr, "close failed: %s\n", strerror(errno));
			}
			break;
		default:
			break;
		}
	}

	pthread_mutex_lock(&mutex);
	while(!sem) {
		pthread_cond_wait(&cond, &mutex);
	}
	sem = 0;
	pthread_mutex_unlock(&mutex);

	return NULL;
}

int
main(int argc, char **argv)
{
	int rc;
	char *uti_str;
	int uti_val;

	fprintf(stdout, "CT11001 syscall START\n");
	uti_str = getenv("DISABLE_UTI");
	uti_val = uti_str ? atoi(uti_str) : 0;
	if (!uti_val) {
		rc = syscall(731, 1, NULL);
		if (rc) {
			fprintf(stdout, "CT11002 INFO: uti not available (rc=%d)\n", rc);
		} else {
			fprintf(stdout, "CT11002 INFO: uti available\n");
		}
	} else {
		fprintf(stdout, "CT11002 INFO: uti disabled\n", rc);
	}

	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if(rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stdout, "CT11003 pthread_create OK\n");

	while (!futex_flag) {
		rc = syscall(__NR_futex, &futex_flag, FUTEX_WAIT, 0, NULL, NULL, 0);
		if (rc == -1) {
			fprintf(stderr, "CT11101 FUTEX_WAIT ERROR: %s\n", strerror(errno));
		}
	}

	pthread_mutex_lock(&mutex);
	sem = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
	pthread_join(thr, NULL);

	fprintf(stdout, "CT10005 END\n");
	exit(0);
}
