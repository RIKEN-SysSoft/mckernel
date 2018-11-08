#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>

#define SMALL_PAGE_SIZE 4096L
#define PAGE_MASK (~(SMALL_PAGE_SIZE - 1))
#define GET_PAGE_INFO 750

int
is_small_page(long pageinfo)
{
	return (pageinfo & PAGE_MASK) == SMALL_PAGE_SIZE;
}

int
is_shared(long pageinfo)
{
	return pageinfo & 1;
}

void
print_test(char *id, char *msg, void *p, int valid_small, int valid_shared)
{
	long pageinfo = syscall(GET_PAGE_INFO, p);
	int ng = 0;
	int small_page = is_small_page(pageinfo);
	int shared = is_shared(pageinfo);
	char buf[80];

	if (pageinfo == -1 && errno == ENOSYS) {
		fprintf(stderr, "get_page_info: unsupported\n");
		exit(1);
	}

	sprintf(buf, "%s %s addr=%p %s %s ", id, msg, p,
		small_page ? "SMALL" : "LARGE", shared ? "SHARED" : "PRIVATE");
	
	if (valid_small != -1 &&
	    small_page != valid_small) {
		ng = 1;
	}
	if (shared != valid_shared) {
		ng = 1;
	}
	printf("%s %s\n", buf, ng ? "NG" : "OK");
}

int
main(int argc, char **argv)
{
	void *p;
	char x[10];
	key_t key;
	int shmid;
	struct shmid_ds buf;

	p = x;
	memset(p, '\0', 10);
	print_test("C765T01", "stack", p, -1, 0);

	p = malloc(10);
	memset(p, '\0', 10);
	print_test("C765T02", "heap", p, -1, 0);

	p = mmap(NULL, 8 * 1024, PROT_READ | PROT_WRITE,
	         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(p, '\0', 8 * 1024);
	print_test("C765T03", "private(8k)", p, 1, 0);
	munmap(p, 8 * 1024);

	p = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
	         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memset(p, '\0', 2 * 1024 * 1024);
	print_test("C765T04", "private(2M)", p, 0, 0);
	munmap(p, 2 * 1024 * 1024);

	p = mmap(NULL, 8 * 1024, PROT_READ | PROT_WRITE,
	         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memset(p, '\0', 8 * 1024);
	print_test("C765T05", "shared(8k)", p, 1, 1);
	munmap(p, 8 * 1024);

	p = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
	         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	memset(p, '\0', 2 * 1024 * 1024);
	print_test("C765T06", "shared(2M)", p, 1, 1);
	munmap(p, 2 * 1024 * 1024);

	key = ftok(argv[0], 1);
	shmid = shmget(key, 8 * 1024, IPC_CREAT | 0660);
	p = shmat(shmid, NULL, 0);
	memset(p, '\0', 8 * 1024);
	print_test("C765T07", "shm(8k)", p, 1, 1);
	shmctl(shmid, IPC_RMID, &buf);
	shmdt(p);

	key = ftok(argv[0], 2);
	shmid = shmget(key, 2 * 1024 * 1024, IPC_CREAT | 0660);
	p = shmat(shmid, NULL, 0);
	memset(p, '\0', 2 * 1024 * 1024);
	print_test("C765T08", "shm(2M)", p, 1, 1);
	shmctl(shmid, IPC_RMID, &buf);
	shmdt(p);

	exit(0);
}
