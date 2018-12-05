/* proc_maps.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define BUF_SIZE 4096
#define EXP_STR_SIZE 64

int main(int argc, char *argv[])
{
	FILE *fp = NULL;
	const char pfname[] = "/proc/self/maps";
	int result = 0;
	int i = 0;
	int offset_ng = 0;
	int dev_ng = 0;
	int inode_ng = 0;
	int vdso_ok = 0;
	int vsyscall_ok = 0;
	int stack_ok = 0;
	int heap_ok = 0;
	int pathempty_ok = 0;
	const unsigned int page_size = sysconf(_SC_PAGESIZE);
	char buf[BUF_SIZE];

	struct {
		int okng;
		int prot;
		int flags;
		void *addr;
		char exp[EXP_STR_SIZE];
	} mapconf[] = {
		{ -1, PROT_NONE, MAP_PRIVATE },
		{ -1, PROT_NONE, MAP_SHARED },
		{ -1, PROT_READ, MAP_PRIVATE },
		{ -1, PROT_READ, MAP_SHARED },
		{ -1, PROT_WRITE, MAP_PRIVATE },
		{ -1, PROT_WRITE, MAP_SHARED },
		{ -1, PROT_EXEC, MAP_PRIVATE },
		{ -1, PROT_EXEC, MAP_SHARED },
		{ -1, PROT_READ | PROT_WRITE, MAP_PRIVATE },
		{ -1, PROT_READ | PROT_WRITE, MAP_SHARED },
		{ -1, PROT_READ | PROT_EXEC, MAP_PRIVATE },
		{ -1, PROT_READ | PROT_EXEC, MAP_SHARED },
		{ -1, PROT_WRITE | PROT_EXEC, MAP_PRIVATE },
		{ -1, PROT_WRITE | PROT_EXEC, MAP_SHARED },
		{ -1, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE },
		{ -1, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED },
	};

	/* fopen */
	if ((fp = fopen(pfname, "r")) == NULL) {
		printf("fopen() failed. %d\n", errno);
		result = -1;
		goto fast_err;
	}

	/* mapping */
	for (i = 0; i < sizeof(mapconf) / sizeof(mapconf[0]); i++) {
		mapconf[i].addr = mmap(NULL, page_size, mapconf[i].prot,
			mapconf[i].flags | MAP_ANONYMOUS, -1, 0);
		if (mapconf[i].addr == NULL) {
			printf("mmap(prot=%d, flags=%d) failed. %d\n",
				mapconf[i].prot, mapconf[i].flags, errno);
			result = -1;
			goto err;
		}
		snprintf(mapconf[i].exp, sizeof(mapconf[i].exp),
			"%lx-%lx %s%s%s%s", mapconf[i].addr, mapconf[i].addr + page_size,
			mapconf[i].prot & PROT_READ ? "r" : "-",
			mapconf[i].prot & PROT_WRITE ? "w" : "-",
			mapconf[i].prot & PROT_EXEC ? "x" : "-",
			mapconf[i].flags & MAP_PRIVATE ? "p" : "s");
	}

	/* print-procfs */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		unsigned long start;
		unsigned long end;
		char prot[8];
		unsigned long offset = 1;
		unsigned long dev1 = 1;
		unsigned long dev2 = 1;
		unsigned long inode = 1;
		char pathname[BUF_SIZE] = "\0";

		sscanf(buf, "%lx-%lx %s %lx %lx:%lx %lx\t\t\t%s",
			&start, &end, prot, &offset, &dev1, &dev2, &inode, pathname);

		if (offset != 0) {
			offset_ng = 1;
		}

		if (dev1 != 0 || dev2 != 0) {
			dev_ng = 1;
		}

		if (inode != 0) {
			inode_ng = 1;
		}

		if (strlen(pathname) != 0) {
			if (vdso_ok != 1) {
				if (!strcmp("[vdso]", pathname)) {
					vdso_ok = 1;
				}
			}

			if (vsyscall_ok != 1) {
				if (!strcmp("[vsyscall]", pathname)) {
					vsyscall_ok = 1;
				}
			}

			if (stack_ok != 1) {
				if (!strcmp("[stack]", pathname)) {
					unsigned long stack_addr = (unsigned long)pathname;
					stack_addr--;

					if ((start <= stack_addr) &&
					    (stack_addr < end)) {
						stack_ok = 1;
					} else {
						stack_ok = -1;
					}
				}
			}

			if (heap_ok != 1) {
				if (!strcmp("[heap]", pathname)) {
					unsigned long heap_addr = (unsigned long)sbrk(0);
					heap_addr--;

					if ((start <= heap_addr) &&
					    (heap_addr < end)) {
						heap_ok = 1;
					} else {
						heap_ok = -1;
					}
				}
			}
		} else if (pathempty_ok != 1) {
			pathempty_ok = 1;
		}

		for (i = 0; i < sizeof(mapconf) / sizeof(mapconf[0]); i++) {
			if (mapconf[i].okng == -1) {
				if (strstr(buf, mapconf[i].exp)) {
					mapconf[i].okng = 0;
					break;
				}
			}
		}
	}

	/* unmapping */
	for (i = 0; i < sizeof(mapconf) / sizeof(mapconf[0]); i++) {
		munmap(mapconf[i].addr, page_size);
	}

	/* ok/ng check */
	/* addr, prot and flags */
	for (i = 0; i < sizeof(mapconf) / sizeof(mapconf[0]); i++) {
		if (mapconf[i].okng == -1) {
			printf("TEST%03d: NG, %s not found.\n", i + 1, mapconf[i].exp);
			result = -1;
		} else {
			printf("TEST%03d: OK\n", i + 1);
		}
	}

	/* offset */
	if (offset_ng == 1) {
		printf("TEST%03d: NG, offset field is not 0.\n", ++i);
		result = -1;
	} else {
		printf("TEST%03d: OK\n", ++i);
	}

	/* dev */
	if (dev_ng == 1) {
		printf("TEST%03d: NG, dev field is not 0.\n", ++i);
		result = -1;
	} else {
		printf("TEST%03d: OK\n", ++i);
	}

	/* inode */
	if (inode_ng == 1) {
		printf("TEST%03d: NG, inode field is not 0.\n", ++i);
		result = -1;
	} else {
		printf("TEST%03d: OK\n", ++i);
	}

	/* pathname */
	/* [vsdo] */
	if (vdso_ok == 1) {
		printf("TEST%03d: OK\n", ++i);
	} else {
		printf("TEST%03d: NG, [vdso] pathname not found.\n", ++i);
		result = -1;
	}

	/* [vsyscall] */
	if (vsyscall_ok == 1) {
		printf("TEST%03d: OK\n", ++i);
	} else {
		printf("TEST%03d: NG, [vsyscall] pathname not found.\n", ++i);
		result = -1;
	}

	/* [stack] */
	if (stack_ok == 0) {
		printf("TEST%03d: NG, [stack] pathname not found.\n", ++i);
		result = -1;
	} else if (stack_ok == -1) {
		printf("TEST%03d: NG, [stack] pathname found, but addr is not expected.\n", ++i);
		result = -1;
	} else {
		printf("TEST%03d: OK\n", ++i);
	}

	/* [heap] */
	if (heap_ok == 0) {
		printf("TEST%03d: NG, [heap] pathname not found.\n", ++i);
		result = -1;
	} else if (heap_ok == -1) {
		printf("TEST%03d: NG, [heap] pathname found, but addr is not expected.\n", ++i);
		result = -1;
	} else {
		printf("TEST%03d: OK\n", ++i);
	}

	/* empty */
	if (pathempty_ok == 0) {
		printf("TEST%03d: NG, empty pathname not found.\n", ++i);
		result = -1;
	} else {
		printf("TEST%03d: OK\n", ++i);
	}

err:
	if (fclose(fp)) {
		printf("fclose() failed. %d\n", errno);
		result = -1;
	}

fast_err:
	return result;
}
