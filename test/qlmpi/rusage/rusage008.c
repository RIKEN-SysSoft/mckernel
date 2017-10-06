#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include "qltest.h"

#define DEBUG

#ifdef DEBUG
#define dprintf(...)                                            \
    do {                                                        \
	char msg[1024];                                         \
	sprintf(msg, __VA_ARGS__);                              \
	fprintf(stderr, "%s,%s", __FUNCTION__, msg);            \
    } while (0);
#define eprintf(...)                                            \
    do {                                                        \
	char msg[1024];                                         \
	sprintf(msg, __VA_ARGS__);                              \
	fprintf(stderr, "%s,%s", __FUNCTION__, msg);            \
    } while (0);
#else
#define dprintf(...) do {  } while (0)
#define eprintf(...) do {  } while (0)
#endif

#define CHKANDJUMP(cond, err, ...)                                      \
    do {                                                                \
		if(cond) {                                                      \
			eprintf(__VA_ARGS__);                                       \
			ret = err;                                                  \
			goto fn_fail;                                               \
		}                                                               \
    } while(0)

int sz_mem[] = {
	4 * (1ULL<<10),
	2 * (1ULL<<20),
	1 * (1ULL<<30),
	134217728};

#define SZ_INDEX 0
#define NUM_AREAS 1

int main(int argc, char** argv) {
	void* mem;
	int ret = 0;
	pid_t pid;
	int status;
	int fd;
// for swap_test
	int swap_rc = 0;
	char buffer[BUF_SIZE];
	
	pid = fork();
	CHKANDJUMP(pid == -1, 255, "fork failed\n");
	if(pid == 0) {
		fd = open("./file", O_RDWR);
		CHKANDJUMP(fd == -1, 255, "open failed\n");
		
		mem = mmap(0, sz_mem[SZ_INDEX], PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");
		
		unsigned long val = *((unsigned long*)mem);

// for swap_test
		swap_rc = do_swap("/tmp/rusage008_c.swp", buffer);
		if (swap_rc < 0) {
			printf("[NG] swap in child is failed\n");
		}
		_exit(123);
	} else {
		fd = open("./file", O_RDWR);
		CHKANDJUMP(fd == -1, 255, "open failed\n");
		
		mem = mmap(0, sz_mem[SZ_INDEX], PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");
		
		unsigned long val = *((unsigned long*)mem);

		ret = waitpid(pid, &status, 0);
		CHKANDJUMP(ret == -1, 255, "waitpid failed\n");
// for swap_test
		swap_rc = do_swap("/tmp/rusage008_p.swp", buffer);
		if (swap_rc < 0) {
			printf("[NG] swap in parent is failed\n");
		}
		printf("exit status=%d\n", WEXITSTATUS(status));
	}
	
 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
