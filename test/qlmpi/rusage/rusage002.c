#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
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

int main(int argc, char** argv) {
	void* mem;
	int ret = 0;
	int fd;
	char fn[256] = "/dev/shm/Intel_MPI";
#define TEST_VAL 0x1234
	int swap_rc = 0;
	char buffer[BUF_SIZE];
	
	fd = open(fn, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
	CHKANDJUMP(fd == -1, 255, "shm_open failed,str=%s\n", strerror(errno));

	ret = ftruncate(fd, sz_mem[SZ_INDEX]);
	CHKANDJUMP(ret != 0, 255, "ftruncate failed\n");

	mem = mmap(0, sz_mem[SZ_INDEX], PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");
	memset(mem, 0, sz_mem[SZ_INDEX]);

	// before swap
	*((unsigned long*)mem) = TEST_VAL;
	unsigned long val = *((unsigned long*)mem);
	if (val == TEST_VAL) {
		printf("[OK] before swap, val:0x%lx\n", val);
	} else {
		printf("[NG] before swap, val is not correct, val:0x%lx\n", val);
	}

	swap_rc = do_swap("/tmp/rusage002.swp", buffer);
	if (swap_rc < 0) {
		printf("[NG] swap is failed\n");
	}

	// after swap
	val = *((unsigned long*)mem);
	if (val == TEST_VAL) {
		printf("[OK] after swap,  val:0x%lx\n", val);
	} else {
		printf("[NG] after swap,  val is not correct, val:0x%lx\n", val);
	}

	munmap(mem, sz_mem[SZ_INDEX]);
	ret = close(fd);
	CHKANDJUMP(ret != 0, 255, "close failed\n");
	ret = unlink(fn);
	CHKANDJUMP(ret != 0, 255, "shm_unlink failed\n");
	
 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
