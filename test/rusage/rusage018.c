#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

#define SZ_INDEX 1
#define NUM_AREAS 1

int main(int argc, char** argv) {
	int i;
	void* mem;
	void* newmem;
	int ret = 0;
	int fd;

	mem = mmap(0, 3 * sz_mem[SZ_INDEX], PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");

	*(unsigned long*)((char*)mem + 0) = 0x123456789abcdef0;
	*(unsigned long*)((char*)mem + sz_mem[SZ_INDEX]) = 0xbeefbeefbeefbeef;
	*(unsigned long*)((char*)mem + 2 * sz_mem[SZ_INDEX]) = 0xbeefbeefbeefbeef;

	ret = mprotect(mem + sz_mem[SZ_INDEX - 1], sz_mem[SZ_INDEX - 1], PROT_READ | PROT_EXEC);
	CHKANDJUMP(ret != 0, 255, "mprotect failed\n");

	munmap(mem, 3 * sz_mem[SZ_INDEX]);
	
 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
