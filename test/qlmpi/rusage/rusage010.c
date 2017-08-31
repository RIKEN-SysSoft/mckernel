#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
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

int sz_anon[] = {
	4 * (1ULL<<10),
	2 * (1ULL<<20),
	1 * (1ULL<<30),
	134217728};

#define SZ_INDEX 0
#define NUM_AREAS 1

int main(int argc, char** argv) {
	int i;
	int sz_index;
	void* anon[NUM_AREAS];
	int ret = 0;
// for qlmpi test
	int swap_rc = 0;
	char buffer[BUF_SIZE];

	CHKANDJUMP(argc != 2, 255, "%s <sz_index>\n", argv[0]);
	sz_index = atoi(argv[1]);

	for(i = 0; i < NUM_AREAS; i++) {
		anon[i] = mmap(0, sz_anon[sz_index], PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		CHKANDJUMP(anon[i] == MAP_FAILED, 255, "mmap failed\n");
		memset(anon[i], 0, sz_anon[sz_index]);
	}
// for qlmpi test
	swap_rc = do_swap("/tmp/rusage010.swp", buffer);
	if (swap_rc < 0) {
		printf("[NG] swap is failed.\n");
	}

	for(i = 0; i < NUM_AREAS; i++) {
		munmap(anon[i], sz_anon[sz_index]);
	}
	
 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
