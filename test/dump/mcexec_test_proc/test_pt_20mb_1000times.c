#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define MEM_SIZE (1024*1024*20)
#define LOOP_MAX 1024
#define SLEEP_TIME 30

main()
{

	int *buf,buf_size,index;

	buf_size = MEM_SIZE;

	for (index = 0; index < LOOP_MAX; index++) {
		buf = mmap(0, buf_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		if (NULL != buf) {
			memset(buf, 1, buf_size);
		} else {
			printf("[%d] mmap error!!! buf_size:%d(0x%x)\n", index, buf_size, buf_size);
		}
	}
	printf("mmap is done\n");

	sleep(SLEEP_TIME);

	return 0;
}
