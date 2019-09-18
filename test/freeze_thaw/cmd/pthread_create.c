/* pthread_create.c COPYRIGHT FUJITSU LIMITED 2019 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define MAX_THREAD 1000
static pthread_t thread[MAX_THREAD];

static void *child_thread(void *arg)
{
	return NULL;
}

int main(int argc, char **argv)
{
	int ret = 0;
	int nr_thread;
	int i, j;

	if (argc < 2) {
		printf("usage: %s <nr_thread>\n", argv[0]);
		return 1;
	}

	nr_thread = atoi(argv[1]);
	if (nr_thread >= MAX_THREAD) {
		printf("err: MAX_THREAD=%d\n", MAX_THREAD);
		return 1;
	}

	for (i = 0; i < nr_thread; i++) {
		ret = pthread_create(&thread[i], NULL, child_thread, NULL);
		if (ret) {
			perror("pthread_create");
			break;
		}
	}

	for (j = 0; j < i; j++) {
		int join = pthread_join(thread[j], NULL);

		if (join) {
			ret = join;
			perror("pthread_join");
		}
	}
	return ret;
}
