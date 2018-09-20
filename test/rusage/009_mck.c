#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "util.h"

#define DEBUG

int sz_mem[] = {
	4 * (1ULL<<10),
	2 * (1ULL<<20),
	1 * (1ULL<<30),
	134217728};

#define SZ_INDEX 0

int main(int argc, char **argv)
{
	void *mem;
	int ret = 0;
	pid_t pid;
	int status;
	key_t key = ftok(argv[0], 0);
	int shmid;

	shmid = shmget(key, sz_mem[SZ_INDEX], IPC_CREAT | 0660);
	CHKANDJUMP(shmid == -1, 255, "shmget failed: %s\n", strerror(errno));

	pid = fork();
	CHKANDJUMP(pid == -1, 255, "fork failed\n");
	if (pid == 0) {
		mem = shmat(shmid, NULL, 0);
		CHKANDJUMP(mem == (void *)-1, 255, "shmat failed: %s\n",
			   strerror(errno));

		*((unsigned long *)mem) = 0x1234;

		ret = shmdt(mem);
		CHKANDJUMP(ret == -1, 255, "shmdt failed\n");

		_exit(123);
	} else {
		mem = shmat(shmid, NULL, 0);
		CHKANDJUMP(mem == (void *)-1, 255, "shmat failed: %s\n",
			   strerror(errno));


		ret = waitpid(pid, &status, 0);
		CHKANDJUMP(ret == -1, 255, "waitpid failed\n");

		printf("%lx\n", *((unsigned long *)mem));

#if 0
		struct shmid_ds buf;

		ret = shmctl(shmid, IPC_RMID, &buf);
		CHKANDJUMP(ret == -1, 255, "shmctl failed\n");
#endif

		ret = shmdt(mem);
		CHKANDJUMP(ret == -1, 255, "shmdt failed\n");
	}

 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
