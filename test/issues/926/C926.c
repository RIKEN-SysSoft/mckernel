#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int
main(int argc, char **argv)
{
	pid_t pid1;
	pid_t pid2;
	pid_t pid3;
	int st;
	int p[2];
	int shmid;
	int *sp;
	key_t key;
	int valid1;
	int valid2;
	int valid3;
	char c;
	int result;
	struct shmid_ds buf;

	key = ftok(argv[0], 0);

	printf("C926T01... ");
	fflush(stdout);
	valid1 = 1;
	valid2 = 2;
	valid3 = 2;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == -1) {
		perror("socketpair");
		exit(1);
	}

	if ((pid1 = fork()) == 0) {
		close(p[0]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 0
		sp = shmat(shmid, NULL, 0);
		*sp = 1;
		// step 1
		st = *sp == valid1? 1: 0;
		shmdt(sp);
		write(p[1], &c, 1);
		exit(st);
	}

	if ((pid2 = fork()) == 0) {
		close(p[1]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 2
		read(p[0], &c, 1);
		sp = shmat(shmid, NULL, 0);
		(*sp)++;
		// step 3
		st = *sp == valid2? 1: 0;
		shmdt(sp);
		// step 4
		exit(st);
	}

	close(p[0]);
	close(p[1]);
	result = 0;
	waitpid(pid1, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);
	waitpid(pid2, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if ((pid3 = fork()) == 0) {
		// step 5
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		sp = shmat(shmid, NULL, 0);
		st = *sp == valid3? 1: 0;
		shmdt(sp);
		exit(st);
	}

	waitpid(pid3, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if (result == 3) {
		printf("OK\n");
	}
	else {
		printf("NG\n");
	}

	printf("C926T02... ");
	fflush(stdout);
	valid1 = 1;
	valid2 = 2;
	valid3 = 2;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == -1) {
		perror("socketpair");
		exit(1);
	}

	if ((pid1 = fork()) == 0) {
		close(p[0]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 0
		sp = shmat(shmid, NULL, 0);
		*sp = 1;
		// step 1
		st = *sp == valid1? 1: 0;
		exit(st);
	}

	if ((pid2 = fork()) == 0) {
		close(p[1]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 2
		read(p[0], &c, 1);
		sp = shmat(shmid, NULL, 0);
		(*sp)++;
		// step 3
		st = *sp == valid2? 1: 0;
		shmdt(sp);
		// step 4
		exit(st);
	}

	close(p[0]);
	close(p[1]);
	result = 0;
	waitpid(pid1, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);
	waitpid(pid2, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if ((pid3 = fork()) == 0) {
		// step 5
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		sp = shmat(shmid, NULL, 0);
		st = *sp == valid3? 1: 0;
		shmdt(sp);
		exit(st);
	}

	waitpid(pid3, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if (result == 3) {
		printf("OK\n");
	}
	else {
		printf("NG\n");
	}

	printf("C926T03... ");
	fflush(stdout);
	valid1 = 1;
	valid2 = 1;
	valid3 = 1;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == -1) {
		perror("socketpair");
		exit(1);
	}

	if ((pid1 = fork()) == 0) {
		close(p[0]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 0
		sp = shmat(shmid, NULL, 0);
		*sp = 1;
		// step 1
		shmctl(shmid, IPC_RMID, &buf);
		write(p[1], &c, 1);

		// step3
		read(p[1], &c, 1);
		st = *sp == valid1? 1: 0;
		shmdt(sp);
		write(p[1], &c, 1);
		exit(st);
	}

	if ((pid2 = fork()) == 0) {
		close(p[1]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 2
		read(p[0], &c, 1);
		sp = shmat(shmid, NULL, 0);
		(*sp)++;
		write(p[0], &c, 1);
		// step 4
		read(p[0], &c, 1);
		st = *sp == valid2? 1: 0;
		shmdt(sp);
		exit(st);
	}

	close(p[0]);
	close(p[1]);
	result = 0;
	waitpid(pid1, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);
	waitpid(pid2, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if ((pid3 = fork()) == 0) {
		// step 5
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		sp = shmat(shmid, NULL, 0);
		st = *sp == valid3? 1: 0;
		shmdt(sp);
		exit(st);
	}

	waitpid(pid3, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if (result == 3) {
		printf("OK\n");
	}
	else {
		printf("NG\n");
	}

	printf("C926T04... ");
	fflush(stdout);
	valid1 = 1;
	valid2 = 1;
	valid3 = 1;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == -1) {
		perror("socketpair");
		exit(1);
	}

	if ((pid1 = fork()) == 0) {
		close(p[0]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 0
		sp = shmat(shmid, NULL, 0);
		*sp = 1;
		// step 1
		shmctl(shmid, IPC_RMID, &buf);
		write(p[1], &c, 1);

		// step4
		read(p[1], &c, 1);
		st = *sp == valid1? 1: 0;
		shmdt(sp);
		exit(st);
	}

	if ((pid2 = fork()) == 0) {
		close(p[1]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 2
		read(p[0], &c, 1);
		sp = shmat(shmid, NULL, 0);
		(*sp)++;
		// step 3
		st = *sp == valid2? 1: 0;
		shmdt(sp);
		write(p[0], &c, 1);
		exit(st);
	}

	close(p[0]);
	close(p[1]);
	result = 0;
	waitpid(pid1, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);
	waitpid(pid2, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if ((pid3 = fork()) == 0) {
		// step 5
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		sp = shmat(shmid, NULL, 0);
		st = *sp == valid3? 1: 0;
		shmdt(sp);
		exit(st);
	}

	waitpid(pid3, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if (result == 3) {
		printf("OK\n");
	}
	else {
		printf("NG\n");
	}

	printf("C926T05... ");
	fflush(stdout);
	valid1 = 1;
	valid2 = 1;
	valid3 = 1;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == -1) {
		perror("socketpair");
		exit(1);
	}

	if ((pid1 = fork()) == 0) {
		close(p[0]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 0
		sp = shmat(shmid, NULL, 0);
		*sp = 1;
		// step 1
		shmctl(shmid, IPC_RMID, &buf);
		// step2
		st = *sp == valid1? 1: 0;
		shmdt(sp);
		write(p[1], &c, 1);
		exit(st);
	}

	if ((pid2 = fork()) == 0) {
		close(p[1]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 3
		read(p[0], &c, 1);
		sp = shmat(shmid, NULL, 0);
		(*sp)++;
		// step 4
		st = *sp == valid2? 1: 0;
		shmdt(sp);
		exit(st);
	}

	close(p[0]);
	close(p[1]);
	result = 0;
	waitpid(pid1, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);
	waitpid(pid2, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if ((pid3 = fork()) == 0) {
		// step 5
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		sp = shmat(shmid, NULL, 0);
		st = *sp == valid3? 1: 0;
		shmdt(sp);
		exit(st);
	}

	waitpid(pid3, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if (result == 3) {
		printf("OK\n");
	}
	else {
		printf("NG\n");
	}

	printf("C926T06... ");
	fflush(stdout);
	valid1 = 1;
	valid2 = 1;
	valid3 = 1;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == -1) {
		perror("socketpair");
		exit(1);
	}

	if ((pid1 = fork()) == 0) {
		close(p[0]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 0
		sp = shmat(shmid, NULL, 0);
		*sp = 1;
		// step 1
		shmctl(shmid, IPC_RMID, &buf);
		// step2
		st = *sp == valid1? 1: 0;
		exit(st);
	}

	if ((pid2 = fork()) == 0) {
		close(p[1]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 3
		read(p[0], &c, 1);
		sp = shmat(shmid, NULL, 0);
		(*sp)++;
		// step 4
		st = *sp == valid2? 1: 0;
		shmdt(sp);
		exit(st);
	}

	close(p[0]);
	close(p[1]);
	result = 0;
	waitpid(pid1, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);
	waitpid(pid2, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if ((pid3 = fork()) == 0) {
		// step 5
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		sp = shmat(shmid, NULL, 0);
		st = *sp == valid3? 1: 0;
		shmdt(sp);
		exit(st);
	}

	waitpid(pid3, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if (result == 3) {
		printf("OK\n");
	}
	else {
		printf("NG\n");
	}

	printf("C926T07... ");
	fflush(stdout);
	valid1 = 2;
	valid2 = 2;
	valid3 = 0;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == -1) {
		perror("socketpair");
		exit(1);
	}

	if ((pid1 = fork()) == 0) {
		close(p[0]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 0
		sp = shmat(shmid, NULL, 0);
		*sp = 1;
		write(p[1], &c, 1);
		// step 2
		read(p[1], &c, 1);
		shmctl(shmid, IPC_RMID, &buf);
		// step2
		st = *sp == valid1? 1: 0;
		exit(st);
	}

	if ((pid2 = fork()) == 0) {
		close(p[1]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 1
		read(p[0], &c, 1);
		sp = shmat(shmid, NULL, 0);
		(*sp)++;
		write(p[0], &c, 1);
		// step 3
		read(p[0], &c, 1);
		st = *sp == valid2? 1: 0;
		shmdt(sp);
		// step 4
		exit(st);
	}

	close(p[0]);
	close(p[1]);
	result = 0;
	waitpid(pid1, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);
	waitpid(pid2, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if ((pid3 = fork()) == 0) {
		// step 5
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		sp = shmat(shmid, NULL, 0);
		st = *sp == valid3? 1: 0;
		shmdt(sp);
		exit(st);
	}

	waitpid(pid3, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if (result == 3) {
		printf("OK\n");
	}
	else {
		printf("NG\n");
	}

	printf("C926T08... ");
	fflush(stdout);
	valid1 = 2;
	valid2 = 2;
	valid3 = 2;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == -1) {
		perror("socketpair");
		exit(1);
	}

	if ((pid1 = fork()) == 0) {
		close(p[0]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 0
		sp = shmat(shmid, NULL, 0);
		*sp = 1;
		write(p[1], &c, 1);
		// step 2
		read(p[1], &c, 1);
		// step2
		st = *sp == valid1? 1: 0;
		exit(st);
	}

	if ((pid2 = fork()) == 0) {
		close(p[1]);
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		// step 1
		read(p[0], &c, 1);
		sp = shmat(shmid, NULL, 0);
		(*sp)++;
		write(p[0], &c, 1);
		// step 3
		read(p[0], &c, 1);
		st = *sp == valid2? 1: 0;
		shmdt(sp);
		// step 4
		exit(st);
	}

	close(p[0]);
	close(p[1]);
	result = 0;
	waitpid(pid1, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);
	waitpid(pid2, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if ((pid3 = fork()) == 0) {
		// step 5
		shmid = shmget(key, 4096, IPC_CREAT | 0660);
		sp = shmat(shmid, NULL, 0);
		st = *sp == valid3? 1: 0;
		shmdt(sp);
		exit(st);
	}

	waitpid(pid3, &st, 0);
	if (WIFEXITED(st))
		result += WEXITSTATUS(st);

	if (result == 3) {
		printf("OK\n");
	}
	else {
		printf("NG\n");
	}

	exit(0);
}
