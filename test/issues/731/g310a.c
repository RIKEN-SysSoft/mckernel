/*
 * g310a: If superuser try to fork() after seteuid(bin), ...
 */

#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void)
{
	int error;
	struct passwd *pwd;
	pid_t pid;
	int ws;

	if (geteuid()) {
		printf("not a superuser\n");
		return 2;
	}

	pwd = getpwnam("bin");
	if (!pwd) {
		perror("getpwnam");
		return 1;
	}

	error = seteuid(pwd->pw_uid);
	if (error) {
		perror("seteuid");
		return 1;
	}

	pid = fork();
	if (pid == -1) {
		perror("fork");
	}

	if (!pid) {
		return 0;
	}

	pid = waitpid(pid, &ws, 0);
	if (pid == -1) {
		perror("waitpid");
		return 1;
	}
	if (ws) {
		printf("ws: %#x\n", ws);
		return 1;
	}

	printf("done.\n");
	return 0;
}
