#define __BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>

long
_ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)
{
	long rc;

	rc = ptrace(request, pid, addr, data);
	if (rc == -1) {
		printf("ptrace(%d, %d, %016x, %016x): %d\n", request, pid,
		       (long)addr, (long)data, errno);
		exit(1);
	}
	return rc;
}

typedef struct user_regs_struct syscall_args;

static inline int
get_syscall_args(int pid, syscall_args *args)
{
	return _ptrace(PTRACE_GETREGS, pid, NULL, args);
}

static inline unsigned long
get_syscall_number(syscall_args *args)
{
	return args->orig_rax;
}

static inline unsigned long
get_syscall_return(syscall_args *args)
{
	return args->rax;
}

static char *syscalls[512];

char *
trim(char *buf)
{
	char *p;
	char *q;

	for (p = buf; *p && (isspace(*p)); p++);
	if (!*p)
		return p;
	for (q = strchr(p, '\0') - 1; isspace(*q); q--)
		*q = '\0';
	return p;
}

char **
split(char *buf, char dlm)
{
	int n;
	char *t;
	char **r;
	char **p;

	for (n = 0, t = buf; *t; t++)
		if (*t == dlm)
			n++;
	p = r = malloc(sizeof(char *) * (n + 2) + strlen(buf) + 1);
	t = (char *)(r + n + 2);
	strcpy(t, buf);
	t = trim(t);
	if (*t) {
		*(p++) = t;
		for (; *t; t++)
			if (*t == dlm) {
				*(t++) = '\0';
				t = trim(t);
				trim(p[-1]);
				if (!*t)
					break;
				*(p++) = t;
			}
	}
	*p = NULL;
	return r;
}

void
init_syscalls()
{
	char buf[1024];
	FILE *f;

	f = fopen("/usr/include/asm/unistd_64.h", "r");
	if (!f) {
		perror("open(unistd_64.h)");
		return;
	}
	while (fgets(buf, 1024, f)) {
		char *t;
		char **a;

		if (strncmp(buf, "#define", 7))
			continue;
		for (t = buf; *t; t++)
			if (isspace(*t))
		*t = ' ';
		a = split(buf, ' ');
		if (a[0] && a[1] && !strncmp(a[1], "__NR_", 5) &&
		    a[2] && *(a[2]) >= '0' && *(a[2]) <= '9') {
			int num = atoi(a[2]);
			syscalls[num] = strdup(a[1] + 5);
		}
		free(a);
	}
	fclose(f);
}

const char *
get_syscall(int n, char *buf)
{
	if (n < 0 || n >= 512 || !syscalls[n]) {
		sprintf(buf, "unknown(%d)", n);
		return NULL;
	}
	return strcpy(buf, syscalls[n]);
}

int
main(int argc, char **argv)
{
	pid_t pid;
	pid_t cpid;
	unsigned long msg;
	int st;
	int rc;
	int w;
	syscall_args args;
	unsigned long sig = 0;
	char name[64];
	int pipefds[2];
	char ch = ' ';
	int ok = 0;
	int ng = 0;
	int procs = 0;

	init_syscalls();
	printf("#946 start\n");
	fflush(stdout);
	pipe(pipefds);
	pid = fork();
	if(pid == 0){
		close(pipefds[0]);
		_ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		kill(getpid(), SIGINT);
		pid = fork();
		if (pid == 0) {
			exit(16);
		}
		sleep(1);
		rc = wait(&st);
		if (rc == pid &&
		    WIFEXITED(st) &&
		    WEXITSTATUS(st) == 16) {
			printf("#946-1 exit after wait OK\n");
			write(pipefds[1], "0", 1);
		}
		else {
			printf("#946-1 exit after wait NG\n");
			write(pipefds[1], "1", 1);
		}
		pid = fork();
		if (pid == 0) {
			sleep(1);
			exit(32);
		}
		rc = wait(&st);
		if (rc == pid &&
		    WIFEXITED(st) &&
		    WEXITSTATUS(st) == 32) {
			printf("#946-2 exit before wait OK\n");
			write(pipefds[1], "0", 1);
		}
		else {
			printf("#946-2 exit before wait NG\n");
			write(pipefds[1], "1", 1);
		}
		close(pipefds[1]);
		fflush(stdout);
		exit(64);
	}
	close(pipefds[1]);
	rc = waitpid(-1, &st, WUNTRACED);
	if (rc != pid || !WIFSTOPPED(st)) {
		printf("BAD1 rc=%d st=%08x\n", rc, st);
		exit(1);
	}
	_ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(PTRACE_O_TRACESYSGOOD |
	                                               PTRACE_O_TRACEFORK    |
	                                               PTRACE_O_TRACEVFORK   |
	                                               PTRACE_O_TRACECLONE   |
	                                               PTRACE_O_TRACEEXEC));

	rc = pid;
	procs = 1;
	for (;;) {
		if (rc != -1)
			_ptrace(PTRACE_SYSCALL, rc, NULL, (void *)sig);
		sig = 0;
		rc = waitpid(-1, &st, WUNTRACED);
		if (WIFEXITED(st) || WIFSIGNALED(st)) {
//			printf("wait(1) rc=%d st=%08x\n", rc, st);
			procs--;
//			printf("%d: terminate procs=%d\n", rc, procs);
//			fflush(stdout);
			if (rc == pid)
				pid = -1;
			else if (rc == cpid)
				cpid = -1;
			rc = -1;
			if (!procs) {
				break;
			}
			continue;
		}
		if (!WIFSTOPPED(st)) {
			printf("wait(1) rc=%d st=%08x\n", rc, st);
			printf("unrecognized status rc=%d st=%08x\n", rc, st);
			fflush(stdout);
			continue;
		}
		if ((w = (st >> 16) & 255) == PTRACE_EVENT_FORK ||
		    w == PTRACE_EVENT_VFORK ||
		    w == PTRACE_EVENT_CLONE ||
		    w == PTRACE_EVENT_VFORK_DONE) {
			int crc;
//			printf("wait(1) rc=%d st=%08x\n", rc, st);
//			printf("%d: fork exent ev=%d\n", rc, w);
//			fflush(stdout);
			_ptrace(PTRACE_GETEVENTMSG, pid, NULL, &msg);
			cpid = msg;
//			printf("child pid=%d\n", cpid);
//			fflush(stdout);
			crc = waitpid(-1, &st, WUNTRACED);
			if (crc != cpid || !WIFSTOPPED(st)) {
				printf("BAD4 rc=%d st=%08x\n", crc, st);
				exit(1);
			}
//			printf("wait(2) rc=%d st=%08x\n", crc, st);
//			fflush(stdout);
			procs++;
			_ptrace(PTRACE_SYSCALL, cpid, NULL, (void *)0);
			continue;
		}
		if (w == PTRACE_EVENT_EXEC) {
			printf("wait(1) rc=%d st=%08x\n", rc, st);
			printf("%d: exec event\n", rc);
			fflush(stdout);
			continue;
		}
		if (w == PTRACE_EVENT_EXIT) {
			printf("wait(1) rc=%d st=%08x\n", rc, st);
			printf("%d: exit event\n", rc);
			fflush(stdout);
			continue;
		}
		if (WSTOPSIG(st) & 0x80) { // syscall
			int num;
			get_syscall_args(rc, &args);
			num = get_syscall_number(&args);
//			if (num == __NR_open ||
//			    num == __NR_access ||
//			    num == __NR_stat)
//				continue;
//			printf("wait(1) rc=%d st=%08x\n", rc, st);
//			fflush(stdout);
//			if (get_syscall_return(&args) == -ENOSYS) {
//				get_syscall(num, name);
//				printf("%d: syscall=%s\n", rc, name);
//			}
//			else {
//				get_syscall(num, name);
//				printf("%d: syscall=%s rc=%ld\n", rc, name,
//				       get_syscall_return(&args));
//			}
//			fflush(stdout);
		}
		else { // signal
//			printf("wait(1) rc=%d st=%08x\n", rc, st);
//			sig = WSTOPSIG(st) & 0x7f;
//			printf("%d: sig=%d\n", rc, sig);
//			fflush(stdout);
		}
	}
	for (;;) {
		int len;
		len = read(pipefds[0], &ch, 1);
		if (len == 1) {
			if (ch == '0') {
				ok++;
			}
			else {
				ng++;
			}
		}
		else {
			break;
		}
	}
	close(pipefds[0]);
	printf("#946 terminated ok=%d ng=%d\n", ok, ng);
	fflush(stdout);
	exit(0);
}
