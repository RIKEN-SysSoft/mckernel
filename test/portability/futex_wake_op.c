#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/time.h>

int uaddr1 = 0;
int uaddr2 = 0;

pid_t gettid()
{
	return syscall(SYS_gettid);
}

static void * waker (void *ptr)
{
	int rc;
	sleep(1);

	rc = syscall(SYS_futex, &uaddr1, FUTEX_WAKE_OP, 1, NULL, &uaddr2, FUTEX_OP(0, 0, 1, 0));

	printf("futex_wake_op return:%d\n", rc);
	pthread_exit(NULL);
}

int main (void)
{
	int rc;
	pthread_t thr;

	pthread_create(&thr, NULL, waker, NULL);

	rc = syscall(SYS_futex, &uaddr1, FUTEX_WAIT, uaddr1, NULL, NULL, 0);

	printf("futex_wait return:%d\n", rc);

	pthread_join(thr, NULL);

	printf("[OK] futex_wake_op_01 : succeed\n");

	return 0;
}
