#include <stdio.h>
#include <unistd.h>
#include <linux/futex.h>
#include <syscall.h>
#include <errno.h>

int main(int argc, void *argv[])
{
	struct robust_list_head rlh;
	size_t len = sizeof(struct robust_list_head);
	int rc = 0, ret = 0;

	errno = 0;
	rc = syscall(__NR_set_robust_list, &rlh, len + 1);
	if (rc == -1 && errno == EINVAL) {
		printf("[OK] invalid len (1 greater than correct): EINVAL\n");
	} else {
		printf("[NG] invalid len (1 greater than correct): Succeed\n");
		ret = -1;
		goto out;
	}

	errno = 0;
	rc = syscall(__NR_set_robust_list, &rlh, len - 1);
	if (rc == -1 && errno == EINVAL) {
		printf("[OK] invalid len (1 less than correct): EINVAL\n");
	} else {
		printf("[NG] invalid len (1 less than correct): Succeed\n");
		ret = -1;
		goto out;
	}

out:
	return ret;
}

