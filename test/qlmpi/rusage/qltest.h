#include <unistd.h>

#define BUF_SIZE (32 * 1024)

int do_swap(char *fname, void *buffer) {
	int rc = -1;
	rc = syscall(801, fname, buffer, BUF_SIZE, 2);
	printf("%s: swap returns %d , %s\n", __FUNCTION__, rc, fname);
	return rc;
}
