#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
int
main(int argc, char **argv)
{
	int data;
	long count;
	long i;
	int *buf;
	int r;
	char *p;

	if (argc != 3) {
		fprintf(stderr, "BAD argument\n");
		exit(1);
	}
	data = atoi(argv[1]);
	count = atol(argv[2]);

	fprintf(stderr, "data=%d count=%ld\n", data, count);
	buf = malloc(sizeof(int) * count);
	for (i = 0; i < count; i++)
		buf[i] = data;

	for (r = sizeof(int) * count, p = (char *)buf; r;) {
		int rc = write(1, p, r);
		if (rc == -EINTR)
			continue;
		if (rc <= 0) {
			fprintf(stderr, "write error: %d", errno);
			exit(1);
		}
		r -= rc;
		p += rc;
	}
	close(1);
	exit(0);
}
