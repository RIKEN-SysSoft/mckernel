#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>

int main(int argc, char *argv[])
{
	int rc = 0, ret = 0;
	int expected_thp = 0;

	if (argc < 2) {
		printf("err: too few arguments\n");
		return -1;
	}

	expected_thp = atoi(argv[1]);

	rc = prctl(PR_GET_THP_DISABLE);
	if (rc < 0) {
		perror("err: PR_GET_THP_DISABLE");
	}

	if (rc == expected_thp) {
		printf("[ OK ] get thp_disable: %d\n", rc);
		ret = 0;
	}
	else {
		printf("[ NG ] get thp_disable: %d (expected %d)\n",
			rc, expected_thp);
		ret = -1;
		goto out;
	}

 out:
	return ret;
}
