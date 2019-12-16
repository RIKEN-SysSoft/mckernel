/* main.c COPYRIGHT FUJITSU LIMITED 2019 */
#include "simple_test.h"
#include "read_test.h"
#include "reset_test.h"
#include "refresh_test.h"
#include "combination_test.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

int main(int argc, char *argv[])
{
	int ret = -1;
	int test_num = -1;
	char *endptr = NULL;

	the_app = argv[0];
	if (argc < 2) {
		fprintf(stderr,
			"%s : Incorrect number of arguments.\n",
			__func__);
		print_usage();
		goto out;
	}

	errno = 0;

	test_num = strtol(argv[1], &endptr, 0);
	if (errno != 0 ||
	    *endptr != '\0' ||
	    (test_num < INT_MIN || INT_MAX < test_num)) {
		fprintf(stderr, "%s : Failed to get test_num.\n"
				"error code : %d\n", __func__, errno);
		goto out;
	}

	switch (test_num) {
	case 1:
		ret = simple_test();
		break;
	case 2:
		ret = read_test();
		break;
	case 3:
		ret = reset_test();
		break;
	case 4:
		ret = refresh_test();
		break;
	case 5:
		argc--;
		argv[1] = argv[0];
		ret = combination_main(argc, &argv[1]);
		break;
	default:
		fprintf(stderr, "%s : Incorrect test_num.\n", __func__);
		print_usage();
		break;
	}
out:
	return ret;
}
