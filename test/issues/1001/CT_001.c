#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include "./test_chk.h"

#include "./perf_tool.h"

#define TEST_NAME "CT_001"

#define NUM_CNTR 1

int main(int argc, char **argv)
{
	int fds[NUM_CNTR];
	long long tmp_count;
	long long counts[NUM_CNTR];
	__u32 configs[NUM_CNTR] = {
		PERF_COUNT_HW_INSTRUCTIONS};
	char *config_names[NUM_CNTR] = {
		"INSTRUCTIONS"};
	struct perf_event_attr pe_attr;
	int group_fd = -1;

	int rc = 0;
	int i = 0;
	int chk_fail = 0;

	printf("*** %s start *******************************\n", TEST_NAME);

	// common config
	memset(&pe_attr, 0, sizeof(struct perf_event_attr));
	pe_attr.size = sizeof(struct perf_event_attr);
	pe_attr.disabled = 1;
	pe_attr.exclude_kernel = 1;
	pe_attr.exclude_user = 0;
	pe_attr.type = PERF_TYPE_HARDWARE;

	chk_fail = 0;
	// perf_event_open
	for (i = 0; i < NUM_CNTR; i++) {
		pe_attr.config = configs[i];

		fds[i] = perf_event_open(&pe_attr, 0, -1, group_fd, 0);
		if (fds[i] == -1) {
			chk_fail = 1;
			break;
		}
		if (group_fd == -1) {
			group_fd = fds[i];
		}
	}
	OKNG(chk_fail != 0, "perf_event_open for %d counter", NUM_CNTR);

	// reset counters
	for (i = 0; i < NUM_CNTR; i++) {
		rc = ioctl(fds[i], PERF_EVENT_IOC_RESET, 0);
		CHKANDJUMP(rc != 0, "ioctl RESET");
	}

	chk_fail = 0;
	// read counters at first
	for (i = 0; i < NUM_CNTR; i++) {
		rc = read(fds[i], &tmp_count, sizeof(long long));
		CHKANDJUMP(rc == -1, "read counter[%d]", i);
		printf("%-16s: %ld\n", config_names[i], tmp_count);
		if (tmp_count != 0) {
			chk_fail = 1;
			break;
		}
	}
	OKNG(chk_fail != 0, "Reset counter to 0");

	// start counters at once
	rc = ioctl(group_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
	OKNG(rc != 0, "Start counter at once");

	// monitoring target
	printf("  do some processing...\n");
	calc_task();
	memory_task();

	// stop counters at once
	rc = ioctl(group_fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
	OKNG(rc != 0, "Stop counter at once");

	printf("  counted value is as belows...\n");
	// read counters after processing
	for (i = 0; i < NUM_CNTR; i++) {
		rc = read(fds[i], &tmp_count, sizeof(long long));
		CHKANDJUMP(rc == -1, "read counter[%d]", i);
		printf("%-16s: %ld\n", config_names[i], tmp_count);
		counts[i] = tmp_count;
	}

	printf("  processing again... (to check if counter is stopped)\n");
	// processing again (counters are stopped)
	calc_task();
	memory_task();

	printf("  current value is bellow\n"
		"  (expected to be same value as last time)\n");

	chk_fail = 0;
	// read counters again to check if counters were stopped
	for (i = 0; i < NUM_CNTR; i++) {
		rc = read(fds[i], &tmp_count, sizeof(long long));
		printf("%-16s: %ld\n", config_names[i], tmp_count);
		if (counts[i] != tmp_count) {
			chk_fail = 1;
			break;
		}
	}
	OKNG(chk_fail != 0, "Counter is stopped");

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
