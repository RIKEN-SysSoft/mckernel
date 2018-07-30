#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "ihklib.h"

#define Q(x) #x
#define QUOTE(x) Q(x)

#define _OKNG(verb, cond, fmt, args...) do {			\
	if (cond) {						\
		if (verb)					\
			printf("[OK] " fmt "\n", ##args);	\
	} else {						\
		printf("[NG] " fmt "\n", ##args);		\
		goto out;					\
	}							\
} while (0)

#define OKNG(args...) _OKNG(1, ##args)
#define NG(args...) _OKNG(0, ##args)

#define CVAL(event, mask) \
	((((event) & 0xf00) << 24) | ((mask) << 8) | ((event) & 0xff))

#define CVAL2(event, mask, inv, count) \
	((((event) & 0xf00) << 24) | ((mask) << 8) | ((event) & 0xff) | \
	 ((inv & 1) << 23) | ((count & 0xff) << 24))

/* Intel Nehalem specific */
struct ihk_perf_event_attr attr[] = {
	{ .config = CVAL(0xc0, 0x00), .exclude_kernel = 1 }, /* INSTRUCTIONS */
	{ .config = CVAL(0x3c, 0x00), .exclude_kernel = 1 }, /* CYCLE */
	{ .config = CVAL(0x43, 0x01), .exclude_kernel = 1 }, /* L1D_REQUEST */
	{ .config = CVAL(0x51, 0x01), .exclude_kernel = 1 }, /* L1D_MISS */
	{ .config = CVAL(0x80, 0x03), .exclude_kernel = 1 }, /* L1I_REQUEST */
	{ .config = CVAL(0x80, 0x02), .exclude_kernel = 1 }, /* L1I_MISS */
	{ .config = CVAL(0x24, 0xaa), .exclude_kernel = 1 }, /* L2_MISS */
	{ .config = CVAL(0x2e, 0x41), .exclude_kernel = 1 }, /* LLC_MISS */
	{ .config = CVAL(0x49, 0x01), .exclude_kernel = 1 }, /* DTLB_MISS */
	{ .config = CVAL(0x85, 0x01), .exclude_kernel = 1 }, /* ITLB_MISS */
	{ .config = CVAL2(0x0e, 0x01, 1, 1), .exclude_kernel = 1 }, /* STALL */
};

int main(int argc, char **argv)
{
	int ret;
	int i, j;
	int event_num = 0;
	char *prefix = QUOTE(MCKDIR);
	char cmd[1024];

	unsigned long counter[4] = {0, 0, 0, 0};

	// INVALID index
	ret = ihk_os_setperfevent(99, attr, 1);
	OKNG(ret < 0, "INVALID index ret: %d", ret);

	// event_num 1
	for (j = 1; j < 5; j++) {
		printf("*** event_num %d ***************************\n", j);
		ret = ihk_os_setperfevent(0, attr, j);
		OKNG(ret == j, "setperfevent ret: %d", ret);

		event_num = ret;

		ret = ihk_os_perfctl(0, PERF_EVENT_ENABLE);
		OKNG(ret == 0, "ENABLE ret: %d", ret);

		sprintf(cmd, "%s/bin/mcexec ./1141_mck > /dev/null", prefix);
		ret = system(cmd);
		OKNG(ret == 0, "system mcexec");

		ret = ihk_os_perfctl(0, PERF_EVENT_DISABLE);
		OKNG(ret == 0, "DISABLE ret: %d", ret);

		ret = ihk_os_getperfevent(0, counter, event_num);
		OKNG(ret == 0, "getperfevent ret: %d", ret);

		for (i = 0; i < event_num; i++) {
			printf("read_value[%d] %ld\n", i, counter[i]);
		}
	}
	ret = 0;
out:
	return ret;
}
