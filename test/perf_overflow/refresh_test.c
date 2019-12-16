/* refresh_test.c COPYRIGHT FUJITSU LIMITED 2019 */
#include "refresh_test.h"

int refresh_test(void)
{
	struct perf_event_attr pe;
	long long count = 0;
	int fd = -1;
	int ret = -1;

	ret = init_perf_event_attr(&pe);
	if (ret < 0) {
		fprintf(stderr,
			"%s : Failed to init_perf_event_attr.\n",
			__func__);
		goto out;
	}

	fd = perf_event_open(&pe, 0, -1, -1, 0);
	if (fd == -1) {
		ret = errno;
		perror("perf_event_open");
		goto out;
	}

	ret = ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	if (ret < 0) {
		perror("ioctl(PERF_EVENT_IOC_RESET)");
		goto out;
	}

	ret = asm_ioctl3(fd, PERF_EVENT_IOC_ENABLE, 0);
	if (ret < 0) {
		perror("asm_ioctl(PERF_EVENT_IOC_ENABLE)");
		goto out;
	}

	nop10;
	nop10;
	nop10;
	nop10;
	ret = asm_ioctl3(fd, PERF_EVENT_IOC_REFRESH, 0);
	if (ret < 0) {
		perror("asm_ioctl(PERF_EVENT_IOC_REFRESH)");
		goto out;
	}
	nop10;
	nop10;
	nop10;
	nop10;

	ret = asm_ioctl3(fd, PERF_EVENT_IOC_DISABLE, 0);
	if (ret < 0) {
		perror("asm_ioctl(PERF_EVENT_IOC_DISABLE)");
		goto out;
	}

	ret = read(fd, &count, sizeof(long long));
	if (ret < 0) {
		perror("read");
		goto out;
	}

	printf("Used %lld instructions\n", count);

	ret = 0;
out:
	if (fd != -1) {
		close(fd);
	}
	return ret;
}
