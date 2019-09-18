/* thaw.c COPYRIGHT FUJITSU LIMITED 2019 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "ihk_host_user.h"

int main(int argc, char **argv)
{
	int ret = 0;
	int fd = -1;
	char dev[128];
	int mcosid;

	if (argc < 2) {
		printf("usage %s <osnum>\n", argv[0]);
		ret = -1;
		goto out;
	}
	mcosid = atoi(argv[1]);

	sprintf(dev, "/dev/mcos%d", mcosid);
	fd = open(dev, O_RDWR);
	if (fd == -1) {
		perror("open /dev/mcosN");
		ret = -1;
		goto out;
	}

	ret = ioctl(fd, IHK_OS_THAW, 0);
	if (ret) {
		perror("ioctl(thaw)");
		ret = -1;
		goto out;
	}
out:
	if (fd != -1) {
		close(fd);
	}
	return ret;
}
