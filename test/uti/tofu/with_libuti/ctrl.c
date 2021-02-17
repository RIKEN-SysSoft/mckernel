#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "tof_uapi.h"
#include "tof_test.h"

int main(int argc, char *argv[]){
	int ctl_fd;
	int res;
	struct tof_addr laddr;
	struct tof_reg_user req;
	uint64_t cqmask[6] = {0x7ff,0x7ff,0x7ff,0x7ff,0x7ff,0x7ff};
	uint64_t bgmask[6] = {0xfffffffffff,0xfffffffffff,0xfffffffffff,
			      0xfffffffffff,0xfffffffffff,0xfffffffffff};


	if(argc != 1 && argc != 10){
		printf("usage: %s <NX> <NY> <NZ> <SX> <SY> <SZ> <LX> <LY> <LZ>\n", argv[0]);
		printf("  ex. %s 1 1 12 0 0 8 1 1 4\n", argv[0]);
		exit(1);
	}
	get_position(&laddr);

	/* REG_USER*/
	req.uid = 0; /// root?
	req.gpid = 23456;
	req.subnet.nx = laddr.x+1;
	req.subnet.ny = laddr.y+1;
	req.subnet.nz = laddr.z+1;
	req.subnet.sx = laddr.x;
	req.subnet.sy = laddr.y;
	req.subnet.sz = laddr.z;
	req.subnet.lx = 1;
	req.subnet.ly = 1;
	req.subnet.lz = 1;
	req.cqmask = (uint64_t *)&cqmask;
	req.bgmask = (uint64_t *)&bgmask;

	if(argc == 10){
		req.subnet.nx = strtol(argv[1], NULL, 10);
		req.subnet.ny = strtol(argv[2], NULL, 10);
		req.subnet.nz = strtol(argv[3], NULL, 10);
		req.subnet.sx = strtol(argv[4], NULL, 10);
		req.subnet.sy = strtol(argv[5], NULL, 10);
		req.subnet.sz = strtol(argv[6], NULL, 10);
		req.subnet.lx = strtol(argv[7], NULL, 10);
		req.subnet.ly = strtol(argv[8], NULL, 10);
		req.subnet.lz = strtol(argv[9], NULL, 10);
	}
	ctl_fd = open("/proc/tofu/dev/control", O_CLOEXEC);
	if(ctl_fd < 0){
		TOF_EXIT();
	}

/*
	res = ioctl(ctl_fd, TOF_IOCTL_SET_SUBNET, &req.subnet);
	if(res != 0){
		TOF_EXIT();
	}
*/
	res = ioctl(ctl_fd, TOF_IOCTL_REG_USER, &req);
	if(res != 0){
		TOF_EXIT();
	}
	printf("subnet= %d %d %d %d %d %d %d %d %d\n",
	       req.subnet.nx, req.subnet.ny, req.subnet.nz,
	       req.subnet.sx, req.subnet.sy, req.subnet.sz,
	       req.subnet.lx, req.subnet.ly, req.subnet.lz);
	printf("success:L%d\n", __LINE__);
	return 0;
}

