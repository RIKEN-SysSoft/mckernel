#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

void do_write(int fd, const void *buf, size_t count)
{
	if (write(fd, buf, count) != count) {
		perror("Cannot write to fake file\n");
		exit(1);
	}
}

int main(int argc, char **argv) {
	int fd;
	unsigned long long watermark;
	unsigned long long pebs_ts, pebs_addr[10], pebs_num;
	unsigned long long mmap_start, mmap_len, mmap_ts;
	size_t size = sizeof(unsigned long long);
	unsigned long int PAGE_SIZE = 1<<12;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	unsigned long int freq_hz = 1300*1000000;
	unsigned long int freq_mult = freq_hz/1000; //for ms

	watermark = 0xffffffffffffffff;

	if ((fd = open("fake.dat", O_WRONLY | O_CREAT, mode))==-1) {
		perror("can't open fake file");
		return 1;
	}


	//mmap
	mmap_start = PAGE_SIZE*1;
	mmap_len   = PAGE_SIZE;
	mmap_ts=freq_mult*0;
	do_write(fd, &mmap_ts,    size);
	do_write(fd, &mmap_start, size);
	do_write(fd, &mmap_len,   size);
	mmap_start=PAGE_SIZE*3;
	mmap_len=PAGE_SIZE*2;
	mmap_ts=freq_mult*10;
	do_write(fd, &mmap_ts,    size);
	do_write(fd, &mmap_start, size);
	do_write(fd, &mmap_len,   size);

	//watermark end of map
	do_write(fd, &watermark,  size);

	//unmap
	mmap_start = PAGE_SIZE*3;
	mmap_len   = PAGE_SIZE*2;
	mmap_ts=freq_mult*50;
	do_write(fd, &mmap_ts,    size);
	do_write(fd, &mmap_start, size);
	do_write(fd, &mmap_len,   size);
	mmap_start = PAGE_SIZE*10;
	mmap_len   = PAGE_SIZE;
	mmap_ts=freq_mult*30;
	do_write(fd, &mmap_ts,    size);
	do_write(fd, &mmap_start, size);
	do_write(fd, &mmap_len,   size);

	//watermark end of umap
	do_write(fd, &watermark,  size);

	//watermark start of pebs 1
	do_write(fd, &watermark,  size);

	//pebs data 1
	pebs_ts=freq_mult*0; //mmap 1
	pebs_num=5;
	pebs_addr[0] = PAGE_SIZE*1 + 1001; //in
	pebs_addr[1] = PAGE_SIZE*1 + 1002; //in
	pebs_addr[2] = PAGE_SIZE*3 + 2001; //out
	pebs_addr[3] = PAGE_SIZE*3 + 2002; //out
	pebs_addr[4] =               1;    //out
	do_write(fd, &pebs_ts,   size);
	do_write(fd, &pebs_num,  size);
	do_write(fd,  pebs_addr, size*5);

	//watermark start of pebs 2
	do_write(fd, &watermark,  size);

	//pebs data 2
	pebs_ts=freq_mult*20; //mmap 1, 2
	pebs_num=5;
	pebs_addr[0] = PAGE_SIZE*1 + 1011; //in
	pebs_addr[1] = PAGE_SIZE*1 + 1012; //in
	pebs_addr[2] = PAGE_SIZE*3 + 2011; //in
	pebs_addr[3] = PAGE_SIZE*3 + 4097; //in
	pebs_addr[4] =               11;   //out
	do_write(fd, &pebs_ts,   size);
	do_write(fd, &pebs_num,  size);
	do_write(fd,  pebs_addr, size*5);

	//watermark start of pebs 3
	do_write(fd, &watermark,  size);

	//pebs data 3
	pebs_ts=freq_mult*60; //mmap 1
	pebs_num=5;
	pebs_addr[0] = PAGE_SIZE*1 + 1021; //in
	pebs_addr[1] = PAGE_SIZE*1 + 1022; //in
	pebs_addr[2] = PAGE_SIZE*3 + 2021; //out
	pebs_addr[3] = PAGE_SIZE*3 + 5000; //out
	pebs_addr[4] =               1;    //out
	do_write(fd, &pebs_ts,   size);
	do_write(fd, &pebs_num,  size);
	do_write(fd,  pebs_addr, size*5);

	if (close(fd)) {
		perror("Error closing file");
		return 1;
	}

	return 0;
}
