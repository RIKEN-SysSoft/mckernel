#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>

static const char test_text[] = "TEST_TEXT_988";

int main(void)
{
	int fd1, fd2;
	long pgsize = getpagesize();
	void *ptr1, *ptr2;
	int rc = 0;
	size_t fsize;

	fsize = strlen(test_text);

	if ((fd1 = open("MapFile1", O_RDWR | O_CREAT, 0666)) == -1) {
		perror("open");
		exit(-1);
	}

	// Set file size
	lseek(fd1, fsize, SEEK_SET);
	write(fd1, "\n", sizeof(char));
	lseek(fd1, 0, SEEK_SET);

	ptr1 = mmap(0, pgsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
	memcpy(ptr1, test_text, strlen(test_text));
	msync(ptr1, fsize, MS_SYNC);

	// mprotec PROT_NONE to ptr1
	rc = mprotect(ptr1, pgsize, PROT_NONE);
	if (rc != 0) {
		perror("mprotect");
		exit(-1);
	}
	printf("** mprotect PROT_NONE: Succeed\n");

	munmap(ptr1, pgsize);
	close(fd1);

	printf("** 1st file map and write: Done\n");

	if ((fd2 = open("MapFile2", O_RDWR | O_CREAT, 0666)) == -1) {
		perror("open");
		exit(-1);
	}

	// Set file size
	lseek(fd2, fsize, SEEK_SET);
	write(fd2, "\n", sizeof(char));
	lseek(fd2, 0, SEEK_SET);

	ptr2 = mmap(0, pgsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
	memcpy(ptr2, test_text, strlen(test_text));
	msync(ptr2, fsize, MS_SYNC);

	munmap(ptr2, pgsize);
	close(fd2);

	printf("** 2nd file map and write: Done\n");

	return 0;
}
