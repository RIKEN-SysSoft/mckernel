// test getdents d_off and lseek are coherent
#define _GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)
struct linux_dirent {
	long           d_ino;
	off_t          d_off;
	unsigned short d_reclen;
	char           d_name[];
};
#define BUF_SIZE 40
#define OFF_TABLE_SIZE (256UL << 20)

void print_dirent(char *buf, int bpos)
{
	struct linux_dirent *d;
	char d_type;

	d = (struct linux_dirent *) (buf + bpos);
	printf("%8ld  ", d->d_ino);
	d_type = *(buf + bpos + d->d_reclen - 1);
	printf("%-10s ", (d_type == DT_REG) ?  "regular" :
	       (d_type == DT_DIR) ?  "directory" :
	       (d_type == DT_FIFO) ? "FIFO" :
	       (d_type == DT_SOCK) ? "socket" :
	       (d_type == DT_LNK) ?  "symlink" :
	       (d_type == DT_BLK) ?  "block dev" :
	       (d_type == DT_CHR) ?  "char dev" : "???");
	printf("%4d %10lld  %s\n", d->d_reclen,
	       (long long) d->d_off, (char *) d->d_name);
}
int
main(int argc, char *argv[])
{
	int fd, nread;
	char buf[BUF_SIZE];
	struct linux_dirent *d;
	int bpos;
	off_t *off_table;
	int off_table_size = 0;
	int i;

	off_table = malloc(OFF_TABLE_SIZE * sizeof(off_t));
	if (!off_table)
		handle_error("malloc");
	off_table[off_table_size++] = 0;

	fd = open(argc > 1 ? argv[1] : ".", O_RDONLY | O_DIRECTORY);
	if (fd == -1)
		handle_error("open");
	for ( ; ; ) {
		nread = syscall(SYS_getdents, fd, buf, BUF_SIZE);
		if (nread == -1)
			handle_error("getdents");
		if (nread == 0)
			break;
		printf("--------------- nread=%d ---------------\n", nread);
		printf("i-node#  file type  d_reclen  d_off   d_name\n");
		for (bpos = 0; bpos < nread;) {
			d = (struct linux_dirent *) (buf + bpos);
			print_dirent(buf, bpos);
			off_table[off_table_size++] = d->d_off;
			bpos += d->d_reclen;
		}
		printf("at end of getdents: lseek %10lld\n",
		       lseek(fd, 0, SEEK_CUR));
	}

	for (i = 0; i < off_table_size; i++) {
		lseek(fd, off_table[i], SEEK_SET);
		printf("lseek to %ld: lseek %10lld\n",
		       off_table[i], lseek(fd, 0, SEEK_CUR));
		nread = syscall(SYS_getdents, fd, buf, BUF_SIZE);
		if (nread == -1)
			handle_error("getdents");
		if (nread == 0) {
			printf("--------------- nread=%d (EOF) ---------\n",
			       nread);
			if (i != off_table_size - 1)
				handle_error("unexpected EOF");
		} else {
			printf("--------------- nread=%d ---------------\n",
			       nread);
			printf("i-node#  file type  d_reclen  d_off   d_name\n");
			for (bpos = 0; bpos < nread;) {
				print_dirent(buf, bpos);
				bpos += d->d_reclen;
			}
		}
		printf("at end of getdents: lseek %10lld\n",
		       lseek(fd, 0, SEEK_CUR));
	}


	exit(EXIT_SUCCESS);
}
