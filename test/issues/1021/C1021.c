#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

int id;
int okcnt;
int ngcnt;
void *area;

void
ok(char *file, char *fmt, ...)
{
	va_list ap;

	printf("*** C1021T%02d %s ", id, file);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	okcnt++;
}

void
ng(char *file, char *fmt, ...)
{
	va_list ap;

	printf("*** C1021T%02d %s ", id, file);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	ngcnt++;
}

void
hex(char *bp, int len)
{
	unsigned char   *buf;
	long l;
	long p;
	long zl = 0;
	long zf = 1;
	long zp = 0;

	for (p = 0; p < len; p += 16) {
		int i;

		buf = (unsigned char *)bp + p;
		l = 16;
		if (p + 16 > len) {
			l = len - p;
		}
		if (!zf) {
			int     zz = 0;

			for (i = 0; i < l; i++) {
				if (buf[i])
					zz = 1;
			}
			if (l < 16 || !zz) {
				zl += 16;
				continue;
			}
			if (zl == 16) {
				printf("%016lx  00000000 00000000 00000000 "
				       "00000000  *................*\n", zp);
			}
			else if (zl) {
				printf("    %08lx - %08lx ZERO\n", zp, p);
			}
		}
		zf = 0;
		printf("%08lx ", p);
		for (i = 0; i < 16; i++) {
			if (i % 4 == 0)
				printf(" ");
			printf(i < l ? "%02x" : "  ", buf[i]);
			if (i < l && buf[i])
				zf = 1;
		}
		printf("  *");
		for (i = 0; i < 16; i++)
			printf(i < l ? "%c" : " ",
			       isprint(buf[i]) ? buf[i] : '.');
		printf("*\n");
		zl = 0;
		zp = p + 16;
	}
}

void
sub(char *file, int mapsflag)
{
	int fd;
	int fd2;
	char buf1[65536];
	char buf2[65536];
	char buf3[65536];
	int n;
	int rc;
	int pos;

	id++;
	fd = open(file, O_RDONLY);
	if (fd == -1) {
		ng(file, "open %s", strerror(errno));
	}
	else {
		ok(file, "open OK");
	}

	id++;
	fd2 = dup(fd);
	if (fd2 == -1) {
		ng(file, "dup %s", strerror(errno));
	}
	else {
		ok(file, "dup OK");
	}

	id++;
	for (n = 0; (rc = read(fd, buf1 + n, 1)) == 1; n++);
	if (rc == -1) {
		ng(file, "read(1) %s", strerror(errno));
	}
	else if (mapsflag && n < 4096) {
		ng(file, "read(1) short n=%d", n);
	}
	else {
		ok(file, "read(1) OK n=%d", n);
	}

	id++;
	rc = lseek(fd, 0L, SEEK_SET);
	if (rc == -1) {
		ng(file, "lseek %s", strerror(errno));
	}
	else {
		ok(file, "lseek OK");
	}

	if (mapsflag)
		munmap(area, 4096);

	id++;
	pos = 0;
	while ((rc = read(fd, buf2 + pos, 1024)) > 0) {
		pos += rc;
	}
	if (rc == -1) {
		ng(file, "read(1) %s\n", strerror(errno));
	}
	else {
		if (pos != n) {
			ng(file, "read(1024) invalid size %d != %d", pos, n);
		}
		else if (memcmp(buf1, buf2, n) != 0) {
			ng(file, "read(1024) invalid data");
			hex(buf1, n);
			hex(buf2, n);
		}
		else {
			ok(file, "read(1024) OK");
		}
	}

	id++;
	rc = close(fd);
	if (rc == -1) {
		ng(file, "close %s", strerror(errno));
	}
	else {
		ok(file, "close OK");
	}

	id++;
	rc = read(fd2, buf3, n);
	if (rc == -1) {
		ng(file, "read(dup) EOF %s", strerror(errno));
	}
	else if (rc == 0) {
		ok(file, "read(dup) EOF OK");
	}
	else {
		ng(file, "read(dup) invalid position");
	}

	id++;
	rc = lseek(fd2, 0L, SEEK_SET);
	if (rc == -1) {
		ng(file, "lseek(dup) %s", strerror(errno));
	}
	else {
		ok(file, "lseek(dup) OK");
	}


	id++;
	rc = read(fd2, buf3, n);
	if (rc == -1) {
		ng(file, "read(dup) %s", strerror(errno));
	}
	else if (rc != n) {
		ng(file, "read(dup) too short");
	}
	else {
		rc = read(fd2, buf3 + rc, n);
		if (rc == -1) {
			ng(file, "read(dup) %s", strerror(errno));
		}
		else if (rc != 0) {
			ng(file, "read(dup) too long");
		}
		else if (memcmp(buf1, buf3, n) != 0) {
			ng(file, "read(dup) invalid data");
			hex(buf1, n);
			hex(buf3, n);
		}
		else {
			ok(file, "read(dup) OK");
		}
	}

	id++;
	rc = close(fd2);
	if (rc == -1) {
		ng(file, "close(dup) %s", strerror(errno));
	}
	else {
		ok(file, "close(dup) OK");
	}
}

int
main(int argc, char **argv)
{
	int i;
	int pid = getpid();
	char file[1024];

	for (i = 0; i < 512; i++) {
		char *c;

		if (i % 2) {
			c = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
				 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			area = c;
		}
		else {
			c = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
				 MAP_SHARED|MAP_ANONYMOUS, -1, 0);
		}

		if (c == (void *)-1) {
			printf("mmap error %d\n", errno);
			exit(1);
		}
		*c = 1;
	}
	sub("/proc/stat", 0);
	sprintf(file, "/proc/%d/auxv", pid);
	sub(file, 0);
	sprintf(file, "/proc/%d/cmdline", pid);
	sub(file, 0);
	sprintf(file, "/proc/%d/maps", pid);
	sub(file, 1);
	sprintf(file, "/proc/%d/status", pid);
	sub(file, 0);
	sprintf(file, "/proc/%d/task/%d/stat", pid, pid);
	sub(file, 0);

	if (ngcnt) {
		printf("TEST FAILED OK=%d NG=%d\n", okcnt, ngcnt);
		exit(1);
	}
	printf("TEST SUCCESS OK=%d\n", okcnt);
	exit(0);
}
