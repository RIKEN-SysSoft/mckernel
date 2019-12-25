#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define CMD_MAX 4096
#define OUT_MAX 4096

struct perf_sampling {
	unsigned long long nr;
	unsigned long long addr[];
};

void usage(void)
{
	printf("usage: perf-script-faker <perf.dat>");
}

void print_fake_header(void)
{
	static unsigned long long ns;

	printf("fake 111111 11111.%06d:          666666 cycles:ppp:\n", ns++);
}

void process_stack(struct perf_sampling *ps)
{
	unsigned long long i;
	char *cmdb = "addr2line -e /home/z30443/riken/projects/ihk+mckernel/install/smp-x86/kernel/mckernel.img -fpa";
	//char *cmdb = "addr2line -e /home/z30443/riken/projects/ihk+mckernel/install/smp-x86/kernel/mckernel.img -fpia";
	char cmd[CMD_MAX];
	char out[OUT_MAX];
	FILE *fp;
	off_t off;
	size_t len;
	char *pout;

	//printf("nr: %lu\n", ps->nr);
	//for (i = 0; i < ps->nr; i++) {
	//	printf("0x%lx\n", ps->addr[i]);
	//}
	//printf("\n");

	off = snprintf(cmd, CMD_MAX, "%s ", cmdb);
	for (i = 0; i < ps->nr; i++) {
		off += snprintf(cmd + off, CMD_MAX - off, "0x%lx ",
				ps->addr[i]);
		if (off >= CMD_MAX) {
			fprintf(stderr, "Error: add2line input buffer too small\n");
			exit(EXIT_FAILURE);
		}
	}

	fp = popen(cmd, "r");
	if (fp == NULL) {
		perror("Error: opening add2line");
		exit(EXIT_FAILURE);
	}

	print_fake_header();

	while (fgets(out, sizeof(out), fp) != NULL) {
		//printf("%s", out);

		// print trimmed address
		pout = strtok(out, ": ");
		len = strlen(pout);
		off = (len > 6) ? len - 6 : 0;
		printf("%24s ", pout + off);

		// print symbol name
		pout = strtok(NULL, ": ");
		printf("%s ", pout);

		// skip "at"
		pout = strtok(NULL, ": ");

		// print path
		pout = strtok(NULL, ": ");
		printf("(%s)\n", pout);
	}
	printf("\n");

	if (pclose(fp) == -1) {
		perror("Warning: closing add2line failed");
	}
}

int main(int argc, char *argv[])
{
	char *fn;
	int fd;
	struct perf_sampling *ps;
	struct stat st;
	size_t size;
	size_t rem, ss;


	if (argc != 2) {
		usage();
		return 1;
	}

	fn = argv[1];

	fd = open(fn, O_RDONLY);
	if (fd == -1) {
		perror("Error: Opening input file");
		return 1;
	}

	if (fstat(fd, &st)) {
		perror("Error: Obtaning input file size");
		return 1;
	}
	size = st.st_size;
	rem = size;

	ps = (struct perf_sampling *) mmap(NULL, size, PROT_READ, MAP_PRIVATE,
					   fd, 0);
	if (ps == MAP_FAILED) {
		perror("Error: mapping input file");
		return 1;
	}

	while (rem) {
		process_stack(ps);

		ss = sizeof(ps->nr) + ps->nr*sizeof(ps->addr[0]);
		ps = (struct perf_sampling *) (((char *) ps) + ss);
		rem -= ss;
	}

	return 0;
}
