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

#include "ht.h"

#define CMD_MAX 4096
#define OUT_MAX 4096
#define NAME_MAX 256

#define PRINT_SYMBOL_LENGTH 6

typedef struct {
	char addr[PRINT_SYMBOL_LENGTH];
	char name[NAME_MAX];
	char libp[NAME_MAX];
} symbol_t;

struct perf_sampling {
	unsigned long long nr;
	unsigned long long addr[];
};

hash_table_t ht;

void usage(void)
{
	printf("usage: perf-script-faker <perf.dat>");
}

void print_fake_header(void)
{
	static unsigned long long ns;

	printf("fake 111111 11111.%06d:          666666 cycles:ppp:\n", ns++);
}

symbol_t *translate_missing_symbol(unsigned long long addr)
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
	size_t nr;
	symbol_t *s;

	off = snprintf(cmd, CMD_MAX, "%s ", cmdb);
	off += snprintf(cmd + off, CMD_MAX - off, "0x%lx ", addr);
	if (off >= CMD_MAX) {
		fprintf(stderr, "Error: add2line input buffer too small\n");
		exit(EXIT_FAILURE);
	}

	s = (symbol_t *) malloc(sizeof(symbol_t));
	if (!s) {
		perror("Error: allocating symbol structures\n");
		exit(EXIT_FAILURE);
	}

	fp = popen(cmd, "r");
	if (fp == NULL) {
		perror("Error: opening add2line");
		exit(EXIT_FAILURE);
	}

	i = 0;
	while (fgets(out, sizeof(out), fp) != NULL) {
		//printf("%s", out);

		if (i) {
			fprintf(stderr, "addr2line returned more than one line\n");
			exit(EXIT_FAILURE);
		}

		// print trimmed address
		pout = strtok(out, ": ");
		len = strlen(pout);
		off = (len > 6) ? len - 6 : 0;
		snprintf(s->addr, PRINT_SYMBOL_LENGTH, "%s", pout + off);

		// print symbol name
		pout = strtok(NULL, ": ");
		snprintf(s->name, NAME_MAX, "%s", pout);

		// skip "at"
		pout = strtok(NULL, ": ");

		// print path
		pout = strtok(NULL, ": ");
		pout[1] = (pout[1] == '\n') ? '\0' : pout[1];
		snprintf(s->libp, NAME_MAX, "%s", pout);

		// insert element into hash table
		ht_insert(ht, addr, s);

		i++;
	}

	if (pclose(fp) == -1) {
		perror("Warning: closing add2line failed");
	}

	return s;
}

void print_raw_stack(struct perf_sampling *ps)
{
	unsigned long long i;

	fprintf(stderr, "nr: %lu\n", ps->nr);
	if (ps->nr > 100000) {
		fprintf(stderr, "skipping raw print of too long callchain\n");
	} else {
		for (i = 0; i < ps->nr; i++) {
			fprintf(stderr, "0x%lx\n", ps->addr[i]);
		}
		fprintf(stderr, "\n");
	}
}

void process_stack(struct perf_sampling *ps)
{
	unsigned long long i;
	symbol_t *s;

	//print_raw_stack(ps);

	if (!ps->nr)
		return;

	print_fake_header();

	for (i = 0; i < ps->nr; i++) {
		s = (symbol_t *) ht_search(ht, ps->addr[i]);
		if (!s) {
			s = translate_missing_symbol(ps->addr[i]);
		}
		printf("%24s %s (%s)\n", s->addr, s->name, s->libp);
	}
	printf("\n");
}

void print_progression_bar(size_t done, size_t size)
{
	int i;
	int ticks;
	const int mticks = 80;
	static int prev_ticks = -1;
	double ratio = (double)done/(double)size;

	ticks = (ratio*mticks);
	//fprintf(stderr, "ticks %d prev %d mticks %d\n",
	//	ticks, prev_ticks, mticks);
	if (ticks != prev_ticks) {
		fprintf(stderr, "\r%87s", "|");
		fprintf(stderr, "\r|");
		for (i = 0; i < ticks; i++)
			fprintf(stderr, "=");
		fprintf(stderr, ">[%d%]", (int)(ratio*100));
		prev_ticks = ticks;
	}
	if (ratio == 1)
		fprintf(stderr, "\n");
	fflush(stderr);
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

	ht_init(ht);

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
		//printf("processed %zu/%zu bytes\n", size-rem, size);
		process_stack(ps);

		ss = sizeof(ps->nr) + ps->nr*sizeof(ps->addr[0]);
		ps = (struct perf_sampling *) (((char *) ps) + ss);
		rem -= ss;

		print_progression_bar(size-rem, size);
	}

	return 0;
}
