#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef unsigned long long cbuf_t;

#define HEX 0
#define DEC 1

void usage()
{
	fprintf(stderr, "usage: rpebs pebs-filename.dat\n");
}

int main(int argc, char **argv)
{
	int fd, i;
	ssize_t ret;
	static const int buffer_size = 4096;
	cbuf_t *buffer;
	int format = HEX;

	if ((argc != 2) && (argc != 3)) {
		usage();
		return 1;
	}

	if (argc == 3) {
		if (strcmp(argv[2], "hex")==0) {
			format = HEX;
		} else if (strcmp(argv[2], "dec")==0) {
			format = DEC;
		} else {
			fprintf(stderr, "Option not recognized, exiting\n");
			return 1;
		}
	}

	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		perror("Can't open PEBS file for reading");
	}

	if ((buffer = malloc(buffer_size)) == NULL) {
		perror("Cannot allocate memory");
		return 1;
	}

	do {
		if ((ret = read(fd, buffer, buffer_size)) == -1) {
			perror("Can't read file");
			return 1;
		}

		if (ret % sizeof(cbuf_t))
			printf("read buffer not multiple of %lu\n",
				sizeof(cbuf_t));

		for (i = 0; i < ret/sizeof(cbuf_t); i++) {
			if (format == HEX) {
				printf("%llx\n", buffer[i]);
			} else if (format == DEC) {
				printf("%llx \t(%llu)\n", buffer[i], buffer[i]);
			}
		}
	} while (ret);

	return 0;
}
