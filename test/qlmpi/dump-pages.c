#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "swapfmt.h"

struct swap_header	header;
struct swap_areainfo	*meminfo, *lckinfo;

void
show(unsigned *data, int cnt)
{
    printf("\t");
    while (--cnt) {
	printf("%08lx ", *data++);
    }
    printf("\n");
}

unsigned long
convhex(char *cp)
{
    unsigned long	val = 0;

    while (*cp != '\n' && *cp != 0) {
	if (isdigit(*cp)) {
	    val = (val<<4) + *cp - '0';
	} else if (isupper(*cp) && isxdigit(*cp)) {
	    val = (val<<4) + *cp - 'A' + 10;
	} else if (isxdigit(*cp)) {
	    val = (val<<4) + *cp - 'a' + 10;
	} else {
	    break;
	}
	cp++;
    }
    return val;
}

ssize_t
findpos(unsigned long addr)
{
    int		i;
    ssize_t	pos = 0;
    for (i = 0; i < header.count_sarea; i++) {
	if (addr >= meminfo[i].start && addr < meminfo[i].end) {
	    pos = meminfo[i].pos;
	    pos += addr - meminfo[i].start;
	}
    }
    return pos;
}

int
main(int argc, char **argv)
{
    FILE	*fp;
    char	*fname, *cp;
    int		interractive = 0;
    int		i;

    if (argc >= 2) {
	fname = argv[1];
	if (argc >= 3) interractive = 1;
    } else {
	fname = "/tmp/pages";
    }
    if ((fp = fopen(fname, "r")) == 0) {
	fprintf(stderr, "Cannot open file: %s\n", fname);
	exit(-1);
    }
    fread(&header, sizeof(header), 1, fp);
    printf("magic           : %s\n", header.magic);
    printf("version         : %d\n", header.version);
    printf("swap area count : %d\n", header.count_sarea);
    printf("mlock area count: %d\n", header.count_marea);
    printf("SWAP:\n");
    printf("\t    start               end          : file position (flags)\n");
    meminfo = malloc(sizeof(struct swap_areainfo)* header.count_sarea);
    lckinfo = malloc(sizeof(struct swap_areainfo)* header.count_marea);
    fread(meminfo, sizeof(struct swap_areainfo), header.count_sarea, fp);
    fread(lckinfo, sizeof(struct swap_areainfo), header.count_marea, fp);

    for (i = 0; i < header.count_sarea; i++) {
	printf("\t%016lx -- %016lx : %010lx (%lx)\n",
	       meminfo[i].start, meminfo[i].end, meminfo[i].pos, meminfo[i].flag);
    }
    printf("MLOCK:\n");
    printf("\t    start               end          : physical address (flags)\n");
    for (i = 0; i < header.count_marea; i++) {
	printf("\t%016lx -- %016lx : %010lx (%lx)\n",
	       lckinfo[i].start, lckinfo[i].end, lckinfo[i].pos, lckinfo[i].flag);
    }

    if (!interractive) goto ending;
    do {
	char	buf1[128], buf2[128], data[8*8 + 1];
	char	cmd;;
	ssize_t	sz;
	int	cc;
	unsigned long	addr;
	ssize_t		fpos;

	fprintf(stdout, "> "); fflush(stdout);
	cp = fgets(buf1, 128, stdin);
	if (cp == NULL) break;
	cc = sscanf(buf1, "%c %s", &cmd, buf2);
	if (cc != 2) continue;
	addr = convhex(buf2);
	fpos = findpos(addr);
	if (fpos == 0) continue;
	printf("%lx (fpos(%lx)):\n", addr, fpos);
	fseek(fp, fpos, SEEK_SET);
	if ((sz = fread(&data, 8*8, 1, fp)) != 1) goto err;
	if (cmd == 's') {
	    data[8*8] = 0;
	    printf("\t%s", data);
	} else {
	    show((unsigned*) data, 8);
	}
    } while (cp != NULL);
err:
ending:
    fclose(fp);
    return 0;
}
