
#include "../include/defs.h"      /* From the crash source top-level directory */
#include <bfd.h>
#include <pwd.h>
#ifdef POSTK_DEBUG_ARCH_DEP_94 /* arch depends move */
#include <arch-ldump2mcdump.h>
#endif /* POSTK_DEBUG_ARCH_DEP_94 */

void ldump2mcdump_init(void);    /* constructor function */
void ldump2mcdump_fini(void);    /* destructor function (optional) */

void cmd_ldump2mcdump(void);     /* Declare the commands and their help data. */
char *help_ldump2mcdump[];

static struct command_table_entry command_table[] = {
        { "ldump2mcdump", cmd_ldump2mcdump, help_ldump2mcdump, 0},          /* One or more commands, */
        { NULL },                                     /* terminated by NULL, */
};


void __attribute__((constructor))
ldump2mcdump_init(void) /* Register the command set. */
{ 
        register_extension(command_table);
}
 
/* 
 *  This function is called if the shared object is unloaded. 
 *  If desired, perform any cleanups here. 
 */
void __attribute__((destructor))
ldump2mcdump_fini(void) { }

struct ihk_dump_page {
	unsigned long start;
	unsigned long map_count;
	unsigned long map[0];
};

struct ihk_dump_page_set {
	unsigned int completion_flag;
	unsigned int count;
	unsigned long page_size;
	unsigned long phy_page;
};

struct dump_mem_chunk {
	unsigned long addr;
	unsigned long size;
};

typedef struct dump_mem_chunks_s {
	int nr_chunks;
	unsigned long kernel_base;
	struct dump_mem_chunk chunks[];
} dump_mem_chunks_t;

#define PATH_MAX	4096
#define DUMP_MEM_SYMBOL	"dump_page_set_addr"
#define BOOTSTRAP_MEM_SYMBOL	"dump_bootstrap_mem_start"
#define MCDUMP_DEFAULT_FILENAME	"mcdump"
#ifndef POSTK_DEBUG_ARCH_DEP_94 /* arch depends move */
#define PAGE_SHIFT         12
#define LARGE_PAGE_SHIFT   21
#endif /* !POSTK_DEBUG_ARCH_DEP_94 */
#define LARGE_PAGE_SIZE    (1UL << LARGE_PAGE_SHIFT)
#define LARGE_PAGE_MASK    (~((unsigned long)LARGE_PAGE_SIZE - 1))

#define PHYSMEM_NAME_SIZE 32

void cmd_ldump2mcdump(void)
{
	static char path[PATH_MAX];
	static char hname[HOST_NAME_MAX+1];
	bfd *abfd = NULL;
	char *fname;
	bfd_boolean ok;
	asection *scn;
	unsigned long phys_size, phys_offset;
	int error;
	size_t bsize;
	void *buf = NULL;
	uintptr_t addr;
	size_t cpsize;
	time_t t;
	struct tm *tm;
	char *date;
	struct passwd *pw;
	dump_mem_chunks_t *mem_chunks = NULL;
	long mem_size;
	int opt = 0;
	int read_mem_ret = TRUE;

	ulong symbol_dump_page_set = 0;
	ulong dump_page_set_addr = 0;
	ulong symbol_bootstrap_mem = 0;
	ulong bootstrap_mem = 0;
	struct ihk_dump_page_set dump_page_set;
	ulong ihk_dump_page_addr = 0;
	struct ihk_dump_page ihk_dump_page;
	ulong *map_buf = NULL;
	ulong map_size = 0;
	int i,j,k,index,mem_num;
	ulong map_start,bit_count;
	char *physmem_name_buf = NULL;
	char physmem_name[PHYSMEM_NAME_SIZE];

	ulong read_mem_addr = 0;

	if (argcnt < 2) {
		perror("argument error");
		return;
	}

	strcpy(path,MCDUMP_DEFAULT_FILENAME);

	while ((opt = getopt(argcnt, args, "o:")) != -1) {
		switch (opt) {
			case 'o': /* '-o' */
				strcpy(path,optarg);
				break;
			default: /* '?' */
				fprintf(stderr, "ldump2mcdump os_index [-o file_name]\n");
				return;
		}
	}

	fname = path;
	symbol_dump_page_set = symbol_value(DUMP_MEM_SYMBOL);
	readmem(symbol_dump_page_set,KVADDR,&dump_page_set_addr,sizeof(dump_page_set_addr),"",FAULT_ON_ERROR);
	readmem(dump_page_set_addr,KVADDR,&dump_page_set,sizeof(dump_page_set),"",FAULT_ON_ERROR);

	// DUMP_QUERY_NUM_MEM_AREAS
	ihk_dump_page_addr = PTOV(dump_page_set.phy_page);
	for (i = 0, mem_num = 0; i < dump_page_set.count; i++) {

		readmem(ihk_dump_page_addr,KVADDR,&ihk_dump_page,sizeof(ihk_dump_page),"",FAULT_ON_ERROR);
		map_size = sizeof(unsigned long)*ihk_dump_page.map_count;
		map_buf = malloc(map_size);
		if (map_buf != NULL) {
			memset(map_buf,0x00,map_size);
			readmem((ihk_dump_page_addr+sizeof(struct ihk_dump_page)),KVADDR,map_buf,map_size,"",FAULT_ON_ERROR);

			for (j = 0, bit_count = 0; j < ihk_dump_page.map_count; j++) {
				for ( k = 0; k < 64; k++) {
					if (((ulong)*(map_buf+j) >> k) & 0x1) {
						bit_count++;
					} else {
						if (bit_count) {
							mem_num++;
							bit_count = 0;
						}
					}
				}
			}

			if (bit_count) {
				mem_num++;
			}
			free(map_buf);
		} else {
			perror("allocating mem buffer: ");
			return;
		}

		ihk_dump_page_addr += (sizeof(struct ihk_dump_page)+(sizeof(unsigned long)*ihk_dump_page.map_count));
	}
	mem_size = (sizeof(dump_mem_chunks_t) + (sizeof(struct dump_mem_chunk) * mem_num));

	// DUMP_QUERY_MEM_AREAS
	mem_chunks = malloc(mem_size);
	if (mem_chunks != NULL) {
		memset(mem_chunks, 0, mem_size);
		ihk_dump_page_addr = PTOV(dump_page_set.phy_page);

		for (i = 0, index = 0; i <  dump_page_set.count; i++) {

			readmem(ihk_dump_page_addr,KVADDR,&ihk_dump_page,sizeof(ihk_dump_page),"",FAULT_ON_ERROR);
			map_size = sizeof(unsigned long)*ihk_dump_page.map_count;
			map_buf = malloc(map_size);
			if (map_buf != NULL) {
				memset(map_buf,0x00,map_size);
				readmem((ihk_dump_page_addr+sizeof(struct ihk_dump_page)),KVADDR,map_buf,map_size,"",FAULT_ON_ERROR);

				for (j = 0, bit_count = 0; j < ihk_dump_page.map_count; j++) {
					for (k = 0; k < 64; k++) {
						if (((ulong)*(map_buf+j) >> k) & 0x1) {
							if (!bit_count) {
								map_start = (unsigned long)(ihk_dump_page.start + ((unsigned long)j << (PAGE_SHIFT+6)));
								map_start = map_start + ((unsigned long)k << PAGE_SHIFT);
							}
							bit_count++;
						} else {
							if (bit_count) {
								mem_chunks->chunks[index].addr = map_start;
								mem_chunks->chunks[index].size = (bit_count << PAGE_SHIFT);
								index++;
								bit_count = 0;
							}
						}
					}
				}

				if (bit_count) {
					mem_chunks->chunks[index].addr = map_start;
					mem_chunks->chunks[index].size = (bit_count << PAGE_SHIFT);
					index++;
				}

				ihk_dump_page_addr += (sizeof(struct ihk_dump_page)+(sizeof(unsigned long)*ihk_dump_page.map_count));
				free(map_buf);
			} else {
				perror("allocating mem buffer: ");
				return;
			}

		}
		mem_chunks->nr_chunks = index;

		symbol_bootstrap_mem = symbol_value(BOOTSTRAP_MEM_SYMBOL);

		readmem(symbol_bootstrap_mem,KVADDR,&bootstrap_mem,sizeof(bootstrap_mem),"",FAULT_ON_ERROR);

		/* See load_file() for the calculation below */
		mem_chunks->kernel_base =
			(bootstrap_mem + LARGE_PAGE_SIZE * 2 - 1) & LARGE_PAGE_MASK;
	} else {
		perror("allocating mem buffer: ");
		return;
	}

	// DUMP_READ
	phys_size = 0;

//	fprintf(fp,"%s: nr chunks: %d\n", __FUNCTION__, mem_chunks->nr_chunks);
	for (i = 0; i < mem_chunks->nr_chunks; ++i) {
//		fprintf(fp,"%s: 0x%lx:0x%lx\n",
//				__FUNCTION__,
//				mem_chunks->chunks[i].addr,
//				mem_chunks->chunks[i].size);
		phys_size += mem_chunks->chunks[i].size;
	}

	bsize = 0x100000;
	buf = malloc(bsize);
	if (!buf) {
		perror("malloc");
		return;
	}

	bfd_init();

#ifdef POSTK_DEBUG_ARCH_DEP_34 /* use bfd_open target is NULL(automatic) */
	abfd = bfd_fopen(fname, NULL, "w", -1);
#else /* POSTK_DEBUG_ARCH_DEP_34 */
	abfd = bfd_fopen(fname, "elf64-x86-64", "w", -1);
#endif /* POSTK_DEBUG_ARCH_DEP_34 */
	if (!abfd) {
		bfd_perror("bfd_fopen");
		return;
	}

	ok = bfd_set_format(abfd, bfd_object);
	if (!ok) {
		bfd_perror("bfd_set_format");
		return;
	}

	t = time(NULL);
	if (t == (time_t)-1) {
		perror("time");
		return;
	}

	tm = localtime(&t);
	if (!tm) {
		perror("localtime");
		return;
	}

	date = asctime(tm);
	if (date) {
		cpsize = strlen(date) - 1;	/* exclude trailing '\n' */
		scn = bfd_make_section_anyway(abfd, "date");
		if (!scn) {
			bfd_perror("bfd_make_section_anyway(date)");
			return;
		}

		ok = bfd_set_section_size(abfd, scn, cpsize);
		if (!ok) {
			bfd_perror("bfd_set_section_size");
			return;
		}

		ok = bfd_set_section_flags(abfd, scn, SEC_HAS_CONTENTS);
		if (!ok) {
			bfd_perror("bfd_set_setction_flags");
			return;
		}
	}
	error = gethostname(hname, sizeof(hname));
	if (!error) {
		cpsize = strlen(hname);
		scn = bfd_make_section_anyway(abfd, "hostname");
		if (!scn) {
			bfd_perror("bfd_make_section_anyway(hostname)");
			return;
		}

		ok = bfd_set_section_size(abfd, scn, cpsize);
		if (!ok) {
			bfd_perror("bfd_set_section_size");
			return;
		}

		ok = bfd_set_section_flags(abfd, scn, SEC_HAS_CONTENTS);
		if (!ok) {
			bfd_perror("bfd_set_setction_flags");
			return;
		}
	}
	pw = getpwuid(getuid());
	if (pw) {
		cpsize = strlen(pw->pw_name);
		scn = bfd_make_section_anyway(abfd, "user");
		if (!scn) {
			bfd_perror("bfd_make_section_anyway(user)");
			return;
		}

		ok = bfd_set_section_size(abfd, scn, cpsize);
		if (!ok) {
			bfd_perror("bfd_set_section_size");
			return;
		}

		ok = bfd_set_section_flags(abfd, scn, SEC_HAS_CONTENTS);
		if (!ok) {
			bfd_perror("bfd_set_setction_flags");
			return;
		}
	}

	/* Add section for physical memory chunks information */
	scn = bfd_make_section_anyway(abfd, "physchunks");
	if (!scn) {
		bfd_perror("bfd_make_section_anyway(physchunks)");
		return;
	}

	ok = bfd_set_section_size(abfd, scn, mem_size);
	if (!ok) {
		bfd_perror("bfd_set_section_size");
		return;
	}

	ok = bfd_set_section_flags(abfd, scn, SEC_ALLOC|SEC_HAS_CONTENTS);
	if (!ok) {
		bfd_perror("bfd_set_setction_flags");
		return;
	}

	for (i = 0; i < mem_chunks->nr_chunks; ++i) {

		physmem_name_buf = malloc(PHYSMEM_NAME_SIZE);
		memset(physmem_name_buf,0,PHYSMEM_NAME_SIZE);
		sprintf(physmem_name_buf, "physmem%d",i);

		/* Physical memory contents section */
		scn = bfd_make_section_anyway(abfd, physmem_name_buf);
		if (!scn) {
			bfd_perror("bfd_make_section_anyway(physmem)");
			return;
		}

		ok = bfd_set_section_size(abfd, scn, mem_chunks->chunks[i].size);

		if (!ok) {
			bfd_perror("bfd_set_section_size");
			return;
		}

		ok = bfd_set_section_flags(abfd, scn, SEC_ALLOC|SEC_HAS_CONTENTS);
		if (!ok) {
			bfd_perror("bfd_set_setction_flags");
			return;
		}

		scn->vma = mem_chunks->chunks[i].addr;

	}

	scn = bfd_get_section_by_name(abfd, "date");
	if (scn) {
		ok = bfd_set_section_contents(abfd, scn, date, 0, scn->size);
		if (!ok) {
			bfd_perror("bfd_set_section_contents(date)");
			return;
		}
	}

	scn = bfd_get_section_by_name(abfd, "hostname");
	if (scn) {
		ok = bfd_set_section_contents(abfd, scn, hname, 0, scn->size);
		if (!ok) {
			bfd_perror("bfd_set_section_contents(hostname)");
			return;
		}
	}

	scn = bfd_get_section_by_name(abfd, "user");
	if (scn) {
		ok = bfd_set_section_contents(abfd, scn, pw->pw_name, 0, scn->size);
		if (!ok) {
			bfd_perror("bfd_set_section_contents(user)");
			return;
		}
	}

	scn = bfd_get_section_by_name(abfd, "physchunks");
	if (scn) {
		ok = bfd_set_section_contents(abfd, scn, mem_chunks, 0, mem_size);
		if (!ok) {
			bfd_perror("bfd_set_section_contents(physchunks)");
			return;
		}
	}

	for (i = 0; i < mem_chunks->nr_chunks; ++i) {

		phys_offset = 0;
		memset(physmem_name,0,sizeof(physmem_name));
		sprintf(physmem_name, "physmem%d",i);

		scn = bfd_get_section_by_name(abfd, physmem_name);
		if (!scn) {
			bfd_perror("err bfd_get_section_by_name(physmem_name)");
			return ;
		}

		for (addr = mem_chunks->chunks[i].addr;
				addr < (mem_chunks->chunks[i].addr + mem_chunks->chunks[i].size);
				addr += cpsize) {

			cpsize = (mem_chunks->chunks[i].addr + mem_chunks->chunks[i].size) - addr;
			if (cpsize > bsize) {
				cpsize = bsize;
			}

			memset(buf,0x00,cpsize);
			read_mem_addr = PTOV(addr);
			read_mem_ret = readmem(read_mem_addr,KVADDR,buf,cpsize,"",FAULT_ON_ERROR|RETURN_ON_ERROR);
			if (read_mem_ret == TRUE) {
				ok = bfd_set_section_contents(abfd, scn, buf, phys_offset, cpsize);
				if (!ok) {
					bfd_perror("bfd_set_section_contents(physmem)");
					return;
				}

				phys_offset += cpsize;
			} else {
				fprintf(fp, "readmem error(%d)\n",read_mem_ret);
			}
		}
	}

	ok = bfd_close(abfd);
	if (!ok) {
		bfd_perror("bfd_close");
		return;
	}

	free(buf);
	free(mem_chunks);

	return;

}

char *help_ldump2mcdump[] = {
	"ldump2mcdump",	/* command name */
	"dump format conversion",	/* short description */
	"<os_index> [-o <file_name>]",	/* argument synopsis, or " " if none */
	"  This command converts the McKernel dump file format.",
        "\nEXAMPLE",
        " ldump2mcdump all command arguments:\n",
        "    crash>ldump2mcdump 0 -o /tmp/mcdump",
        NULL
};


