#include <stdio.h>
#include <assert.h>
#include <sys/mman.h>
#include <numa.h>
#include <numaif.h>

#define PAGE_SIZE	(4096)

typedef struct func_setmem_para {
	int set_mode;
	int dummy;
	unsigned long set_nodemask;
	unsigned long set_maxnode;
} set_mem_para;

typedef struct func_mbind_para {
	int set_mode;
	int loop_cnt;
	unsigned long set_nodemask;
	unsigned long set_maxnode;
	unsigned flags;
} mbind_para;


typedef struct func_para {
	set_mem_para para1;
	mbind_para   para2;
} main_para;



char *mempolicy [] = {
	"MPOL_DEFAULT",
	"MPOL_PREFERRED",
	"MPOL_BIND",
	"MPOL_INTERLEAVE"
};

int func_set_mempolicy(set_mem_para* inpara)
{
	int rst = -1;
	int set_mode = inpara->set_mode;
	unsigned long set_nodemask = inpara->set_nodemask;
	unsigned long set_maxnode = inpara->set_maxnode;
	int mode = set_mode & 0x00000003;
	int get_mode;

	rst = set_mempolicy(set_mode, &set_nodemask, set_maxnode);

	printf("-----\n");
	if (rst < 0) {
		printf("NG:set_mempolicy - mode:(%s) nodemask:0x%x maxnode:%d rst:%d\n",
		       mempolicy[mode], set_nodemask, set_maxnode, rst);
		return -1;
	}
	printf("OK:set_mempolicy - mode:(%s) nodemask:0x%x maxnode:%d\n",
	       mempolicy[mode], set_nodemask, set_maxnode);

	rst = get_mempolicy(&get_mode, &set_nodemask, set_maxnode, NULL,
			    MPOL_F_NODE);

	if (rst < 0) {
		printf("NG:get_mempolicy - mode:(%s) nodemask:0x%x maxnode:%d rst:%d\n",
		       mempolicy[mode], set_nodemask, set_maxnode, rst);
		return -1;
	}
	printf("OK:get_mempolicy - mode:(%s) nodemask:0x%x maxnode:%d\n",
	       mempolicy[mode], set_nodemask, set_maxnode);

	printf("-----\n");

	return rst;
}

int func_mbind(mbind_para* inpara)
{
	int rst = -1;
	unsigned char *addr = NULL, *fresh_addr = NULL;
	int get_mode = 0;
	int i = 0;
	unsigned long mem_len = PAGE_SIZE;

	int set_mode = inpara->set_mode;
	unsigned long set_nodemask = inpara->set_nodemask;
	unsigned long set_maxnode = inpara->set_maxnode;
	unsigned flags = inpara->flags;
	int loop_cnt = inpara->loop_cnt;
	int mode = set_mode & 0x00000003;

	for (i = 0; i < loop_cnt; i++) {

		/* Grab the virtual address range */
		addr = mmap(0, mem_len, PROT_READ | PROT_WRITE,
			    MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
		if (addr == (void *) -1) {
			printf("[%02d] NG:mmap - len:%d prot:0x%x flags:0x%x\n",
			       i, mem_len, PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE);
			//assert(0 && "mmap() failed");
			return -1;
		} else {
			printf("[%02d] OK:mmap - addr:(0x%016lx) len:%d prot:0x%x flags:0x%x\n",
			       i, addr, mem_len, PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE);
		}

		if ((inpara->set_mode & 0x000000ff) == 0xff) {
			/* Skip MPOL_INTERLEAVE because it's not supported */
			switch ((i % 3)) {
				case MPOL_PREFERRED:
					set_mode = ((set_mode & 0xffffff00) |
						    MPOL_PREFERRED);
					set_nodemask = inpara->set_nodemask;
					flags = 0;
					mode = MPOL_PREFERRED;
					break;

				case MPOL_BIND:
					set_mode = ((set_mode & 0xffffff00) |
						    MPOL_BIND);
					set_nodemask = inpara->set_nodemask;
					flags = 0;
					mode = MPOL_BIND;
					break;

				case MPOL_INTERLEAVE:
					set_mode = ((set_mode & 0xffffff00) |
						    MPOL_INTERLEAVE);
					set_nodemask = inpara->set_nodemask;
					flags = 0;
					mode = MPOL_INTERLEAVE;
					break;

				case MPOL_DEFAULT:
				default:
					set_mode = ((set_mode & 0xffffff00) |
						    MPOL_DEFAULT);
					set_nodemask = 0;
					flags = MPOL_MF_STRICT;
					mode = MPOL_DEFAULT;
					break;
			}
		}

		rst = mbind(addr, mem_len, set_mode, &set_nodemask,
			    set_maxnode, flags);
		if (rst < 0) {
			printf("[%02d] NG:mbind - addr:(0x%016lx) len:%d mode:(%s) nodemask:0x%x maxnode:%d flags:%d rst:%d\n",
			       i, addr, mem_len, mempolicy[mode],
			       set_nodemask, set_maxnode, flags, rst);
			//assert(0 && "mbind() failed");
			return -1;
		} else {
			printf("[%02d] OK:mbind - addr:(0x%016lx) len:%d mode:(%s) nodemask:0x%x maxnode:%d flags:%d\n",
			       i, addr, mem_len, mempolicy[mode],
			       set_nodemask, set_maxnode, flags);
		}

		rst = get_mempolicy(&get_mode, NULL, 0, addr, MPOL_F_ADDR);
		if(rst < 0) {
			printf("[%02d] NG:get_mempolicy - addr:(0x%016lx) rst:%d\n",
				i, addr,  rst);
			//assert(0 && "get_mempolicy failed");
			return -1;
		} else {
			printf("[%02d] OK:get_mempolicy - addr:(0x%016lx) mode:(%s)\n",
			       i, addr, mempolicy[get_mode]);
		}

		/* Remap with the address policy */

		rst = munmap(addr, mem_len);
		if (rst < 0) {
			printf("[%02d] NG:munmap - addr:(0x%016lx) len:%d\n",
			       i, addr, mem_len);
		} else {
			printf("[%02d] OK:munmap - addr:(0x%016lx) len:%d\n",
			       i, addr, mem_len);
		}

		addr = mmap(addr, mem_len, PROT_READ | PROT_WRITE,
			     MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
		if (addr == (void *) -1) {
			printf("[%02d] NG:mmap - len:%d prot:0x%x flags:0x%x\n",
			       i, mem_len,  PROT_READ | PROT_WRITE,
			       MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE);
			return -1;
		} else {
			printf("[%02d] OK:mmap - addr:(0x%016lx) len:%d prot:0x%x flags:0x%x\n",
				i, addr, mem_len, PROT_READ | PROT_WRITE,
			       MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE);
		}


		/* Map with the default policy */

		fresh_addr = mmap(0, mem_len, PROT_READ | PROT_WRITE,
			     MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
		if (fresh_addr == (void *) -1) {
			printf("[%02d] NG:mmap - len:%d prot:0x%x flags:0x%x\n",
			       i, mem_len,  PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE);
			return -1;
		} else {
			printf("[%02d] OK:mmap - addr:(0x%016lx) len:%d prot:0x%x flags:0x%x\n",
			       i, fresh_addr, mem_len,
			       PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE);
		}

		printf("-----\n");

	}

	return 0;
}

int main(int argc, char *argv[])
{
	main_para inpara;
	int rst = -1;

	if (argc == 9 ) {

		inpara.para1.set_mode = strtol(argv[1], NULL, 16);
		inpara.para1.set_nodemask = strtoul(argv[2], NULL, 16);
		inpara.para1.set_maxnode = strtol(argv[3], NULL, 10);
		rst = func_set_mempolicy(&inpara.para1);
		if (rst == 0) {
			inpara.para2.set_mode = strtol(argv[4], NULL, 16);
			inpara.para2.set_nodemask =  strtoul(argv[5], NULL,
							     16);
			inpara.para2.set_maxnode = strtoul(argv[6], NULL, 10);

			/* Ignored */
			inpara.para2.flags = strtoul(argv[7], NULL, 16);

			/* Sweep over MPOL_* values */
			inpara.para2.loop_cnt = strtol(argv[8], NULL, 10);

			rst = func_mbind(&inpara.para2);
		}
	} else {
		printf("NG: Invalid number of parameters(%d)\n",(argc-1));
		printf("   parameter 1 : set_mempolicy(mode)\n");
		printf("   parameter 2 : set_mempolicy(nodemask)\n");
		printf("   parameter 3 : set_mempolicy(maxnode)\n");
		printf("   parameter 4 : mbind(mode). Pass 0xff when looping over mode values\n");
		printf("   parameter 5 : mbind(nodemask)\n");
		printf("   parameter 6 : mbind(maxnode)\n");
		printf("   parameter 7 : not used (mbind(flags))\n");
		printf("   parameter 8 : Loop count over mode values\n");
		printf("   example) ./exec_setmempolicy_mbind 0x8001 0x1 2 0x8002 0x1 2 0x0 1\n");
	}

	return rst;
}

