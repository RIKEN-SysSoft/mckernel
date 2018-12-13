/* ihklib001_lin.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <getopt.h>
#include <ihklib.h>
#include "util.h"
#include "mck_bps_conflict.h"

#define DEBUG

int main(int argc, char **argv)
{
	int ret, status;
	FILE *fp, *fp1, *fp2;
	char buf[65536], buf1[65536], buf2[65536];
	size_t nread;

	char cmd[1024];
	char fn[256];
	char kargs[256];
	char logname[256], *envstr, *groups;

	int cpus[4];
	int num_cpus;

	struct ihk_mem_chunk mem_chunks[4];
	int num_mem_chunks;
	int indices[2];
	int num_os_instances;
	ssize_t kmsg_size;
	struct ihk_ikc_cpu_map ikc_map[2];
	int num_numa_nodes;
	unsigned long memfree[4];
	int num_pgsizes;
	long pgsizes[3];
	struct ihk_os_rusage rusage;
	char *retstr;
	int boot_shutdown = 0;
	int mcexec_shutdown = 0;
	int ikc_map_by_func = 0;
	int opt;

	while ((opt = getopt(argc, argv, "bxm")) != -1) {
		switch (opt) {
		case 'b':
			boot_shutdown = 1;
			break;
		case 'x':
			mcexec_shutdown = 1;
			break;
		case 'm':
			ikc_map_by_func = 1;
			break;
		default: /* '?' */
			printf("unknown option %c\n", optopt);
			exit(1);
		}
	}


	fp = popen("logname", "r");
	nread = fread(logname, 1, sizeof(logname), fp);
	CHKANDJUMP(nread == 0, -1, "%s: ERROR: fread\n",
		   __func__);
	retstr = strrchr(logname, '\n');
	if (retstr) {
		*retstr = 0;
	}
	printf("logname=%s\n", logname);

	envstr = getenv("MYGROUPS");
	CHKANDJUMP(envstr == NULL, -1, "%s: ERROR: MYGROUPS not defined\n",
		   __func__);
	groups = strdup(envstr);
	retstr = strrchr(groups, '\n');
	if (retstr) {
		*retstr = 0;
	}
	printf("groups=%s\n", groups);

	if (geteuid() != 0) {
		printf("Execute as a root\n");
	}

#if 0
	// ihk_os_destroy_pseudofs
	ret = ihk_os_destroy_pseudofs(0, 0, 0);
	fp = popen("cat /proc/mounts | grep /tmp/mcos/mcos0_sys", "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(ret == 0 &&
	     strstr(buf, "/tmp/mcos/mcos0_sys") == NULL,
	     "ihk_os_destroy_pseudofs (1)\n");
#endif

	/* Test error handling */

	// reserve cpu
	cpus[0] = 3;
	cpus[2] = 1;
	num_cpus = 2;
	ret = ihk_reserve_cpu(0, cpus, num_cpus);
	OKNG(ret != 0, "ihk_reserve_cpu (1)\n");

	// get # of reserved cpus
	num_cpus = ihk_get_num_reserved_cpus(0);
	//printf("num_cpus=%d\n", num_cpus);
	OKNG(num_cpus < 0, "ihk_get_num_reserved_cpu (1)\n");

	// get reserved cpus
	ret = ihk_query_cpu(0, cpus, 1);
	OKNG(ret != 0, "ihk_query_cpu (1)\n");

	// release cpu
	cpus[0] = 1;
	num_cpus = 1;
	ret = ihk_release_cpu(0, cpus, num_cpus);
	OKNG(ret != 0, "ihk_release_cpu (1)\n");

	// reserve mem 128m@0,64m@0: expected to fail
	num_mem_chunks = 2;
	mem_chunks[0].size = 128*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	mem_chunks[1].size = 64*1024*1024ULL;
	mem_chunks[1].numa_node_number = 0;
	ret = ihk_reserve_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret != 0, "ihk_reserve_mem w/o /dev/mcd0\n");

	// get # of reserved mem chunks: exptected to fail
	num_mem_chunks = ihk_get_num_reserved_mem_chunks(0);
	OKNG(num_mem_chunks < 0,
	     "ihk_get_num_reserved_mem_chunks w/o /dev/mcd0\n");

	// get reserved mem chunks: exptected to fail
	ret = ihk_query_mem(0, mem_chunks, 1);
	OKNG(ret != 0, "ihk_query_mem (1)\n");

	// release mem 128m@0: expected to fail
	num_mem_chunks = 1;
	mem_chunks[0].size = 128*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	ret = ihk_release_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret != 0, "ihk_release_mem w/o /dev/mcd0\n");

	// create
	ret = ihk_create_os(0);
	OKNG(ret != 0, "ihk_create_os (1)\n");

	// get # of OS instances
	num_os_instances = ihk_get_num_os_instances(0);
	//printf("num_os_instances=%d\n", num_os_instances);
	OKNG(num_os_instances < 0, "ihk_get_num_os_instances (1)\n");

	// get OS instances
	ret = ihk_get_os_instances(0, indices, 1);
	OKNG(ret != 0, "ihk_get_os_instances (1)\n");

	// get os_instances
	sprintf(cmd, "%s/sbin/ihkconfig 0 get os_instances", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "0") == NULL,
	     "ihkconfig 0 get os_instances (1) returned:\n%s\n", buf);

	// destroy
	ret = ihk_destroy_os(0, 0);
	OKNG(ret != 0, "ihk_destroy_os (1)\n");

	/* Expected to succeed */

	sprintf(cmd, "insmod %s/kmod/ihk.ko", MCK_DIR);
	status = system(cmd);
	CHKANDJUMP(WEXITSTATUS(status) != 0, -1, "system");

	sprintf(cmd,
		"insmod %s/kmod/ihk-smp-%s.ko %s",
		MCK_DIR, ARCH, PART_MOD_PARAM);
	status = system(cmd);
	CHKANDJUMP(WEXITSTATUS(status) != 0, -1, "system");

	sprintf(cmd, "chown %s:%s /dev/mcd*\n", logname, groups);
	printf("%s\n", cmd);
	status = system(cmd);
	CHKANDJUMP(WEXITSTATUS(status) != 0, -1, "system");

	sprintf(cmd, "insmod %s/kmod/mcctrl.ko", MCK_DIR);
	status = system(cmd);
	CHKANDJUMP(WEXITSTATUS(status) != 0, -1, "system");

	// reserve cpu
	cpus[0] = 3;
	cpus[1] = 1;
	num_cpus = 2;
	ret = ihk_reserve_cpu(0, cpus, num_cpus);
	OKNG(ret == 0, "ihk_reserve_cpu\n");

	// get # of reserved cpus
	num_cpus = ihk_get_num_reserved_cpus(0);
	OKNG(num_cpus == 2, "ihk_get_num_reserved_cpu (2)\n");

	// get reserved cpus. Note that cpu# is sorted in ihk.
	ret = ihk_query_cpu(0, cpus, num_cpus);
	OKNG(ret == 0 &&
	     cpus[0] == 1 &&
	     cpus[1] == 3, "ihk_query_cpu (2)\n");

	// release cpu
	cpus[0] = 1;
	num_cpus = 1;
	ret = ihk_release_cpu(0, cpus, num_cpus);
	OKNG(ret == 0, "ihk_release_cpu (2)\n");

	// get # of reserved cpus
	num_cpus = ihk_get_num_reserved_cpus(0);
	OKNG(num_cpus == 1, "ihk_get_num_reserved_cpu (3)\n");

	// get reserved cpus
	ret = ihk_query_cpu(0, cpus, num_cpus);
	OKNG(ret == 0 &&
	     cpus[0] == 3, "ihk_query_cpu (3)\n");

	// reserve cpu
	cpus[0] = 1;
	num_cpus = 1;
	ret = ihk_reserve_cpu(0, cpus, num_cpus);
	OKNG(ret == 0, "ihk_reserve_cpu\n");

	// get # of reserved cpus
	num_cpus = ihk_get_num_reserved_cpus(0);
	OKNG(num_cpus == 2, "ihk_get_num_reserved_cpu (3)\n");

	// get reserved cpus. Note that cpu# is sorted in ihk.
	ret = ihk_query_cpu(0, cpus, num_cpus);
	OKNG(ret == 0 &&
	     cpus[0] == 1 &&
	     cpus[1] == 3, "ihk_query_cpu (4)\n");

	// reserve mem 128m@0,64m@0
	num_mem_chunks = 2;
	mem_chunks[0].size = 128*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	mem_chunks[1].size = 64*1024*1024ULL;
	mem_chunks[1].numa_node_number = 0;
	ret = ihk_reserve_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0, "ihk_reserve_mem\n");

	// get # of reserved mem chunks
	num_mem_chunks = ihk_get_num_reserved_mem_chunks(0);
	OKNG(num_mem_chunks == 2, "ihk_get_num_reserved_mem_chunks\n");

	// get reserved mem chunks
	ret = ihk_query_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0 &&
	     ((mem_chunks[0].size == 128*1024*1024ULL &&
	       mem_chunks[0].numa_node_number == 0 &&
	       mem_chunks[1].size == 64*1024*1024ULL &&
	       mem_chunks[1].numa_node_number == 0) ||
	      (mem_chunks[0].size == 64*1024*1024ULL &&
	       mem_chunks[0].numa_node_number == 0 &&
	       mem_chunks[1].size == 128*1024*1024ULL &&
	       mem_chunks[1].numa_node_number == 0)), "ihk_query_mem (2)\n");

	// release mem 128m@0
	num_mem_chunks = 1;
	mem_chunks[0].size = 128*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	ret = ihk_release_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0, "ihk_release_mem w/o /dev/mcd0\n");

	// get # of reserved mem chunks
	num_mem_chunks = ihk_get_num_reserved_mem_chunks(0);
	OKNG(num_mem_chunks == 1, "ihk_get_num_reserved_mem_chunks\n");

	// get reserved mem chunks
	ret = ihk_query_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0 &&
	     mem_chunks[0].size == 64*1024*1024ULL &&
	     mem_chunks[0].numa_node_number == 0, "ihk_query_mem (3)\n");

	// reserve mem 128m@0
	num_mem_chunks = 1;
	mem_chunks[0].size = 128*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	ret = ihk_reserve_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0, "ihk_reserve_mem\n");

	// get # of reserved mem chunks
	num_mem_chunks = ihk_get_num_reserved_mem_chunks(0);
	OKNG(num_mem_chunks == 2, "ihk_get_num_reserved_mem_chunks\n");

	// get reserved mem chunks
	ret = ihk_query_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0 &&
	     ((mem_chunks[0].size == 128*1024*1024ULL &&
	       mem_chunks[0].numa_node_number == 0 &&
	       mem_chunks[1].size == 64*1024*1024ULL &&
	       mem_chunks[1].numa_node_number == 0) ||
	      (mem_chunks[0].size == 64*1024*1024ULL &&
	       mem_chunks[0].numa_node_number == 0 &&
	       mem_chunks[1].size == 128*1024*1024ULL &&
	       mem_chunks[1].numa_node_number == 0)), "ihk_query_mem (3)\n");

	/* Test error handling */

	// assign cpu 3,1
	num_cpus = 2;
	cpus[0] = 3;
	cpus[1] = 1;
	ret = ihk_os_assign_cpu(0, cpus, num_cpus);
	OKNG(ret != 0, "ihk_os_assign_cpu\n");

	// get # of assigned cpus
	num_cpus = ihk_os_get_num_assigned_cpus(0);
	OKNG(num_cpus < 0, "ihk_os_get_num_assigned_cpus\n");

	// get assigned cpus
	ret = ihk_os_query_cpu(0, cpus, 2);
	OKNG(ret != 0, "ihk_os_query_cpu (4)\n");

	// release cpu
	num_cpus = 1;
	cpus[0] = 1;
	ret = ihk_os_release_cpu(0, cpus, num_cpus);
	OKNG(ret != 0, "ihk_os_release_cpu (1)\n");

	// assign mem 128m@0,64m@0
	num_mem_chunks = 2;
	mem_chunks[0].size = 128*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	mem_chunks[1].size = 64*1024*1024ULL;
	mem_chunks[1].numa_node_number = 0;
	ret = ihk_os_assign_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret != 0, "ihk_os_assign_mem (1)\n");

	// get # of assigned mem chunks
	num_mem_chunks = ihk_os_get_num_assigned_mem_chunks(0);
	OKNG(num_mem_chunks < 0, "ihk_os_get_num_assigned_mem_chunks\n");

	// get assigned mem chunks
	ret = ihk_os_query_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret != 0, "ihk_os_query_mem (1)\n");

	// release mem chunks
	num_mem_chunks = 1;
	mem_chunks[0].size = 64*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	ret = ihk_os_release_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret != 0, "ihk_os_release_mem\n");

	if (ikc_map_by_func) {
		// set ikc_map
		ikc_map[0].src_cpu = 3;
		ikc_map[0].dst_cpu = 0;
		ikc_map[0].src_cpu = 1;
		ikc_map[0].dst_cpu = 2;
		ret = ihk_os_set_ikc_map(0, ikc_map, 2);
		OKNG(ret != 0, "ihk_os_set_ikc_map\n");

		// get ikc_map
		ret = ihk_os_get_ikc_map(0, ikc_map, 2);
		OKNG(ret != 0, "ihk_os_get_ikc_map (1)\n");
	} else {
		// set ikc_map
		sprintf(cmd, "%s/sbin/ihkosctl 0 set ikc_map 3:0+1:2 2>&1",
			MCK_DIR);
		fp = popen(cmd, "r");
		nread = fread(buf, 1, sizeof(buf), fp);
		buf[nread] = 0;
		OKNG(strstr(buf, "rror") != NULL,
		     "ihkconfig 0 set ikc_map (1)\n");

		// get ikc_map
		sprintf(cmd, "%s/sbin/ihkosctl 0 get ikc_map 2>&1",
			MCK_DIR);
		fp = popen(cmd, "r");
		nread = fread(buf, 1, sizeof(buf), fp);
		buf[nread] = 0;
		OKNG(strstr(buf, "3:0+1:2") == NULL,
		     "ihkconfig 0 get ikc_map (1) returned:\n%s\n", buf);
	}

	// load
	sprintf(fn, "%s/%s/kernel/mckernel.img",
		MCK_DIR, TARGET);
	printf("%s\n", fn);
	ret = ihk_os_load(0, fn);
	OKNG(ret != 0, "ihk_os_load\n");

	// kargs
	sprintf(kargs, "hidos ksyslogd=0");
	ret = ihk_os_kargs(0, kargs);
	OKNG(ret != 0, "ihk_os_kargs\n");

	// boot
	ret = ihk_os_boot(0);
	OKNG(ret != 0, "ihk_os_boot\n");

	// get status
	ret = ihk_os_get_status(0);
	OKNG(ret < 0, "ihk_os_get_status (1)\n");

	// get status
	sprintf(cmd, "%s//sbin/ihkosctl 0 get status 2>&1", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "rror") != NULL,
	     "ihkconfig 0 get status (1) returned:\n%s\n", buf);

	// create pseudofs
	ret = ihk_os_create_pseudofs(0, 0, 0);
	OKNG(ret != 0, "ihk_os_create_pseudofs\n");

	// kmsg size
	kmsg_size = ihk_os_get_kmsg_size(0);
	OKNG(kmsg_size < 0, "ihk_os_get_kmsg_size\n");

	// get kmsg
	ret = ihk_os_kmsg(0, buf, 256);
	OKNG(ret != 0, "ihk_os_kmsg returns %d\n", ret);

	// clear kmsg
	ret = ihk_os_clear_kmsg(0);
	OKNG(ret != 0, "ihk_os_clear_kmsg\n");

	// get # of NUMA nodes
	num_numa_nodes = ihk_os_get_num_numa_nodes(0);
	OKNG(num_numa_nodes < 0, "ihk_os_get_num_numa_nodes\n");

	// query_free_mem
	ret = ihk_os_query_free_mem(0, memfree, num_numa_nodes);
	OKNG(ret != 0, "ihk_os_query_free_mem\n");

	// get # of page sizes
	num_pgsizes = ihk_os_get_num_pagesizes(0);
	OKNG(num_pgsizes < 0, "ihk_os_get_num_pagesizes\n");

	// get page sizes
	ret = ihk_os_get_pagesizes(0, pgsizes, num_pgsizes);
	OKNG(ret != 0, "ihk_os_get_pagesizes\n");

	// get rusage
	ret = ihk_os_getrusage(0, &rusage, sizeof(rusage));
	OKNG(ret != 0, "ihk_os_getrusage\n");

	// shutdown
	ret = ihk_os_shutdown(0);
	OKNG(ret != 0, "ihk_os_shutdown (1)\n");

	// destroy os
	ret = ihk_destroy_os(0, 0);
	OKNG(ret != 0, "ihk_destroy_os (2)\n");

	// destroy pseudofs. Note that it doesn't check the existence
	// of the OS.
	ret = ihk_os_destroy_pseudofs(0, 0, 0);
	OKNG(ret == 0, "ihk_os_destroy_pseudofs (2)\n");

	/* Expected to succeed */

	// create 0
	ret = ihk_create_os(0);
	OKNG(ret == 0, "ihk_create_os (2)\n");
#if 0
	// create 1
	ret = ihk_create_os(0);
	OKNG(ret == 1, "ihk_create_os (3)\n");

	// get # of OS instances
	num_os_instances = ihk_get_num_os_instances(0);
	OKNG(num_os_instances == 2, "ihk_get_num_os_instances (2)\n");

	// get OS instances. Note that the index of the youngest OS
	// instance resides in [0].
	ret = ihk_get_os_instances(0, indices, num_os_instances);
	OKNG(ret == 0 &&
	     indices[0] == 1 &&
	     indices[1] == 0, "ihk_get_os_instances (2)\n");

	// get os_instances
	sprintf(cmd, "%s//sbin/ihkconfig 0 get os_instances", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "0") != NULL && strstr(buf, "1") != NULL,
	     "ihkconfig 0 get os_instances (2) returned:\n%s\n", buf);

	// destroy one of them
	ret = ihk_destroy_os(0, 1);
	OKNG(ret == 0, "ihk_destroy_os (3)\n");

#else
	// get # of OS instances
	num_os_instances = ihk_get_num_os_instances(0);
	OKNG(num_os_instances == 1, "ihk_get_num_os_instances (2)\n");

	// get OS instances. Note that the index of the youngest OS
	// instance resides in [0].
	ret = ihk_get_os_instances(0, indices, num_os_instances);
	OKNG(ret == 0 &&
	     indices[0] == 0, "ihk_get_os_instances (2)\n");

	// get os_instances
	sprintf(cmd, "%s//sbin/ihkconfig 0 get os_instances", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "0") != NULL,
	     "ihkconfig 0 get os_instances (3) returned:\n%s\n", buf);
#endif

	// get status
	ret = ihk_os_get_status(0);
	OKNG(ret == IHK_STATUS_INACTIVE, "ihk_os_get_status (2)\n");

	// get status
	sprintf(cmd, "%s/sbin/ihkosctl 0 get status 2>&1", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "INACTIVE") != NULL,
	     "ihkconfig 0 get status (2) returned:\n%s\n", buf);

	sprintf(cmd, "chown %s:%s /dev/mcos*\n", logname, groups);
	status = system(cmd);
	CHKANDJUMP(WEXITSTATUS(status) != 0, -1, "system");

	// assign cpu 3,1
	num_cpus = 2;
	cpus[0] = 3;
	cpus[1] = 1;
	ret = ihk_os_assign_cpu(0, cpus, num_cpus);
	OKNG(ret == 0, "ihk_os_assign_cpu\n");

	// get # of assigned cpus
	num_cpus = ihk_os_get_num_assigned_cpus(0);
	OKNG(num_cpus == 2, "ihk_os_get_num_assigned_cpus\n");

	// get assigned cpus
	ret = ihk_os_query_cpu(0, cpus, num_cpus);
	OKNG(ret == 0 &&
	     cpus[0] == 3 &&
	     cpus[1] == 1, "ihk_os_query_cpu (5)\n");

	// release cpu
	num_cpus = 1;
	cpus[0] = 3;
	ret = ihk_os_release_cpu(0, cpus, num_cpus);
	OKNG(ret == 0, "ihk_os_release_cpu (2)\n");

	// get # of assigned cpus
	num_cpus = ihk_os_get_num_assigned_cpus(0);
	OKNG(num_cpus == 1, "ihk_os_get_num_assigned_cpus\n");

	// get assigned cpus
	ret = ihk_os_query_cpu(0, cpus, num_cpus);
	OKNG(ret == 0 &&
	     cpus[0] == 1, "ihk_os_query_cpu (6)\n");

	// release cpu
	num_cpus = 1;
	cpus[0] = 1;
	ret = ihk_os_release_cpu(0, cpus, num_cpus);
	OKNG(ret == 0, "ihk_os_release_cpu (3)\n");

	// assign cpu 3,1
	num_cpus = 2;
	cpus[0] = 3;
	cpus[1] = 1;
	ret = ihk_os_assign_cpu(0, cpus, num_cpus);
	OKNG(ret == 0, "ihk_os_assign_cpu\n");

	if (ikc_map_by_func) {
		// set ikc_map
		ikc_map[0].src_cpu = 3;
		ikc_map[0].dst_cpu = 0;
		ikc_map[1].src_cpu = 1;
		ikc_map[1].dst_cpu = 2;
		ret = ihk_os_set_ikc_map(0, ikc_map, num_cpus);
		OKNG(ret == 0, "ihk_os_set_ikc_map\n");

		// get ikc_map
		ret = ihk_os_get_ikc_map(0, ikc_map, num_cpus);
		OKNG(ret == 0 &&
		     ikc_map[0].src_cpu == 3 &&
		     ikc_map[0].dst_cpu == 0 &&
		     ikc_map[1].src_cpu == 1 &&
		     ikc_map[1].dst_cpu == 2, "ihk_os_get_ikc_map (2)\n");
	} else {
		// set ikc_map
		sprintf(cmd, "%s/sbin/ihkosctl 0 set ikc_map 3:0+1:2 2>&1",
			MCK_DIR);
		fp = popen(cmd, "r");
		nread = fread(buf, 1, sizeof(buf), fp);
		buf[nread] = 0;
		OKNG(strstr(buf, "rror") == NULL,
		     "ihkconfig 0 set ikc_map (2)\n");

		// get ikc_map
		sprintf(cmd, "%s/sbin/ihkosctl 0 get ikc_map 2>&1",
			MCK_DIR);
		fp = popen(cmd, "r");
		nread = fread(buf, 1, sizeof(buf), fp);
		buf[nread] = 0;
		OKNG(strstr(buf, "3:0+1:2") != NULL,
		     "ihkconfig 0 get ikc_map (2) returned:\n%s\n", buf);
	}

	// assign mem 128m@0,64m@0
	num_mem_chunks = 2;
	mem_chunks[0].size = 128*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	mem_chunks[1].size = 64*1024*1024ULL;
	mem_chunks[1].numa_node_number = 0;
	ret = ihk_os_assign_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0, "ihk_os_assign_mem (2)\n");

	// get # of assigned mem chunks
	num_mem_chunks = ihk_os_get_num_assigned_mem_chunks(0);
	OKNG(num_mem_chunks == 2, "ihk_os_get_num_assigned_mem_chunks\n");

	// get assigned mem chunks
	ret = ihk_os_query_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0 &&
	     ((mem_chunks[0].size == 128*1024*1024ULL &&
	       mem_chunks[0].numa_node_number == 0 &&
	       mem_chunks[1].size == 64*1024*1024ULL &&
	       mem_chunks[1].numa_node_number == 0) ||
	      (mem_chunks[0].size == 64*1024*1024ULL &&
	       mem_chunks[0].numa_node_number == 0 &&
	       mem_chunks[1].size == 128*1024*1024ULL &&
	       mem_chunks[1].numa_node_number == 0)), "ihk_os_query_mem (2)\n");

	// release mem chunks
	num_mem_chunks = 1;
	mem_chunks[0].size = 64*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	ret = ihk_os_release_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0, "ihk_os_release_mem\n");

	// get # of assigned mem chunks
	num_mem_chunks = ihk_os_get_num_assigned_mem_chunks(0);
	OKNG(num_mem_chunks == 1, "ihk_os_get_num_assigned_mem_chunks\n");

	// get assigned mem chunks
	ret = ihk_os_query_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0 &&
	     mem_chunks[0].size == 128*1024*1024ULL &&
	     mem_chunks[0].numa_node_number == 0, "ihk_os_query_mem (3)\n");

	// assign mem 64m@0
	num_mem_chunks = 1;
	mem_chunks[0].size = 64*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	ret = ihk_os_assign_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0, "ihk_os_assign_mem (3)\n");

	// get # of assigned mem chunks
	num_mem_chunks = ihk_os_get_num_assigned_mem_chunks(0);
	OKNG(num_mem_chunks == 2, "ihk_os_get_num_assigned_mem_chunks\n");

	// get assigned mem chunks
	ret = ihk_os_query_mem(0, mem_chunks, num_mem_chunks);
	OKNG(ret == 0 &&
	     ((mem_chunks[0].size == 128*1024*1024ULL &&
	       mem_chunks[0].numa_node_number == 0 &&
	       mem_chunks[1].size == 64*1024*1024ULL &&
	       mem_chunks[1].numa_node_number == 0) ||
	      (mem_chunks[0].size == 64*1024*1024ULL &&
	       mem_chunks[0].numa_node_number == 0 &&
	       mem_chunks[1].size == 128*1024*1024ULL &&
	       mem_chunks[1].numa_node_number == 0)),
	     "ihk_os_query_mem (4)\n");

	// load
	sprintf(fn, "%s/%s/kernel/mckernel.img",
		MCK_DIR, TARGET);
	printf("%s\n", fn);
	ret = ihk_os_load(0, fn);
	OKNG(ret == 0, "ihk_os_load\n");

	// kargs
	sprintf(kargs, "hidos ksyslogd=0");
	ret = ihk_os_kargs(0, kargs);
	OKNG(ret == 0, "ihk_os_kargs\n");

	// boot
	ret = ihk_os_boot(0);
	OKNG(ret == 0, "ihk_os_boot\n");
	if (boot_shutdown) { /* #898 */
		goto shutdown;
	}

	// get status
	ret = ihk_os_get_status(0);
	OKNG(ret == IHK_STATUS_BOOTING ||
	     ret == IHK_STATUS_RUNNING, "ihk_os_get_status (3)\n");

	// get status
	sprintf(cmd, "%s/sbin/ihkosctl 0 get status 2>&1", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "BOOTING") != NULL ||
	     strstr(buf, "RUNNING") != NULL,
	     "ihkconfig 0 get status (3) returned:\n%s\n", buf);

	/* Make sure that all initialization related transactions
	 * between McKernel and IHK finish
	 * sysfs_init(void) (in mckernel/kernel/sysfs.c)
	 * packet.msg = SCD_MSG_SYSFS_REQ_SETUP;
	 * sysfsm_work_main() in (mckernel/executer/kernel/mcctrl/sysfs.c)
	 * sysfsm_req_setup
	 * sysfsm_setup
	 */
	usleep(100*1000);

	// get status
	ret = ihk_os_get_status(0);
	OKNG(ret == IHK_STATUS_RUNNING, "ihk_os_get_status (4)\n");

	// get status
	sprintf(cmd, "%s/sbin/ihkosctl 0 get status 2>&1", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "RUNNING") != NULL,
	     "ihkconfig 0 get status (4) returned:\n%s\n", buf);

#if 0
	// create pseudofs
	ret = ihk_os_create_pseudofs(0, 0, 0);
	fp = popen("cat /proc/mounts | grep /tmp/mcos/mcos0_sys", "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(ret == 0 &&
	     strstr(buf, "/tmp/mcos/mcos0_sys") != NULL,
	     "ihk_os_create_pseudofs()\n");
#endif

	// get kmsg size
	kmsg_size = ihk_os_get_kmsg_size(0);
	OKNG(kmsg_size > 0, "ihk_os_get_kmsg_size\n");

	// get kmsg
	ret = ihk_os_kmsg(0, buf, kmsg_size);
	OKNG(ret > 0 &&
	     strstr(buf, "IHK/McKernel started.") != NULL, "ihk_os_kmsg\n");

	// clear kmsg
	ret = ihk_os_clear_kmsg(0);
	OKNG(ret == 0, "ihk_os_clear_kmsg\n");

#if 0
	// get kmsg
	ret = ihk_os_kmsg(0, buf, kmsg_size);
	printf("%s,%d", strstr(buf, "IHK/McKernel started."), ret);
	OKNG(ret == 0 &&
	     strstr(buf, "IHK/McKernel started.") == NULL,
	     "ihk_os_kmsg returns %d\n", ret);
#endif

	// mcexec
	sprintf(cmd, "%s/bin/mcexec ls -l | grep Makefile", MCK_DIR);
	if (mcexec_shutdown) { /* #928 */
		status = system(cmd);
		goto shutdown;
	}
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "Makefile") != NULL, "mcexec\n");

	// /proc
	sprintf(cmd, "%s/bin/mcexec cat /proc/stat", MCK_DIR);
	fp1 = popen(cmd, "r");
	nread = fread(buf1, 1, sizeof(buf1), fp1);
	buf1[nread] = 0;
	fp2 = popen("cat /proc/stat", "r");
	nread = fread(buf2, 1, sizeof(buf2), fp2);
	buf2[nread] = 0;
	OKNG(strcmp(buf1, buf2) != 0, "mcexec cat /proc/stat\n");

	// get # of NUMA nodes
	num_numa_nodes = ihk_os_get_num_numa_nodes(0);
	OKNG(num_numa_nodes > 0, "ihk_os_get_num_numa_nodes\n");

	// query_free_mem
	ret = ihk_os_query_free_mem(0, memfree, num_numa_nodes);
	OKNG(ret == 0 &&
		 memfree[0] > 0, "ihk_os_query_free_mem\n");

	// get # of page sizes
	num_pgsizes = ihk_os_get_num_pagesizes(0);
	OKNG(num_pgsizes == 3, "ihk_os_get_num_pagesizes\n");

	// get page sizes
	ret = ihk_os_get_pagesizes(0, pgsizes, num_pgsizes);
	OKNG(ret == 0 &&
		 pgsizes[0] == (1ULL<<12) &&
		 pgsizes[1] == (1ULL<<21) &&
		 pgsizes[2] == (1ULL<<30), "ihk_os_get_pagesizes\n");
#if 1
	// shutdown
	// usleep(250*1000); // Wait for nothing is in-flight
 shutdown:
	ret = ihk_os_shutdown(0);
	OKNG(ret == 0, "ihk_os_shutdown (2)\n");

	// get status. Note that the smp_ihk_os_shutdown() transitions
	// smp-x86 status to BUILTIN_OS_STATUS_SHUTDOWN
	// and smp_ihk_os_query_status() transitions os status to
	// IHK_OS_STATUS_NOT_BOOTED.
	ret = ihk_os_get_status(0);
	OKNG(ret == IHK_STATUS_SHUTDOWN ||
	     ret == IHK_STATUS_INACTIVE,
	     "ihk_os_get_status (5) returned %d\n", ret);

	// get status
	sprintf(cmd, "%s/sbin/ihkosctl 0 get status 2>&1", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "SHUTDOWN") != NULL ||
	     strstr(buf, "INACTIVE") != NULL,
	     "ihkconfig 0 get status (5) returned:\n%s\n", buf);
#endif

#if 1
	// destroy os
	usleep(250*1000); // Wait for nothing is in-flight
	ret = ihk_destroy_os(0, 0);
	OKNG(ret == 0, "ihk_destroy_os (4)\n");
#else
	// destroy os
	usleep(250*1000); // Wait for nothing is in-flight
	sprintf(cmd, "%s/sbin/ihkconfig 0 destroy 0 2>&1", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "rror") == NULL,
	     "ihkconfig 0 destroy 0 returned:\n%s\n", buf);
#endif

	// get # of OS instances
	num_os_instances = ihk_get_num_os_instances(0);
	OKNG(num_os_instances == 0, "ihk_get_num_os_instances (3)\n");

	// get OS instances
	ret = ihk_get_os_instances(0, indices, num_os_instances);
	OKNG(ret == 0, "ihk_get_os_instances (3)\n");

	// get os_instances
	sprintf(cmd, "%s/sbin/ihkconfig 0 get os_instances", MCK_DIR);
	fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "0") == NULL,
	     "ihkconfig 0 get os_instances (4) returned:\n%s\n", buf);

	sprintf(cmd, "rmmod %s/kmod/mcctrl.ko", MCK_DIR);
	status = system(cmd);
	CHKANDJUMP(WEXITSTATUS(status) != 0, -1, "system");

	// destroy pseudofs
	ret = ihk_os_destroy_pseudofs(0, 0, 0);
	fp = popen("cat /proc/mounts | grep /tmp/mcos/mcos0_sys", "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(ret == 0 &&
	     strstr(buf, "/tmp/mcos/mcos0_sys") == NULL,
	     "ihk_os_destroy_pseudofs (3)\n");

	sprintf(cmd, "rmmod %s/kmod/ihk-smp-%s.ko",
		MCK_DIR, ARCH);
	status = system(cmd);
	CHKANDJUMP(WEXITSTATUS(status) != 0, -1, "system");

	sprintf(cmd, "rmmod %s/kmod/ihk.ko", MCK_DIR);
	status = system(cmd);
	CHKANDJUMP(WEXITSTATUS(status) != 0, -1, "system");

	printf("[INFO] All tests finished\n");
	ret = 0;

 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
