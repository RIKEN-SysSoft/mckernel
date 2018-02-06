#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ihklib.h>
#include <sys/types.h>

#define MCK_DIR "/home/satoken/ppos"
static char prefix[256] = MCK_DIR;

static char test_name[64] = "CT_009";

#define OKNG(cond, ...)													\
    do {                                                                \
		if(cond) {                                                      \
			printf("[OK] ");											\
			printf(__VA_ARGS__);										\
		} else {														\
            printf("[NG] ");											\
			printf(__VA_ARGS__);										\
			char buf[65536];\
			char cmd[256];\
			sprintf(cmd, "%s/sbin/ihkosctl 0 kmsg", prefix);\
			FILE* fp = popen(cmd, "r");		\
			size_t nread = fread(buf, 1, sizeof(buf), fp);				\
			buf[nread] = 0;												\
			printf("%s", buf);											\
			goto fn_fail;												\
		}																\
    } while(0)

int main(int argc, char** argv) {
    int ret = 0, status, ret_ihklib;
	FILE *fp;
	char buf[65536];
	size_t nread;

	char cmd[1024];
	char fn[256];
	char kargs[256];

	int cpus[4] = {6, 7, 8, 9};
	int num_cpus = 4;

	struct ihk_mem_chunk mem_chunks[4];
	int num_mem_chunks;

	printf("*** %s start *************************\n", test_name);
	/*--------------------------------------------
	 * Preparing                                  
	 *--------------------------------------------*/
	sprintf(cmd, "%s/sbin/mcstop+release.sh", prefix);
	status = system(cmd);

	// ihk_os_destroy_pseudofs
	ret_ihklib = ihk_os_destroy_pseudofs(0);
	fp = popen("cat /proc/mounts | grep /tmp/mcos/mcos0_sys", "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;

	sprintf(cmd, "insmod %s/kmod/ihk.ko", prefix);
	status = system(cmd);

	sprintf(cmd, "insmod %s/kmod/ihk-smp-x86_64.ko ihk_start_irq=240 ihk_ikc_irq_core=0", prefix);
	status = system(cmd);

	sprintf(cmd, "insmod %s/kmod/mcctrl.ko", prefix);
	status = system(cmd);

	/*--------------------------------------------
	 * Test                                  
	 *--------------------------------------------*/
	// create 0
    ret_ihklib = ihk_create_os(0);

	// reserve cpus
	ret_ihklib = ihk_reserve_cpu(0, cpus, num_cpus);
	//OKNG(ret_ihklib == 0, "ihk_reserve_cpu\n");

	// assign cpus
    ret_ihklib = ihk_os_assign_cpu(0, cpus, num_cpus);
    //OKNG(ret_ihklib == 0, "ihk_os_assign_cpu\n");

	// reserve mem 128m@0,128m@1
	num_mem_chunks = 2;
	mem_chunks[0].size = 128*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	mem_chunks[1].size = 128*1024*1024ULL;
	mem_chunks[1].numa_node_number = 1;
    ret_ihklib = ihk_reserve_mem(0, mem_chunks, num_mem_chunks);
    //OKNG(ret_ihklib == 0, "ihk_reserve_mem (2)\n");

	// assign mem 128m@0,128m@1
	num_mem_chunks = 2;
	mem_chunks[0].size = 128*1024*1024ULL;
	mem_chunks[0].numa_node_number = 0;
	mem_chunks[1].size = 128*1024*1024ULL;
	mem_chunks[1].numa_node_number = 1;
    ret_ihklib = ihk_os_assign_mem(0, mem_chunks, num_mem_chunks);
    //OKNG(ret_ihklib == 0, "ihk_os_assign_mem (2)\n");

	// load
	sprintf(fn, "%s/smp-x86/kernel/mckernel.img", prefix);
    ret_ihklib = ihk_os_load(0, fn);
	//OKNG(ret_ihklib == 0, "ihk_os_load\n");

	// kargs
	sprintf(kargs, "hidos ksyslogd=0");
    ret_ihklib = ihk_os_kargs(0, kargs);
	//OKNG(ret_ihklib == 0, "ihk_os_kargs\n");

	// boot
    ret_ihklib = ihk_os_boot(0);
goto shutdown;
	OKNG(ret_ihklib == 0, "ihk_os_boot\n");

	/* Make sure that all initialization related transactions between McKernel and IHK finish
	   sysfs_init(void) (in mckernel/kernel/sysfs.c)
	   packet.msg = SCD_MSG_SYSFS_REQ_SETUP;
	   sysfsm_work_main() in (mckernel/executer/kernel/mcctrl/sysfs.c)
       sysfsm_req_setup
       sysfsm_setup */
	usleep(100*1000);

	// create pseudofs
	ret_ihklib = ihk_os_create_pseudofs(0);
	fp = popen("cat /proc/mounts | grep /tmp/mcos/mcos0_sys", "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	//OKNG(ret_ihklib == 0 &&
	//	 strstr(buf, "/tmp/mcos/mcos0_sys") != NULL, "ihk_os_create_pseudofs()\n");

	// mcexec
	sprintf(cmd, "%s/bin/mcexec ls -l | grep Makefile", prefix);
    fp = popen(cmd, "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;
	OKNG(strstr(buf, "Makefile") != NULL, "mcexec\n");

	// shutdown
shutdown:
    ret_ihklib = ihk_os_shutdown(0);
	OKNG(ret_ihklib == 0, "force shutdown immediately after boot returned 0\n");

	// get status. Note that the smp_ihk_os_shutdown() transitions 
	// smp-x86 status to BUILTIN_OS_STATUS_SHUTDOWN
	// and smp_ihk_os_query_status() transitions os status to IHK_OS_STATUS_NOT_BOOTED.
	ret_ihklib = ihk_os_get_status(0);
	//OKNG(ret_ihklib == IHK_STATUS_SHUTDOWN ||
	//	 ret_ihklib == IHK_STATUS_INACTIVE, "ihk_os_get_status (5) returned %d\n", ret_ihklib);

destroy:
    ret_ihklib = ihk_destroy_os(0, 0);
	//OKNG(ret_ihklib == 0, "destroy immediately after boot\n");

	sprintf(cmd, "rmmod %s/kmod/mcctrl.ko", prefix);
	status = system(cmd);

	// destroy pseudofs
	ret_ihklib = ihk_os_destroy_pseudofs(0);
	fp = popen("cat /proc/mounts | grep /tmp/mcos/mcos0_sys", "r");
	nread = fread(buf, 1, sizeof(buf), fp);
	buf[nread] = 0;

	sprintf(cmd, "rmmod %s/kmod/ihk-smp-x86_64.ko", prefix);
	status = system(cmd);

	sprintf(cmd, "rmmod %s/kmod/ihk.ko", prefix);
	status = system(cmd);

	printf("*** All tests finished\n\n");

 fn_exit:
    return ret;
 fn_fail:
    goto fn_exit;
}
