/**
 * \file kernel/init.c
 *  License details are found in the file LICENSE.
 * \brief
 *  main function and initializer
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 *      Copyright (C) 2012  RIKEN AICS
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 *      Copyright (C) 2012 - 2013 Hitachi, Ltd.
 * \author Balazs Gerofi  <bgerofi@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2013  The University of Tokyo
 */
/*
 * HISTORY:
 *  2013/09/02 shirasawa add terminate thread
 *  2013/06/02 balazs resolved merge conflicts with futex code
 *  2013/05/20 simin exchange the dcfa stuff init/exit order in mcexec
 */
#include <types.h>
#include <kmsg.h>
#include <kmalloc.h>
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/dma.h>
#include <ihk/perfctr.h>
#include <process.h>
#include <init.h>
#include <cls.h>
#include <syscall.h>
#include <sysfs.h>
#include <rusage.h>

//#define IOCTL_FUNC_EXTENSION
#ifdef IOCTL_FUNC_EXTENSION
#include <ioctl.h>
#endif

//#define DEBUG_PRINT_INIT

#ifdef DEBUG_PRINT_INIT
#define dkprintf(...) do { kprintf(__VA_ARGS__); } while (0)
#define ekprintf(...) do { kprintf(__VA_ARGS__); } while (0)
#else
#define dkprintf(...) do { } while (0)
#define ekprintf(...) do { kprintf(__VA_ARGS__); } while (0)
#endif

int osnum = 0;

extern struct ihk_kmsg_buf kmsg_buf;
extern unsigned long ihk_mc_get_ns_per_tsc(void);
extern long syscall(int, ihk_mc_user_context_t *);

struct ihk_os_monitor *monitor;

static void handler_init(void)
{
	ihk_mc_set_syscall_handler(syscall);
}

unsigned long data[1024] __attribute__((aligned(64)));

#ifdef USE_DMA
static void dma_test(void)
{
	struct ihk_dma_request req;
	unsigned long fin = 0;
	int i, j;

	for (j = 0; j < 2; ++j) {
		fin = 0;

		memset(data, 0, 1024 * sizeof(unsigned long));

		for (i = 0; i < 8; i++) {
			data[i] = i;
		}

		kprintf("DMA Test Started.\n");
		memset(&req, 0, sizeof(req));
		req.src_os = IHK_THIS_OS;
		req.src_phys = virt_to_phys(data);
		req.dest_os = IHK_THIS_OS;
		req.dest_phys = virt_to_phys(&data[256]);
		req.size = 64;
		req.notify = (void *)virt_to_phys(&fin);
		req.notify_os = IHK_THIS_OS;
		req.priv = (void *)0x2984;

		kprintf("VtoP : %p, %lx\n", data, virt_to_phys(data));
		kprintf("notify : %p, %lx (%lx)\n", &fin, virt_to_phys(&fin),
				sizeof(req));

		if (ihk_mc_dma_request(0, &req) != 0) {
			kprintf("Failed to request DMA!\n");
		}
		kprintf("DMA Test Wait.\n");
		while (!fin) {
			barrier();
		}
		kprintf("DMA Test End.\n");

		for (i = 0; i < 8; i++) {
			if (data[i] != data[256 + i]) {
				kprintf("DMA result is inconsistent!\n");
				panic("");
			}
		}
	}
}
#endif

extern char *ihk_get_kargs(void);

char *find_command_line(char *name)
{
	char *cmdline = ihk_get_kargs();

	if (!cmdline) {
		return NULL;
	}
	return strstr(cmdline, name);
}

static void parse_kargs(void)
{
	kprintf("KCommand Line: %s\n", ihk_get_kargs());

	if (1) {
		char *key = "osnum=";
		char *p;

		p = find_command_line(key);
		if (p != NULL) {
			p += strlen(key);
			osnum = 0;
			while (('0' <= *p) && (*p <= '9')) {
				osnum *= 10;
				osnum += *p++ - '0';
			}
			kprintf("osnum: %d\n", osnum);
		}
	}
}

void pc_init(void)
{
	int i;
	int kmode = PERFCTR_KERNEL_MODE;
	int imode = 1;
	char *p;

	int x[2][4] = { { APT_TYPE_INSTRUCTIONS_EXECUTED,
	                  APT_TYPE_DATA_READ_MISS,
	                  APT_TYPE_L2_CODE_READ_MISS_MEM_FILL,
                      APT_TYPE_CODE_CACHE_MISS, },
	                { APT_TYPE_CODE_CACHE_MISS,
                      APT_TYPE_LLC_MISS, // not updated for KNC
	                  APT_TYPE_STALL, APT_TYPE_CYCLE }, // not updated for KNC
	};


	if (!(p = find_command_line("perfctr"))) {
		dkprintf("perfctr not initialized.\n");
		return;
	}
	if (p[7] == '=' && p[8] >= '0' && p[8] <= '5') {
		i = p[8] - '0';
		kmode = (i >> 1) + 1;
		imode = (i & 1);
	} else {
		dkprintf("perfctr not initialized.\n");
		return;
	}
	dkprintf("perfctr mode : priv = %d, set = %d\n", kmode, imode);

	for (i = 0; i < 4; i++) {
		ihk_mc_perfctr_init(i, x[imode][i], kmode);
	}
	ihk_mc_perfctr_start(0xf);
}

void pc_ap_init(void)
{
	pc_init();
}

static void pc_test(void)
{
	int i;
	unsigned long st[4], ed[4];

	pc_init();

	ihk_mc_perfctr_read_mask(0xf, st);
	for (i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
		data[i] += i;
		asm volatile ("" : : : "memory");
	}
	ihk_mc_perfctr_read_mask(0xf, ed);

	kprintf("perfctr:(%ld) %ld, %ld, %ld, %ld\n", st[0], ed[0] - st[0],
	        ed[1] - st[1], ed[2] - st[2], ed[3] - st[3]);
}

extern void ihk_mc_get_boot_time(unsigned long *tv_sec, unsigned long *tv_nsec);
extern unsigned long ihk_mc_get_ns_per_tsc(void);

static void time_init(void)
{
	unsigned long tv_sec, tv_nsec;
	unsigned long ns_per_kclock;
	unsigned long tsc;

	ihk_mc_get_boot_time(&tv_sec, &tv_nsec);
	ns_per_kclock = ihk_mc_get_ns_per_tsc();

	tod_data.origin.tv_sec = tv_sec;
	tod_data.origin.tv_nsec = tv_nsec;

	if (ns_per_kclock) {
		tod_data.clocks_per_sec = (1000L * NS_PER_SEC) / ns_per_kclock;

		tsc = rdtsc();
		tod_data.origin.tv_sec -= tsc / tod_data.clocks_per_sec;
		tod_data.origin.tv_nsec -= NS_PER_SEC * (tsc % tod_data.clocks_per_sec)
			/ tod_data.clocks_per_sec;
		if (tod_data.origin.tv_nsec < 0) {
			--tod_data.origin.tv_sec;
			tod_data.origin.tv_nsec += NS_PER_SEC;
		}
	}

	if (!ns_per_kclock) {
		gettime_local_support = 0;
	}

	if (gettime_local_support) {
		tod_data.do_local = 1;
	}
	return;
}

static void monitor_init()
{
	int z;
	unsigned long phys;

	z = sizeof(struct ihk_os_monitor) +
	    sizeof(struct ihk_os_cpu_monitor) * num_processors;
	z = (z + PAGE_SIZE -1) >> PAGE_SHIFT;
	monitor = ihk_mc_alloc_pages(z, IHK_MC_AP_CRITICAL);
	memset(monitor, 0, z * PAGE_SIZE);
	monitor->num_processors = num_processors;
	monitor->num_numa_nodes = ihk_mc_get_nr_numa_nodes();
	monitor->ns_per_tsc = ihk_mc_get_ns_per_tsc();
	phys = virt_to_phys(monitor);
	ihk_set_monitor(phys, sizeof(struct ihk_os_monitor) +
	                    sizeof(struct ihk_os_cpu_monitor) * num_processors);
}

int nmi_mode;

static void nmi_init()
{
	unsigned long phys;

	phys = virt_to_phys(&nmi_mode);
	ihk_set_nmi_mode_addr(phys);
}

static void rest_init(void)
{
	handler_init();

#ifdef USE_DMA
	ihk_mc_dma_init();
	dma_test();
#endif
	//pc_test();

	ap_init();
	monitor_init();
	cpu_local_var_init();
	nmi_init();
	time_init();
	kmalloc_init();

	ihk_ikc_master_init();

	proc_init();

	sched_init();
}

static void setup_remote_snooping_samples(void)
{
	static long lvalue = 0xf123456789abcde0;
	static char *svalue = "string(remote)";
	int error;
	struct sysfs_bitmap_param param;

	error = sysfs_createf(SYSFS_SNOOPING_OPS_d32, &lvalue, 0444, "/sys/test/remote/d32");
	if (error) {
		panic("setup_remote_snooping_samples: d32");
	}

	error = sysfs_createf(SYSFS_SNOOPING_OPS_d64, &lvalue, 0444, "/sys/test/remote/d64");
	if (error) {
		panic("setup_remote_snooping_samples: d64");
	}

	error = sysfs_createf(SYSFS_SNOOPING_OPS_u32, &lvalue, 0444, "/sys/test/remote/u32");
	if (error) {
		panic("setup_remote_snooping_samples: u32");
	}

	error = sysfs_createf(SYSFS_SNOOPING_OPS_u64, &lvalue, 0444, "/sys/test/remote/u64");
	if (error) {
		panic("setup_remote_snooping_samples: u64");
	}

	error = sysfs_createf(SYSFS_SNOOPING_OPS_s, svalue, 0444, "/sys/test/remote/s");
	if (error) {
		panic("setup_remote_snooping_samples: s");
	}

	param.nbits = 40;
	param.ptr = &lvalue;

	error = sysfs_createf(SYSFS_SNOOPING_OPS_pbl, &param, 0444, "/sys/test/remote/pbl");
	if (error) {
		panic("setup_remote_snooping_samples: pbl");
	}

	param.nbits = 40;
	param.ptr = &lvalue;

	error = sysfs_createf(SYSFS_SNOOPING_OPS_pb, &param, 0444, "/sys/test/remote/pb");
	if (error) {
		panic("setup_remote_snooping_samples: pb");
	}

	error = sysfs_createf(SYSFS_SNOOPING_OPS_u32K, &lvalue, 0444, "/sys/test/remote/u32K");
	if (error) {
		panic("setup_remote_snooping_samples: u32K");
	}

	return;
} /* setup_remote_snooping_samples() */

static void populate_sysfs(void)
{
	cpu_sysfs_setup();
	numa_sysfs_setup();
	//setup_remote_snooping_samples();
} /* populate_sysfs() */

int host_ikc_inited = 0;
extern int num_processors;

static void post_init(void)
{
	cpu_enable_interrupt();

	while (!host_ikc_inited) {
		barrier();
		cpu_pause();
	}

	if (find_command_line("hidos")) {
		int ikc_cpu = ihk_mc_get_ikc_cpu(ihk_mc_get_processor_id());
		if(ikc_cpu < 0) {
			ekprintf("%s,ihk_mc_get_ikc_cpu failed\n", __FUNCTION__);
		}
		init_host_ikc2mckernel();
		init_host_ikc2linux(ikc_cpu);
	}

	arch_setup_vdso();
	arch_start_pvclock();
	ap_start();

	sysfs_init();
	populate_sysfs();
}
#ifdef DCFA_RUN
extern void user_main();
#endif

#ifdef DCFA_KMOD
extern int mc_cmd_client_init(void);
extern void ibmic_cmd_init(void);
#endif

int main(void)
{
	char *ptr;
	int mode = 0;

	ptr = find_command_line("ksyslogd=");
	if (ptr) {
	    mode = ptr[9] - 0x30;
	    if (mode < 0 || mode > 2) mode = 0;
	}
	kmsg_init(mode);

	kputs("IHK/McKernel started.\n");
	ihk_set_kmsg(virt_to_phys(&kmsg_buf), IHK_KMSG_SIZE);
	arch_init();

	/*
	 * In attached-mic,
	 * bootparam is not mapped until arch_init() is finished.
	 * In builtin-mic and builtin-x86,
	 * virtual address of bootparam is changed in arch_init().
	 */
	parse_kargs();

	mem_init();

	rest_init();

	arch_ready();

	post_init();

	futex_init();

	kputs("IHK/McKernel booted.\n");

#ifdef DCFA_KMOD
	mc_cmd_client_init();
#ifdef CMD_DCFA
	ibmic_cmd_init();
#endif
#endif

#ifdef DCFA_RUN
	kputs("DCFA begin\n");

	user_main();

	kputs("DCFA end\n");
#else
	schedule();
#endif

	return 0;
}
