/**
 * \file rusage.c
 */
#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <process.h>
#include <init.h>
#include <march.h>
#include <cls.h>
#include <time.h>
#include <syscall.h>
#include <string.h>
#include <rusage.h>

//#define DEBUG_PRINT_AP

#ifdef DEBUG_PRINT_AP
#define dkprintf(...) kprintf(__VA_ARGS__)
#define ekprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
#define ekprintf(...) kprintf(__VA_ARGS__)
#endif

extern int num_processors ;
static volatile int ap_stop = 1;

mcs_lock_node_t ap_syscall_semaphore;

extern struct ihk_os_monitor *monitor;


#ifdef ENABLE_RUSAGE
/* count total rss */
unsigned long count_rss () {
	int i;
	unsigned long val = 0;
	for(i = 0; i < sizeof(cpu_set_t)/8; i++){
		val += rusage_rss[i];
	}
	return val;
}

/* count total cache */
unsigned long count_cache () {
   return 0;
}

/* count total rss_huge */
unsigned long count_rss_huge () {
	return 0;
}

/* count total mapped_file */
unsigned long count_mapped_file () {
	return 0;
}

/* count total max_usage */
unsigned long count_max_usage() {
	return rusage_rss_max;
}

/* count total kmem_usage */
unsigned long count_kmem_usage() {
	return 0;
}

/* count total kmax_usage */
unsigned long count_kmem_max_usage() {
	return 0;
}

#endif 

#include <sysfs.h>
#include <vsprintf.h>

#ifdef ENABLE_RUSAGE
char* strcat_rusage(char *s1, char *s2) {
	int i;
	int j;
	for (i = 0; s1[i] != '\0'; i++); //skip chars.
	for (j = 0; s2[j] != '\0'; j++) {
		s1[i+j] = s2[j];
	}
	s1[i+j] = '\0';
	return s1;	
}

static ssize_t
show_rusage_memory_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf, size, "rss %lu\ncache %lu\nrss_huge %lu\nmapped_file %lu\n",
			count_rss(),
			count_cache(),
			count_rss_huge(),
			count_mapped_file()
	);
}

static ssize_t 
show_rusage_memory_max_usage_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf,size,"%lu\n",count_max_usage());
}

static ssize_t 
show_rusage_memory_kmem_usage_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf,size,"%lu\n",count_kmem_usage());
}

static ssize_t 
show_rusage_memory_kmem_max_usage_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf,size,"%lu\n",count_kmem_max_usage());
}

static ssize_t 
show_rusage_num_numa_nodes_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf,size,"%d\n",ihk_mc_get_nr_numa_nodes());
}

static ssize_t 
show_rusage_memory_numa_stat_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	int i;
	int num_numa;
	char tmp_buf1[1024];
	char tmp_buf2[1024];
	unsigned long total = 0;
	memset(tmp_buf1, 0, 1024);
	num_numa = ihk_mc_get_nr_numa_nodes();

	for (i = 0; i < num_numa; i++) {
		total += rusage_numa_stat[i];
	}
	sprintf(tmp_buf1, "total=%lu ", total);

	for (i = 0; i < num_numa; i++) {
		sprintf(tmp_buf2, "N%d=%lu ", i, rusage_numa_stat[i]);
		strcat_rusage(tmp_buf1, tmp_buf2);
		memset(tmp_buf2, 0, 1024);
	}
	return snprintf(buf, size, "%s\n", tmp_buf1);
}

static ssize_t 
show_rusage_hugetlb_usage_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf, size, "%lu\n", rusage_hugetlb_usage);
}

static ssize_t 
show_rusage_hugetlb_max_usage_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf, size, "%lu\n", rusage_hugetlb_max_usage);
}
static ssize_t 
show_rusage_cpuacct_stat_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	struct timespec uts;
	struct timespec sts;
	int i;
	int r = 0;

	uts.tv_sec = 0;
	uts.tv_nsec = 0;
	sts.tv_sec = 0;
	sts.tv_nsec = 0;
	if (monitor)
		for (i = 0; i < num_processors; i++) {
			struct timespec ats;

			tsc_to_ts(monitor[i].user_tsc, &ats);
			ts_add(&uts, &ats);
			tsc_to_ts(monitor[i].system_tsc, &ats);
			ts_add(&sts, &ats);
		}
	r = snprintf(buf, size, "user %lu\n", timespec_to_jiffy(&uts));
	r += snprintf(strchr(buf, '\0'), size - r, "system %lu\n",
				  timespec_to_jiffy(&sts));
	return r;
}
static ssize_t 
show_rusage_cpuacct_usage_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	struct timespec uts;
	int i;
	int r = 0;

	uts.tv_sec = 0;
	uts.tv_nsec = 0;
	if (monitor)
		for (i = 0; i < num_processors; i++) {
			struct timespec ats;

			tsc_to_ts(monitor[i].user_tsc + monitor[i].system_tsc,
					  &ats);
			ts_add(&uts, &ats);
		}
	if (uts.tv_sec)
		r = snprintf(buf, size, "%lu%09lu\n", uts.tv_sec, uts.tv_nsec);
	else
		r = snprintf(buf, size, "%lu\n", uts.tv_nsec);
	return r;
}


static ssize_t 
show_rusage_cpuacct_usage_percpu_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	struct timespec uts;
	int i;
	int r = 0;

	((char *)buf)[0] = '\0';
	for (i = 0; i < num_processors; i++) {
		if (monitor) {
			tsc_to_ts(monitor[i].user_tsc + monitor[i].system_tsc,
					  &uts);
		}
		else {
			uts.tv_sec = 0;
			uts.tv_nsec = 0;
		}
		if (uts.tv_sec)
			r += snprintf(strchr(buf, '\0'), size - r,
						  "%lu%09lu ", uts.tv_sec, uts.tv_nsec);
		else
			r += snprintf(strchr(buf, '\0'), size - r,
						  "%lu ", uts.tv_nsec);
	}
	((char *)buf)[r - 1] = '\n';
	return r;
}

/* callback funciton of rusage(threads) sysfs */
static ssize_t
show_rusage_num_threads_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf, size, "%lu\n", rusage_num_threads);
}

/* callback funciton of rusage(max threads) sysfs */
static ssize_t
show_rusage_max_num_threads_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf, size, "%lu\n", rusage_max_num_threads);
}

/* definition of sysfs ops */
struct sysfs_ops show_rusage_memory = {
	.show = &show_rusage_memory_data,
};
struct sysfs_ops show_rusage_memory_max_usage = {
	.show = &show_rusage_memory_max_usage_data,
};
struct sysfs_ops show_rusage_memory_kmem_usage = {
	.show = &show_rusage_memory_kmem_usage_data,
};
struct sysfs_ops show_rusage_memory_kmem_max_usage = {
	.show = &show_rusage_memory_kmem_max_usage_data,
};
struct sysfs_ops show_rusage_num_numa_nodes = {
	.show = &show_rusage_num_numa_nodes_data,
};
struct sysfs_ops show_rusage_memory_numa_stat = {
	.show = &show_rusage_memory_numa_stat_data,
};
struct sysfs_ops show_rusage_hugetlb_usage = {
	.show = &show_rusage_hugetlb_usage_data,
};
struct sysfs_ops show_rusage_hugetlb_max_usage = {
	.show = &show_rusage_hugetlb_max_usage_data,
};
struct sysfs_ops show_rusage_cpuacct_stat = {
	.show = &show_rusage_cpuacct_stat_data,
};
struct sysfs_ops show_rusage_cpuacct_usage = {
	.show = &show_rusage_cpuacct_usage_data,
};
struct sysfs_ops show_rusage_num_threads = {
	.show = &show_rusage_num_threads_data,
};
struct sysfs_ops show_rusage_cpuacct_usage_percpu = {
	.show = &show_rusage_cpuacct_usage_percpu_data,
};
struct sysfs_ops show_rusage_max_num_threads = {
	.show = &show_rusage_max_num_threads_data,
};

/* create sysfs files for rusage. */
void rusage_sysfs_setup(void) {
	int error;
	error = sysfs_createf(&show_rusage_memory, &rdata, 0444,
		"/sys/fs/cgroup/memory/memory.stat");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_memory_max_usage, &rdata, 0444,
		"/sys/fs/cgroup/memory/memory.max_usage_in_bytes");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_memory_kmem_usage, &rdata, 0444,
		"/sys/fs/cgroup/memory/memory.kmem.usage_in_bytes");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_memory_kmem_max_usage, &rdata, 0444,
		"/sys/fs/cgroup/memory/memory.kmem.max_usage_in_bytes");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_num_numa_nodes, &rdata, 0444,
		"/sys/fs/cgroup/cpu/num_numa_nodes.txt");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_memory_numa_stat, &rdata, 0444,
		"/sys/fs/cgroup/memory/memory.numa_stat");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_hugetlb_usage, &rdata, 0444,
		"/sys/fs/cgroup/hugetlb/hugetlb.1GB.usage_in_bytes");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_hugetlb_max_usage, &rdata, 0444,
		"/sys/fs/cgroup/hugetlb/hugetlb.1GB.max_usage_in_bytes");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_cpuacct_stat, &rdata, 0444,
		"/sys/fs/cgroup/cpuacct/cpuacct.stat");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_cpuacct_usage, &rdata, 0444,
		"/sys/fs/cgroup/cpuacct/cpuacct.usage");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_cpuacct_usage_percpu, &rdata, 0444,
		"/sys/fs/cgroup/cpuacct/cpuacct.usage_percpu");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_num_threads, &rdata, 0444,
		"/sys/fs/cgroup/num_threads");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
	error = sysfs_createf(&show_rusage_max_num_threads, &rdata, 0444,
		"/sys/fs/cgroup/max_num_threads");
	if (error) {
		panic("rusage_sysfs_setup:sysfs_createf() failed\n");
	}
}

/* callback funciton of os_status sysfs */
static ssize_t
show_ihk_status_data(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	return snprintf(buf, size, "%d\n", os_status);
}

struct sysfs_ops show_ihk_status = {
	.show = &show_ihk_status_data,
};

/* create sysfs files for monitoring status.*/
void status_sysfs_setup(void) {
	int error;
	error = sysfs_createf(&show_ihk_status, &rdata, 0444,
		"/sys/fs/cgroup/mck_status");
	if (error) {
		panic("status_sysfs_setup:sysfs_createf() failed\n");
	}
}
#endif

