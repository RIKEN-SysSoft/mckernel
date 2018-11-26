/*
 * mcstat -- reports McKernel statistis
 *	mcstat [-h] 
 *	mcstat [-n]  [delay [ count]]
 *	mcstat [-s] 
 *	mcstat [-c] 
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include <ihklib.h>
#include <ihk/ihk_host_user.h>
#undef IHK_MAX_NUM_NUMA_NODES
#include <ihklib_rusage.h>	// mckernel_rusage is defined here

#define MAX_CPUS	256
#define MiB100		(100*1024*1024) // 100 MiB
#define MiB		(1024*1024)
#define GiB		(1024*1024*1024)
#define CONV_UNIT(d)	(((float)(d))/scale)
#define UPDATE_COUNTER(c)	(c = (c + 1) % 10)

struct my_rusage {
	struct mckernel_rusage rusage;

	/* Initial amount posted to allocator. Note that the amount
	 * used before the initialization is not included.
	 */
	unsigned long memory_total;

	/* Current of sum of kernel and user */
	unsigned long memory_cur_usage;

	/* Max of sum of kernel and user */
	unsigned long memory_max_usage;
};

struct my_rusage rbuf;

static void	mcstatistics(int idx, int once, int delay, int count);
static int	mcstatus(int idx, int delay, int count);
static void	mcosusage(int idx, int once, int delay, int count);

static void
usage()
{
    fprintf(stderr, "Usage: mcstat [-h|-n|-s] [delay [count]]\n");
}

int
main(int argc, char **argv)
{
	int rc;
    int		opt;
    int		idx = 0;	/* index of OS instance */
    int		sflag = 0;	/* statistic option */
    int		cflag = 0;	/* cpu info */
    int		once = 0;	/* header is shown once */
    int		delay = 0;	/* delay in second */
    int		count = 1;	/* */

    if (argc > 1) {
        while ((opt = getopt(argc, argv, "chns")) != -1) {
            switch (opt) {
	    case 'c':	/* cpu info */
		cflag = 1; break;
	    case 'h':
		usage(); exit(0);
	    case 'n':
		once = 1; break;
	    case 's':	/* status */
		sflag = 1; break;
	    }
	}
    }
    if (optind < argc) { /* interval */
	delay = atoi(argv[optind]);
	if (optind + 1 < argc) { /* count */
	    count = atoi(argv[optind+1]);
	} else {
	    count = -1; /* inifi */
	}
    }

	if (sflag) {
		if ((rc = mcstatus(idx, delay, count))) {
			printf("error: mcstatus: %d",
			       rc);
			goto out;
		}
	} else if (cflag) {
		mcosusage(idx, once, delay, count);
	} else {
		mcstatistics(idx, once, delay, count);
	}

	rc = 0;
out:
	return rc;
}

static int
devopen(int idx)
{
    int		fd;
    char	fn[128];

    snprintf(fn, 128, "/dev/mcos%d", idx);
    fd = open(fn, O_RDONLY);
    return fd;
}

static void
statistics_header(char *unit)
{
    printf("------- memory (%s) ------- ------- tsc ------ --- thread ---\n",
	   unit);
    printf("    total  current      max    system     user current max\n");
}

/*
 * Device should be open in each ioctl time. Otherwise, this command grabs
 * the device, and cannot be rebooted by others.
 */
static int
mygetrusage(int idx, struct my_rusage *rbp)
{
	int rc;
	int num_numa_nodes;
	int i;
	unsigned long *memtotal = NULL;

	rc = ihk_os_getrusage(idx, &rbp->rusage,
			      sizeof(struct mckernel_rusage));
	if (rc) {
		printf("%s: error: ihk_os_getrusage: %s\n",
		       __func__, strerror(-rc));
		goto out;
	}

	num_numa_nodes = ihk_os_get_num_numa_nodes(idx);
	if (num_numa_nodes <= 0) {
		printf("%s: error: ihk_os_get_num_numa_nodes: %d\n",
		       __func__, num_numa_nodes);
		rc = -1;
		goto out;
	}

	/* Calculate total by taking a sum over NUMA nodes */

	memtotal = malloc(num_numa_nodes * sizeof(unsigned long));
	if (!memtotal) {
		printf("%s: error: assigining memory\n",
		       __func__);
		rc = -ENOMEM;
		goto out;
	}
	memset(memtotal, 0, num_numa_nodes * sizeof(unsigned long));

	rc = ihk_os_query_total_mem(idx, memtotal, num_numa_nodes);
	if (rc) {
		printf("%s: error: ihk_os_query_total_mem: %s\n",
		       __func__, strerror(-rc));
		goto out;
	}

	rbp->memory_total = 0;
	for (i = 0; i < num_numa_nodes; i++) {
		rbp->memory_total += memtotal[i];
	}

	/* Calculate current by taking a sum over NUMA nodes */

	rbp->memory_cur_usage = rbp->rusage.memory_kmem_usage;
	for (i = 0; i < num_numa_nodes; i++) {
		rbp->memory_cur_usage += rbp->rusage.memory_numa_stat[i];
	}

	/* Calculate max by taking a sum of kernel and user */

	rbp->memory_max_usage = rbp->rusage.memory_kmem_max_usage +
		rbp->rusage.memory_max_usage;

	rc = 0;
out:
	free(memtotal);
	return rc;
}

static void
mcstatistics(int idx, int once, int delay, int count)
{
    int		i, scale;
    char	*unit;
    unsigned char show = 0;

    if (mygetrusage(idx, &rbuf) < 0) {
	printf("Device has not been created.\n");
	exit(-1);
    }
	if (rbuf.rusage.memory_max_usage < MiB100) {
		scale = MiB; unit = "MB";
	} else {
		scale = GiB; unit = "GB";
	}
    statistics_header(unit);
    for (;;) {

	printf("%9.3f%9.3f%9.3f %9ld%9ld %7d %3d\n",
	       CONV_UNIT(rbuf.memory_total),
	       CONV_UNIT(rbuf.memory_cur_usage),
	       CONV_UNIT(rbuf.memory_max_usage),
	       rbuf.rusage.cpuacct_stat_system, rbuf.rusage.cpuacct_stat_user,
	       rbuf.rusage.num_threads, rbuf.rusage.max_num_threads);
	if (count > 0 && --count == 0) break;
	sleep(delay);
	if (mygetrusage(idx, &rbuf) < 0) {
	    printf("Device is now invisible.\n");
	    break;
	}
	if (!once) {
	    if (UPDATE_COUNTER(show) == 0) {
		statistics_header(unit);
	    }
	}
    }
/*
	?? /1000000
  	rusage->cpuacct_stat_system = st / 10000000;
	rusage->cpuacct_stat_user = ut / 10000000;
	rusage->cpuacct_usage = ut;
	printf("cpuacct_usage = %x\n", rbuf.rusage.cpuacct_usage);
*/
	for (i = 0; i < rbuf.rusage.max_num_threads; i++) {
		printf("cpuacct_usage_percpu[%d] = %ld\n",
		       i, rbuf.rusage.cpuacct_usage_percpu[i]);
	}
}

/* ihk_os_status enum is defined in ihk/linux/include/ihk/status.h */
static char *charstat[] = {
	[IHK_OS_STATUS_NOT_BOOTED] = "None",
	[IHK_OS_STATUS_BOOTING] = "Booting",
	[IHK_OS_STATUS_BOOTED] = "Booted",	/* OS booted and acked */
	[IHK_OS_STATUS_READY] = "Ready",	/* OS is ready and fully functional */
	[IHK_OS_STATUS_RUNNING] = "Running",	/* OS is running */
	[IHK_OS_STATUS_FREEZING] = "Freezing",	/* OS is freezing */
	[IHK_OS_STATUS_FROZEN] = "Frozen",	/* OS is frozen */
	[IHK_OS_STATUS_SHUTDOWN] = "Shutdown",	/* OS is shutting down */
	[IHK_OS_STATUS_STOPPED] = "Stopped",	/* OS stopped successfully */
	[IHK_OS_STATUS_FAILED] = "Panic",	/* OS panics or failed to boot */
	[IHK_OS_STATUS_HUNGUP] = "Hangup",	/* OS is hungup */
	[IHK_OS_STATUS_COUNT] = NULL,		/* End mark */
};

static int
mcstatus(int idx, int delay, int count)
{
	int fd = -1, rc;

	for (;;) {
		if ((fd = devopen(idx)) == -1) {
			printf("Device not found, retrying...\n");
			goto next;
		}

		rc = ioctl(fd, IHK_OS_STATUS, 0);
		if (rc == -1) {
			printf("%s: error: IHK_OS_STATUS: %s\n",
			       __func__, strerror(errno));
			rc = -errno;
			goto out;
		}

		close(fd);
		fd = -1;

		if (rc < 0 && rc >= IHK_OS_STATUS_COUNT) {
			printf("%s: error: status (%d) out of range\n",
			       __func__, rc);
			rc = -EINVAL;
			goto out;
		}

		printf("McKernel status: %s\n",
		       charstat[rc] ? : "Unknown");

next:
		if (count > 0 && --count == 0) {
			break;
		}
		sleep(delay);
	}

	rc = 0;
out:
	if (fd != -1) {
		close(fd);
	}
	return rc;
}

/* status is not contiguous numbers */
static char *
monstatus(int status)
{
    switch (status) {
    case IHK_OS_MONITOR_NOT_BOOT:	return "boot";
    case IHK_OS_MONITOR_IDLE:		return "idle";
    case IHK_OS_MONITOR_USER:		return "user mode";
    case IHK_OS_MONITOR_KERNEL:		return "kernel mode";
    case IHK_OS_MONITOR_KERNEL_HEAVY:   return "kernel mode";
    case IHK_OS_MONITOR_KERNEL_OFFLOAD:	return "offload";
    case IHK_OS_MONITOR_KERNEL_FREEZING:return "freezing";
    case IHK_OS_MONITOR_KERNEL_FROZEN:	return "frozen";
    case IHK_OS_MONITOR_KERNEL_THAW:	return "thaw";
    case IHK_OS_MONITOR_PANIC:	return "panic";
    }
    return "";
}

static void
osusage_header()
{
    printf("--cpu-- --status-- --count--\n");
}

static void
mcosusage(int idx, int once, int delay, int count)
{
    int		fd, i, rc;
    int		ncpus;
    unsigned char show = 0;
    struct ihk_os_cpu_monitor	mon[MAX_CPUS];

	if (mygetrusage(idx, &rbuf) < 0) {
		printf("Device has not been created.\n");
	}
	ncpus = rbuf.rusage.max_num_threads;
    osusage_header();
    for(;;) {
	if ((fd = devopen(idx)) < 0) {
	    printf("Devide is not created\n");
	} else {
	    rc = ioctl(fd, IHK_OS_GET_CPU_USAGE, &mon);
	    close(fd);
	    if (rc != 0) {
		printf("ioctl error(IHK_OS_GET_CPU_USAGE)\n");
		break;
	    }
	    for (i = 0; i < ncpus; i++) {
		printf("%6d: %10s %9ld\n",
		       i, monstatus(mon[i].status), mon[i].counter);
	    }
	}
	if (count > 0 && --count == 0) break;
	sleep(delay);
	if (!once) {
	    if (UPDATE_COUNTER(show) == 0) {
		osusage_header();
	    }
	}
    }
}
