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

#include <ihk/ihk_host_user.h>
#include <ihk/ihklib_private.h>		// mcctrl_ioctl_getrusage_desc is defined here
#undef IHK_MAX_NUM_NUMA_NODES
#include <ihklib_rusage.h>	// mckernel_rusage is defined here

#define MAX_CPUS	256
#define MiB100		(100*1024*1024) // 100 MiB
#define MiB		(1024*1024)
#define GiB		(1024*1024*1024)
#define CONV_UNIT(d)	(((float)(d))/scale)
#define UPDATE_COUNTER(c)	(c = (c + 1) % 10)

struct mckernel_rusage			rbuf;

static void	mcstatistics(int idx, int once, int delay, int count);
static void	mcstatus(int idx, int delay, int count);
static void	mcosusage(int idx, int once, int delay, int count);

static void
usage()
{
    fprintf(stderr, "Usage: mcstat [-h|-n|-s] [delay [count]]\n");
}

int
main(int argc, char **argv)
{
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
	mcstatus(idx, delay, count);
    } else if (cflag) {
	mcosusage(idx, once, delay, count);
    } else {
	mcstatistics(idx, once, delay, count);
    }
    return 0;
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
mygetrusage(int idx, struct mckernel_rusage *rbp)
{
    int		fd, rc;
    struct mcctrl_ioctl_getrusage_desc	rusage;

    if ((fd = devopen(idx)) < 0) {
	return -1;
    }
    rusage.rusage = rbp;
    rusage.size_rusage = sizeof(struct mckernel_rusage);
    memset(rbp, 0, sizeof(struct mckernel_rusage));
    if ((rc = ioctl(fd, IHK_OS_GETRUSAGE, &rusage)) < 0) {
	perror("ioctl"); exit(-1);
    }
    close(fd);
    return 0;
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
    if (rbuf.memory_max_usage < MiB100) {
	scale = MiB; unit = "MB";
    } else {
	scale = GiB; unit = "GB";
    }
    statistics_header(unit);
    for (;;) {
	printf("%9.3f%9.3f%9.3f %9ld%9ld %7d %3d\n",
	       CONV_UNIT(rbuf.memory_max_usage),
	       CONV_UNIT(rbuf.memory_kmem_usage),
	       CONV_UNIT(rbuf.memory_kmem_max_usage),
	       rbuf.cpuacct_stat_system, rbuf.cpuacct_stat_user,
	       rbuf.num_threads, rbuf.max_num_threads);
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
	printf("cpuacct_usage = %x\n", rbuf.cpuacct_usage);
*/
    for (i = 0; i < rbuf.max_num_threads; i++) {
	printf("cpuacct_usage_percpu[%d] = %ld\n", i, rbuf.cpuacct_usage_percpu[i]);
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
};

static void
mcstatus(int idx, int delay, int count)
{
    int		fd, rc;

    for(;;) {
	if ((fd = devopen(idx)) < 0) {
	    printf("Devide is not created\n");
	} else {
	    rc = ioctl(fd, IHK_OS_STATUS, 0);
	    close(fd);
	    printf("McKernel status: ");
	    if (rc >= IHK_OS_STATUS_NOT_BOOTED && rc <= IHK_OS_STATUS_HUNGUP) {
		printf("%s\n", charstat[rc]);
	    } else {
		printf("ioctl error(IHK_OS_STATUS)\n");
	    }
	}
	if (count > 0 && --count == 0) break;
	sleep(delay);
    }
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
    ncpus = rbuf.max_num_threads;
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
