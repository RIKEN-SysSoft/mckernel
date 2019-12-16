/* perf_common.c COPYRIGHT FUJITSU LIMITED 2019 */
#include "perf_common.h"

const char *the_app;

//
// usage
//
void print_usage(void)
{
	printf("usage : %s [test_num]\n"
		"test_num :\n"
		"	1 simple_test\n"
		"	2 read_test\n"
		"	3 reset_test\n"
		"	4 refresh_test\n"
		"	5 combination_test\n"
		"\n"
		"combination_test :\n"
		"	perf_test 5 -c [ctrl1,ctrl2...]\n"
		"ex) perf_test 5 -c READ,RESET,REFRESH\n",
	       the_app
	);
}

//
// system call
//
long perf_event_open(struct perf_event_attr *event_attr, pid_t pid,
				int cpu, int group_fd, unsigned long flags)
{
	int ret = syscall(__NR_perf_event_open, event_attr, pid, cpu,
			group_fd, flags);
	return ret;
}

int init_perf_event_attr(struct perf_event_attr *event_attr)
{
	int ret = -EINVAL;

	if (event_attr == NULL) {
		goto out;
	}
	memset(event_attr, 0, sizeof(struct perf_event_attr));
	event_attr->type = PERF_TYPE_HARDWARE;
	event_attr->size = sizeof(struct perf_event_attr);
	event_attr->config = PERF_COUNT_HW_INSTRUCTIONS;
	event_attr->sample_period = SAMPLE_PERIOD;
	event_attr->disabled = 1;
	event_attr->exclude_kernel = 1;
	event_attr->exclude_hv = 1;
	ret = 0;
out:
	return ret;
}

static long system_call3(long syscall_number, long arg0, long arg1, long arg2)
{
	long ret;
#if defined(__x86_64__)
	asm volatile ("syscall"
		: "=a" (ret)
		: "a" (syscall_number), "D" (arg0), "S" (arg1), "d" (arg2)
		: "rcx", "r11", "memory");
#elif defined(__aarch64__)
	asm volatile(
		"mov x8, %1;"
		"mov x0, %2;"
		"mov x1, %3;"
		"mov x2, %4;"
		"svc #0x0;"
		"mov %0, x0;"
		: "=r" (ret)
		: "r" (syscall_number),
		  "r" (arg0), "r" (arg1), "r" (arg2));
#else
# error not supported architecture.
#endif
	if (ret < 0) {
		errno = -ret;
	}
	return ret;
}

int asm_ioctl3(int fd, unsigned long arg1, unsigned long arg2)
{
	return system_call3(__NR_ioctl, fd, arg1, arg2);
}

int asm_read(int fd, void *buf, size_t size)
{
	return system_call3(__NR_read, fd, (unsigned long)buf, size);
}

//
// command
//

// sys_read command
struct sys_read_arg {
	long long count;
};

static int sys_read(int fd, void *_args)
{
	struct sys_read_arg *args = _args;
	int ret = asm_read(fd, &args->count, sizeof(args->count));

	if (ret < 0) {
		errno = -ret;
		perror("sys_read");
	}
	return ret;
}

static void print_sys_read(void *_args)
{
	struct sys_read_arg *args = _args;

	printf("sys_read: %lld\n", args->count);
}

static void release_sys_read_command(struct command *cmd)
{
	free(cmd->args);
	cmd->args = NULL;
}

static void build_sys_read_command(struct command *cmd)
{
	cmd->do_cmd = sys_read;
	cmd->args = calloc(sizeof(struct sys_read_arg), 1);
	cmd->release = release_sys_read_command;
	cmd->print = print_sys_read;
}

// perf_event_ioc_reset command
static int perf_event_ioc_reset(int fd, void *_args)
{
	int ret = asm_ioctl3(fd, PERF_EVENT_IOC_RESET, 0);

	if (ret < 0) {
		errno = -ret;
		perror("sys_ioctl: reset");
	}
	return ret;
}

static void print_perf_event_ioc_reset(void *cmd)
{
	printf("%s:\n", __func__);
}

static void release_perf_event_ioc_reset(struct command *cmd)
{
}

static void build_perf_event_ioc_reset(struct command *cmd)
{
	cmd->do_cmd = perf_event_ioc_reset;
	cmd->args = NULL;
	cmd->release = release_perf_event_ioc_reset;
	cmd->print = print_perf_event_ioc_reset;
}

// perf_event_ioc_refresh command
static int perf_event_ioc_refresh(int fd, void *_args)
{
	int ret = asm_ioctl3(fd, PERF_EVENT_IOC_REFRESH, 0);

	if (ret < 0) {
		errno = -ret;
		perror("sys_ioctl: refresh");
	}
	return ret;
}

static void print_perf_event_ioc_refresh(void *cmd)
{
	printf("%s:\n", __func__);
}

static void release_perf_event_ioc_refresh(struct command *cmd)
{
}

static void build_perf_event_ioc_refresh(struct command *cmd)
{
	cmd->do_cmd = perf_event_ioc_refresh;
	cmd->args = NULL;
	cmd->release = release_perf_event_ioc_refresh;
	cmd->print = print_perf_event_ioc_refresh;
}

// command factory
int build_command(const char *cmd_src, struct command *cmd)
{
	int ret = 0;

	if (strcmp(cmd_src, "READ") == 0) {
		build_sys_read_command(cmd);
	}
	else if (strcmp(cmd_src, "RESET") == 0) {
		build_perf_event_ioc_reset(cmd);
	}
	else if (strcmp(cmd_src, "REFRESH") == 0) {
		build_perf_event_ioc_refresh(cmd);
	}
	else {
		ret = -EINVAL;
	}
	return ret;
}
