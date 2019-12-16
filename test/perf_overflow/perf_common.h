/* perf_common.h COPYRIGHT FUJITSU LIMITED 2019 */
#ifndef _PERF_COMMON_H_
#define _PERF_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <asm/unistd.h>

#define SAMPLE_PERIOD 30

#define nop10 do {					\
		asm volatile("nop;nop;nop;nop;nop;"	\
				"nop;nop;nop;nop;nop");	\
	} while (0)

//usage
extern const char *the_app;
void print_usage(void);

//system call
long perf_event_open(struct perf_event_attr *event_attr, pid_t pid,
			int cpu, int group_fd, unsigned long flags);
int init_perf_event_attr(struct perf_event_attr *event_attr);
int asm_ioctl3(int fd, unsigned long arg1, unsigned long arg2);
int asm_read(int fd, void *buf, size_t size);

//command
struct command {
	void *args;
	void (*release)(struct command *cmd);
	int (*do_cmd)(int fd, void *args);
	void (*print)(void *args);
};

#define MAX_COMBINATION 256
struct command_set {
	int nr_cmds;
	struct command cmds[MAX_COMBINATION];
};
int build_command(const char *cmd_src, struct command *cmd);

#endif /* _PERF_COMMON_H_ */
