/* combination_test.c COPYRIGHT FUJITSU LIMITED 2019 */
#include "combination_test.h"

//
// main
//
static int combination_test(struct command_set *cmd_set)
{
	struct perf_event_attr pe;
	long long lest_count;
	int ret = -1;
	int fd;
	int i;

	ret = init_perf_event_attr(&pe);
	if (ret < 0) {
		fprintf(stderr,
			"%s : Failed to init_perf_event_attr.\n",
			__func__);
		goto out;
	}

	fd = perf_event_open(&pe, 0, -1, -1, 0);
	if (fd == -1) {
		perror("pef_event_open");
		goto out;
	}

	ret = ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	if (ret < 0) {
		perror("ioctl(PERF_EVENT_IOC_RESET)");
		goto out;
	}

	ret = asm_ioctl3(fd, PERF_EVENT_IOC_ENABLE, 0);
	if (ret < 0) {
		errno = -ret;
		perror("asm_ioctl(PERF_EVENT_IOC_ENABLE)");
		goto out;
	}

	nop10;
	nop10;
	nop10;
	nop10;
	for (i = 0; i < cmd_set->nr_cmds; i++) {
		struct command *cmd = &cmd_set->cmds[i];

		cmd->do_cmd(fd, cmd->args);
		nop10;
		nop10;
		nop10;
		nop10;
	}
	nop10;
	nop10;
	nop10;
	nop10;

	ret = asm_ioctl3(fd, PERF_EVENT_IOC_DISABLE, 0);
	if (ret < 0) {
		errno = -ret;
		perror("asm_ioctl(PERF_EVENT_IOC_DISABLE)");
		goto out;
	}

	for (i = 0; i < cmd_set->nr_cmds; i++) {
		struct command *cmd = &cmd_set->cmds[i];

		cmd->print(cmd->args);
	}

	ret = read(fd, &lest_count, sizeof(lest_count));
	if (ret < 0) {
		perror("read(lest_count)");
		goto out;
	}
	printf("---------\n"
		"sys_read: %lld\n", lest_count);

	ret = 0;
out:
	if (fd != -1) {
		close(fd);
	}
	return ret;
}

int combination_main(int argc, char **argv)
{
	int ret = -1;
	int i;
	int opt;
	char *input_commands = NULL;
	struct command_set cmd_set = {0};

	// parse args
	while ((opt = getopt(argc, argv, "c:")) != -1) {
		switch (opt) {
		case 'c':
			input_commands = optarg;
			break;
		default:
			print_usage();
			goto out;
		}
	}
	if (input_commands == NULL) {
		fprintf(stderr,
			"%s : combination test requires -c option.\n",
			__func__);
		print_usage();
		goto out;
	}

	// build command
	for (i = 0; i <= MAX_COMBINATION; i++) {
		const char *cmd = strtok(input_commands, ",");

		input_commands = NULL;
		if (cmd == NULL) {
			break;
		}

		if (i == MAX_COMBINATION) {
			fprintf(stderr,
				"%s : Too many arguments to option '-c'.\n",
				__func__);
			goto release_out;
		}

		if (build_command(cmd,  &cmd_set.cmds[i]) < 0) {
			fprintf(stderr,
				"%s : Incorrect command[%s].\n",
				__func__, cmd);
			print_usage();
			goto release_out;
		}
	}
	cmd_set.nr_cmds = i;

	// run
	ret = combination_test(&cmd_set);

	// release command
release_out:
	for (i = 0; i < cmd_set.nr_cmds; i++) {
		struct command *cmd = &cmd_set.cmds[i];

		cmd->release(cmd);
	}
out:
	return ret;
}
