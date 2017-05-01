#ifndef __MCCTRL_PUBLIC_H
#define __MCCTRL_PUBLIC_H

#include <ihk/ihk_host_user.h>
#include <ikc/queue.h>

struct mcctrl_os_cpu_register {
	unsigned long addr;
	unsigned long val;
	unsigned long addr_ext;
};

int mcctrl_os_read_cpu_register(ihk_os_t os, int cpu,
		struct mcctrl_os_cpu_register *desc);
int mcctrl_os_write_cpu_register(ihk_os_t os, int cpu,
		struct mcctrl_os_cpu_register *desc);
int mcctrl_get_request_os_cpu(ihk_os_t *os, int *cpu);


#endif // __MCCTRL_PUBLIC_H
