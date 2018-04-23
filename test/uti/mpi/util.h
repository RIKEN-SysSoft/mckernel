#ifndef __UTIL_H_INCLUDED__
#define __UTIL_H_INCLUDED__

#include <stdint.h>

#define DIFFUSEC(end, start) ((end.tv_sec - start.tv_sec) * 1000000UL + (end.tv_usec - start.tv_usec))
#define DIFFNSEC(end, start) ((end.tv_sec - start.tv_sec) * 1000000000UL + (end.tv_nsec - start.tv_nsec))
#define CYC2NSEC(cyc) (cyc * 1.401)

int print_cpu_last_executed_on();
void fwq_init();
void fwq(long delay_cyc);

#endif
