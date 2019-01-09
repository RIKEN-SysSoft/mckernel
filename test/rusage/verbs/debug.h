#ifndef MYLIB_H
#define MYLIB_H

#ifndef NULL
#define NULL   ((void *) 0)
#endif

#ifdef DEBUG
#define debug_printf(fmt,arg...) {printf("[DEBUG] " fmt, ##arg);}
#define debug_print_mem(arg...) {fprintf(stderr, "[DEBUG] ");print_mem(arg);}
#else
#define debug_printf(fmt,arg...) {}
#define debug_print_mem(arg...) {}
#endif

#ifdef ERROR
#define error_printf(fmt,arg...) {fprintf(stderr, "[ERROR] " fmt, ##arg);}
#define error_perror(arg...) {fprintf(stderr, "[ERROR] "); perror(arg);}
#else
#define error_printf(fmt,arg...) {}
#define error_perror(fmt,arg...) {}
#endif

#include "mtype.h"

/**
 * get current time(sec)
 */
extern double cur_time();
extern void print_mem(addr_t addr, int size);
#endif
