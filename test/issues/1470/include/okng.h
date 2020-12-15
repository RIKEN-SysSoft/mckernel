#ifndef __OKNG_H_INCLUDED__
#define __OKNG_H_INCLUDED__

#include <stdio.h>

#define _OKNG(verb, jump, cond, fmt, args...) do {		\
	if (cond) {						\
		if (verb)					\
			printf("[  OK  ] " fmt, ##args);	\
	} else {						\
		printf("[  NG  ] " fmt, ##args);		\
		if (jump) {					\
			ret = 1;				\
			goto out;				\
		}						\
	}							\
} while (0)

#define OKNG(args...) _OKNG(1, 1, ##args)
#define INFO(fmt, args...) printf("[ INFO ] " fmt, ##args)
#define START(fmt, args...) printf("[ START] " fmt, ##args)
#define INTERR(cond, fmt, args...) do {	 \
	if (cond) {			 \
		char msg[4096];			 \
		sprintf(msg, fmt, ##args);		 \
		printf("[INTERR] %s:%d %s", __FILE__, __LINE__, msg);	\
		ret = 1;					\
		goto out;					\
	} \
} while (0)
#define ARRAY_SIZE_CHECK(array, size) INTERR(sizeof(array)/sizeof(array[0]) != size, "size of array \"%s\" isn't %d\n", #array, size)

#endif
