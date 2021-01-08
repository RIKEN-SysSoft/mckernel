#ifndef __UTIL_H_INCLUDED__
#define __UTIL_H_INCLUDED__

#define CHKANDJUMP(cond, err, ...) do { \
	if (cond) {			\
		printf(__VA_ARGS__);   \
		ret = err;		\
		goto out;		\
	}				\
} while (0)

#define _OKNG(verb, jump, cond, fmt, args...) do {	\
	if (cond) {					\
		if (verb)				\
			printf("[ OK ] " fmt, ##args);	\
	} else {					\
		printf("[ NG ] " fmt, ##args);		\
		if (jump)				\
			goto out;			\
	}						\
} while (0)

#define OKNG(args...) _OKNG(1, 1, ##args)
#define NG(args...) _OKNG(0, 1, ##args)
#define OKNGNOJUMP(args...) _OKNG(1, 0, ##args)

#endif

