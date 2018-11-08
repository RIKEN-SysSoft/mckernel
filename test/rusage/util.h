#ifndef __UTIL_H_INCLUDED__
#define __UTIL_H_INCLUDED__

#define DEBUG

#ifdef DEBUG
#define dprintf(...) do {			 \
	char msg[1024];			 \
	sprintf(msg, __VA_ARGS__);		 \
	fprintf(stderr, "%s: %s", __func__, msg); \
} while (0)
#else
#define dprintf(...) do {  } while (0)
#endif

#define eprintf(...) do {			 \
	char msg[1024];			 \
	sprintf(msg, __VA_ARGS__);		 \
	fprintf(stderr, "%s: ERROR: %s", __func__, msg); \
} while (0)

#define CHKANDJUMP(cond, err, ...) do { \
	if (cond) {			\
		eprintf(__VA_ARGS__);   \
		ret = err;		\
		goto fn_fail;		\
	}				\
} while (0)


#define OKNG(cond, ...) do {				\
	if (cond) {					\
		printf("[ OK ] ");			\
		printf(__VA_ARGS__);			\
	} else {					\
		printf("[ NG ] ");			\
		printf(__VA_ARGS__);			\
		ret = -EINVAL;				\
		goto fn_fail;				\
	}						\
} while (0)

#endif

