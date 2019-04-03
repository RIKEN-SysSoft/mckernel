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

#define _OKNG(verb, jump, cond, fmt, args...) do {	\
	if (cond) {					\
		if (verb)				\
			printf("\t[ OK ] " fmt, ##args);	\
	} else {					\
		printf("\t[ NG ] " fmt, ##args);		\
		if (jump)				\
			goto fn_fail;			\
	}						\
} while (0)

#define OKNG(args...) _OKNG(1, 1, ##args)
#define NG(args...) _OKNG(0, 1, ##args)
#define OKNGNOJUMP(args...) _OKNG(1, 0, ##args)

#define Q(x) #x
#define QUOTE(x) Q(x)

extern char *mck_dir;
extern char *arch;
extern char *target;

int get_config(void);
void destroy_config(void);

#endif

