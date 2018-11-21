#ifndef HEADER_TEST_CHK_H
#define HEADER_TEST_CHK_H

#define CHKANDJUMP(cond, ...)							\
	do {												\
		if (cond) {										\
			fprintf(stderr, " [NG] ");					\
			fprintf(stderr, __VA_ARGS__);				\
			fprintf(stderr, " failed\n");				\
			goto fn_fail;								\
		}												\
	} while(0);

#define OKNG(cond, ...)									\
	do {												\
		if (cond) {										\
			CHKANDJUMP(cond, __VA_ARGS__);				\
		} else {										\
			fprintf(stdout, " [OK] ");					\
			fprintf(stdout, __VA_ARGS__);				\
			fprintf(stdout, "\n");						\
		}												\
	} while(0);

#endif	
