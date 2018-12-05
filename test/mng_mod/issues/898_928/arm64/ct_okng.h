/* ct_okng.h COPYRIGHT FUJITSU LIMITED 2018 */
#ifndef _CT_OKNG_H
#define _CT_OKNG_H

#define OKNG(cond, ...)								\
	do {									\
		if(cond) {							\
			printf("[OK] ");					\
			printf(__VA_ARGS__);					\
			fflush(stdout);						\
		}								\
		else {								\
			char buf[65536];					\
			char cmd[256];						\
			FILE* fp = NULL;					\
			size_t nread = 0;					\
										\
			printf("[NG] ");					\
			printf(__VA_ARGS__);					\
			sprintf(cmd, "%s/sbin/ihkosctl 0 kmsg", prefix);	\
			fp = popen(cmd, "r");					\
			nread = fread(buf, 1, sizeof(buf), fp);			\
			buf[nread] = 0;						\
			printf("%s", buf);					\
			fflush(stdout);						\
			goto fn_fail;						\
		}								\
	} while(0)

#endif /* _CTOKNG_H */
