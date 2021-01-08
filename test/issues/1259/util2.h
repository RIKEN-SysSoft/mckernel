#define CHKANDJUMP(cond, ...)	do {		\
	if (cond) {				\
		fprintf(stderr, " [NG] ");	\
		fprintf(stderr, __VA_ARGS__);	\
		fprintf(stderr, " failed\n");	\
		goto fn_fail;			\
	}					\
} while (0)

#define OKNG(cond, ...)		do {		\
	if (cond) {				\
		CHKANDJUMP(cond, __VA_ARGS__);	\
	} else {				\
		fprintf(stdout, " [OK] ");	\
		fprintf(stdout, __VA_ARGS__);	\
		fprintf(stdout, "\n");		\
	}					\
} while (0)


#ifdef __aarch64__
#define LARGE_PAGE_SHIFT 21
#elif defined(__x86_64__)
#define LARGE_PAGE_SHIFT 21
#else
#error "Non-compliant architecture."
#endif

#define MAP_HUGE_SHIFT 26
#define SZ_MEM (2 * (1ULL << LARGE_PAGE_SHIFT))
#define TEST_VAL 0x1129
