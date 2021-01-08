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
