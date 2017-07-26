extern int switch_ctx(int fd, unsigned long cmd, void **param, void *lctx, void *rctx);
extern unsigned long compare_and_swap(unsigned long *addr, unsigned long old, unsigned long new);
extern unsigned int compare_and_swap_int(unsigned int *addr, unsigned int old, unsigned int new);
