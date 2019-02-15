#include "../include/uprotocol.h"

extern int switch_ctx(int fd, unsigned long cmd, struct uti_save_tls_desc *desc, void *lctx, void *rctx);
extern unsigned long compare_and_swap(unsigned long *addr, unsigned long old, unsigned long new);
extern unsigned int compare_and_swap_int(unsigned int *addr, unsigned int old, unsigned int new);
extern int archdep_syscall(struct syscall_wait_desc *w, long *ret);
