#ifndef AAL_DEBUG_H
#define AAL_DEBUG_H

#include <aal/memconst.h>

struct aal_kmsg_buf {
	int tail;
	int len;
	char str[AAL_KMSG_SIZE - sizeof(int) * 2];
};

extern int kprintf(const char *format, ...);
extern int kprintf_lock();
extern void kprintf_unlock(int irqflags);
extern int __kprintf(const char *format, ...);

extern void panic(const char *msg);

#endif
