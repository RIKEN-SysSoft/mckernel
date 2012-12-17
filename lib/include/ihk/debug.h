#ifndef IHK_DEBUG_H
#define IHK_DEBUG_H

#include <ihk/memconst.h>

struct ihk_kmsg_buf {
	int tail;
	int len;
	char str[IHK_KMSG_SIZE - sizeof(int) * 2];
};

extern int kprintf(const char *format, ...);
extern int kprintf_lock();
extern void kprintf_unlock(int irqflags);
extern int __kprintf(const char *format, ...);

extern void panic(const char *msg);

#endif
