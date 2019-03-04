#ifndef IHK_DEBUG_H
#define IHK_DEBUG_H

#include "lwk/compiler.h"

void __noreturn panic(const char *);

/* when someone has a lot of time, add attribute __printf(1, 2) to kprintf */
int kprintf(const char *format, ...);
unsigned long kprintf_lock(void);
void kprintf_unlock(unsigned long irqflags);
int __kprintf(const char *format, ...);

struct ddebug {
	const char *file;
	const char *func;
	const char *fmt;
	unsigned int line:24;
	unsigned int flags:8;
} __aligned(8);

#define DDEBUG_NONE  0x0
#define DDEBUG_PRINT 0x1

#define DDEBUG_DEFAULT DDEBUG_NONE

#define DDEBUG_SYMBOL()                                  \
	static struct ddebug __aligned(8)                \
	__attribute__((section("__verbose"))) ddebug = { \
		.file = __FILE__,                        \
		.func = __func__,                        \
		.line = __LINE__,                        \
		.flags = DDEBUG_DEFAULT,                 \
	}

#define DDEBUG_TEST ddebug.flags



#define dkprintf(fmt, args...)        \
do {                                  \
	DDEBUG_SYMBOL();              \
	if (DDEBUG_TEST)              \
		kprintf(fmt, ##args); \
} while (0)
#define ekprintf(fmt, args...) kprintf(fmt, ##args)

#define BUG_ON(condition) do {                         \
	if (condition) {                               \
		kprintf("PANIC: %s: %s(line:%d)\n",    \
			__FILE__, __func__, __LINE__); \
		panic("");                             \
	}                                              \
} while (0)

#define STATIC_ASSERT(cond) _STATIC_ASSERT(cond, __LINE__)
#define _STATIC_ASSERT(cond, line) __STATIC_ASSERT(cond, line)
#define __STATIC_ASSERT(cond, line)			\
	static void __static_assert_ ## line (void) {	\
		STATIC_ASSERT_LOCAL(cond);		\
	}
#define STATIC_ASSERT_LOCAL(cond) ((void)sizeof(struct { int:-!!!(cond); }))


#endif
