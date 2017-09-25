/**
 * \file debug.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Output to kmsg
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#include <stdarg.h>
#include <string.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <ihk/lock.h>
#include <ihk/monitor.h>
#include <errno.h>

struct ihk_kmsg_buf *kmsg_buf;

extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
extern int sprintf(char * buf, const char *fmt, ...);
extern void eventfd(int type);
static ihk_spinlock_t kmsg_lock;
extern char *find_command_line(char *name);

#define DEBUG_KMSG_USED (((unsigned int)kmsg_buf->tail - (unsigned int)kmsg_buf->head) % (unsigned int)kmsg_buf->len)
#define DEBUG_KMSG_MARGIN (kmsg_buf->head == kmsg_buf->tail ? kmsg_buf->len : (((unsigned int)kmsg_buf->head - (unsigned int)kmsg_buf->tail) % (unsigned int)kmsg_buf->len))

unsigned long kprintf_lock(void)
{
	return __ihk_mc_spinlock_lock(&kmsg_lock);
}

void kprintf_unlock(unsigned long irqflags)
{
	__ihk_mc_spinlock_unlock(&kmsg_lock, irqflags);
}

#define debug_spin_lock_irqsave(lock, flags) do {						\
		flags = cpu_disable_interrupt_save();							\
		while (__sync_val_compare_and_swap(lock, 0, 1) != 0) {			\
			cpu_pause();												\
		}																\
	} while (0)

#define debug_spin_unlock_irqrestore(lock, flags) do {					\
		*(lock) = 0;													\
		cpu_restore_interrupt(flags);									\
	} while (0)

static void memcpy_ringbuf(char* buf, int len) {
	int i;
	for(i = 0; i < len; i++) {
		*(kmsg_buf->str + kmsg_buf->tail) = *(buf + i);
		kmsg_buf->tail = (kmsg_buf->tail + 1) % kmsg_buf->len;
	}
}

void kputs(char *buf)
{
	int len = strlen(buf);
	unsigned long flags_outer, flags_inner;
	int overflow;

	if (kmsg_buf == NULL) {
		return;
	}

	flags_outer = kprintf_lock(); /* Guard from destruction */
	debug_spin_lock_irqsave(&kmsg_buf->lock, flags_inner); /* For consistency */

	overflow = DEBUG_KMSG_MARGIN <= len;

	memcpy_ringbuf(buf, len);
	
	if (overflow) {
		kmsg_buf->head = (kmsg_buf->tail + 1) % kmsg_buf->len;
	}

	debug_spin_unlock_irqrestore(&kmsg_buf->lock, flags_inner);
	kprintf_unlock(flags_outer);

	if (DEBUG_KMSG_USED > IHK_KMSG_HIGH_WATER_MARK) {
		eventfd(IHK_OS_EVENTFD_TYPE_KMSG);
		ihk_mc_delay_us(IHK_KMSG_NOTIFY_DELAY);
	}
}

#define KPRINTF_LOCAL_BUF_LEN 1024

/* Caller must hold kmsg_lock! */
int __kprintf(const char *format, ...)
{
	int len = 0;
	va_list va;
	char buf[KPRINTF_LOCAL_BUF_LEN];
	int overflow;
	unsigned long flags_inner;

	if (kmsg_buf == NULL) {
		return -EINVAL;
	}

	/* Copy into the local buf */
	len = sprintf(buf, "[%3d]: ", ihk_mc_get_processor_id());

	va_start(va, format);
	len += vsnprintf(buf + len, KPRINTF_LOCAL_BUF_LEN - len - 2, format, va);
	va_end(va);

	debug_spin_lock_irqsave(&kmsg_buf->lock, flags_inner);

	overflow = DEBUG_KMSG_MARGIN <= len;

	memcpy_ringbuf(buf, len);

	if (overflow) {
		kmsg_buf->head = (kmsg_buf->tail + 1) % kmsg_buf->len;
	}

	debug_spin_unlock_irqrestore(&kmsg_buf->lock, flags_inner);

	if (DEBUG_KMSG_USED > IHK_KMSG_HIGH_WATER_MARK) {
		eventfd(IHK_OS_EVENTFD_TYPE_KMSG);
		ihk_mc_delay_us(IHK_KMSG_NOTIFY_DELAY);
	}

	return len;
}

int kprintf(const char *format, ...)
{
	int len = 0;
	va_list va;
	unsigned long flags_outer, flags_inner;
	char buf[KPRINTF_LOCAL_BUF_LEN];
	int overflow;

	if (kmsg_buf == NULL) {
		return -EINVAL;
	}

	/* Copy into the local buf */
	len = sprintf(buf, "[%3d]: ", ihk_mc_get_processor_id());

	va_start(va, format);
	len += vsnprintf(buf + len, KPRINTF_LOCAL_BUF_LEN - len - 2, format, va);
	va_end(va);

	flags_outer = kprintf_lock();
	debug_spin_lock_irqsave(&kmsg_buf->lock, flags_inner);

	overflow = DEBUG_KMSG_MARGIN <= len;
	
	memcpy_ringbuf(buf, len);

	if (overflow) {
		kmsg_buf->head = (kmsg_buf->tail + 1) % kmsg_buf->len;
	}

	debug_spin_unlock_irqrestore(&kmsg_buf->lock, flags_inner);
	kprintf_unlock(flags_outer);

	if (DEBUG_KMSG_USED > IHK_KMSG_HIGH_WATER_MARK) {
		eventfd(IHK_OS_EVENTFD_TYPE_KMSG);
		ihk_mc_delay_us(IHK_KMSG_NOTIFY_DELAY);
	}

	barrier();
	return len;
}

void kmsg_init()
{
	ihk_mc_spinlock_init(&kmsg_lock);
}
