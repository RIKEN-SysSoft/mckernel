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
#include <ihk/debug.h>
#include <ihk/lock.h>

struct ihk_kmsg_buf kmsg_buf IHK_KMSG_ALIGN;

extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
extern int sprintf(char * buf, const char *fmt, ...);
static ihk_spinlock_t kmsg_lock;

static unsigned long kprintf_lock_head(void);
static void kprintf_unlock_head(unsigned long irqflags);

static void kprintf_wait(int len, unsigned long *flags_head, int *slide) {
	int head, tail, buf_len, mode, adj;

	mode = kmsg_buf.mode;
	while (1) {
		adj = 0;
		tail = kmsg_buf.tail;
		buf_len = kmsg_buf.len;
		head = kmsg_buf.head;
		if (head < tail) head += buf_len;
		if (tail + len > buf_len) adj = buf_len - tail;
		if (head > tail && head <= tail + len + adj) {
			/* When proceeding tail (producer pointer) by len would
			   cross head (consumer pointer) in ring-buffer */
			if (mode != 1) {
				*slide = 1;
				break;
			} else {
				kprintf_unlock_head(*flags_head);
				*flags_head = kprintf_lock_head();
			}
		} else {
			break;
		}
	}
}

/* TODO: lock */
void kputs(char *buf)
{
	int len = strlen(buf);
	int slide = 0;
	unsigned long flags_tail, flags_head;

	flags_tail = kprintf_lock();
	flags_head = kprintf_lock_head();
	kprintf_wait(len, &flags_head, &slide);

	if (len + kmsg_buf.tail > kmsg_buf.len) {
		kmsg_buf.tail = 0;
		if(len > kmsg_buf.len) {
			len = kmsg_buf.len;
		}
	}
	
	memcpy(kmsg_buf.str + kmsg_buf.tail, buf, len);
	kmsg_buf.tail += len;
	/* When proceeding tail (producer pointer) by len would
	   cross head (consumer pointer) in ring-buffer, give up
	   [head, tail] because the range is overwritten */
	if (slide == 1) {
		kmsg_buf.head = kmsg_buf.tail + 1;
		if (kmsg_buf.head >= kmsg_buf.len) kmsg_buf.head = 0;
	}
	kprintf_unlock_head(flags_head);
	kprintf_unlock(flags_tail);
}

#define KPRINTF_LOCAL_BUF_LEN 1024

unsigned long kprintf_lock(void)
{
	return __ihk_mc_spinlock_lock(&kmsg_lock);
}

void kprintf_unlock(unsigned long irqflags)
{
	__ihk_mc_spinlock_unlock(&kmsg_lock, irqflags);
}

static unsigned long kprintf_lock_head(void)
{
	return __ihk_mc_spinlock_lock(&kmsg_buf.lock);
}

static void kprintf_unlock_head(unsigned long irqflags)
{
	__ihk_mc_spinlock_unlock(&kmsg_buf.lock, irqflags);
}

/* Caller must hold kmsg_lock! */
int __kprintf(const char *format, ...)
{
	int len = 0;
	int slide = 0;
	va_list va;
	unsigned long flags_head;
	char buf[KPRINTF_LOCAL_BUF_LEN];

	/* Copy into the local buf */
	len = sprintf(buf, "[%3d]: ", ihk_mc_get_processor_id());
	va_start(va, format);
	len += vsnprintf(buf + len, KPRINTF_LOCAL_BUF_LEN - len - 2, format, va);
	va_end(va);

	flags_head = kprintf_lock_head();
	kprintf_wait(len, &flags_head, &slide);

	/* Append to kmsg buffer */
	if (kmsg_buf.tail + len > kmsg_buf.len) {
		kmsg_buf.tail = 0;
	}

	memcpy(kmsg_buf.str + kmsg_buf.tail, buf, len);
	kmsg_buf.tail += len;
	if (slide == 1) {
		kmsg_buf.head = kmsg_buf.tail + 1;
		if (kmsg_buf.head >= kmsg_buf.len) kmsg_buf.head = 0;
	}

	kprintf_unlock_head(flags_head);
	return len;
}

int kprintf(const char *format, ...)
{
	int len = 0;
	int slide = 0;
	va_list va;
	unsigned long flags_tail, flags_head;
	char buf[KPRINTF_LOCAL_BUF_LEN];

	/* Copy into the local buf */
	len = sprintf(buf, "[%3d]: ", ihk_mc_get_processor_id());
	va_start(va, format);
	len += vsnprintf(buf + len, KPRINTF_LOCAL_BUF_LEN - len - 2, format, va);
	va_end(va);

	flags_tail = kprintf_lock();
	flags_head = kprintf_lock_head();
	kprintf_wait(len, &flags_head, &slide);

	/* Append to kmsg buffer */
	if (kmsg_buf.tail + len > kmsg_buf.len) {
		kmsg_buf.tail = 0;
	}

	memcpy(kmsg_buf.str + kmsg_buf.tail, buf, len);
	kmsg_buf.tail += len;
	if (slide == 1) {
		kmsg_buf.head = kmsg_buf.tail + 1;
		if (kmsg_buf.head >= kmsg_buf.len) kmsg_buf.head = 0;
	}

	kprintf_unlock_head(flags_head);
	kprintf_unlock(flags_tail);

	return len;
}

/* mode:
    0: mcklogd is not running.
       When kmsg buffer is full, writer doesn't block
       and overwrites the buffer.
    1: mcklogd periodically retrieves kmsg.
       When kmsg buffer is full, writer blocks until 
       someone retrieves kmsg.
    2: mcklogd periodically retrieves kmsg.
       When kmsg buffer is full, writer doesn't block
       and overwrites the buffer.
*/
void kmsg_init(int mode)
{
	ihk_mc_spinlock_init(&kmsg_lock);
	kmsg_buf.tail = 0;
	kmsg_buf.len = sizeof(kmsg_buf.str);
	kmsg_buf.head = 0;
	kmsg_buf.mode = mode;
	ihk_mc_spinlock_init(&kmsg_buf.lock);
	memset(kmsg_buf.str, 0, kmsg_buf.len);
}
