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
#include <sysfs.h>
#include <debug.h>
#include <limits.h>

struct ihk_kmsg_buf *kmsg_buf;

extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
extern int snprintf(char *buf, size_t size, const char *fmt, ...);
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

	if (irqflags_can_interrupt(flags_outer) &&
			DEBUG_KMSG_USED > IHK_KMSG_HIGH_WATER_MARK) {
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
	len = snprintf(buf, KPRINTF_LOCAL_BUF_LEN, "[%3d]: ",
		       ihk_mc_get_processor_id());

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
	if (irqflags_can_interrupt(flags_inner) &&
			DEBUG_KMSG_USED > IHK_KMSG_HIGH_WATER_MARK) {
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
	len = snprintf(buf, KPRINTF_LOCAL_BUF_LEN, "[%3d]: ",
		       ihk_mc_get_processor_id());

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

	if (irqflags_can_interrupt(flags_outer) &&
			DEBUG_KMSG_USED > IHK_KMSG_HIGH_WATER_MARK) {
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

extern struct ddebug __start___verbose[];
extern struct ddebug __stop___verbose[];

static ssize_t dynamic_debug_sysfs_show(struct sysfs_ops *ops,
		void *instance, void *buf, size_t size)
{
	struct ddebug *dbg;
	ssize_t n = 0;

	n = snprintf(buf, size, "# filename:lineno function flags format\n");

	for (dbg = __start___verbose; dbg < __stop___verbose; dbg++) {
		n += snprintf(buf + n, size - n, "%s:%d %s =%s\n",
				dbg->file, dbg->line, dbg->func,
				dbg->flags ? "p" : "_");

		if (n >= size)
			break;
	}

	return n;
}

static ssize_t dynamic_debug_sysfs_store(struct sysfs_ops *ops,
		void *instance, void *buf, size_t size)
{
	char *cur = buf;
	char *file = NULL, *func = NULL;
	long int line_start = 0, line_end = INT_MAX;
	int set_flag = -1;
	struct ddebug *dbg;


	// assume line was new-line terminated and squash last newline
	cur[size-1] = '\0';

	/* basic line parsing, combinaisons of:
	 *   file <file>
	 *   func <func>
	 *   line <line|line-line|line-|-line>
	 *   and must end with [+-=][p_] (set/clear print flag)
	 */
again:
	while (cur && cur < ((char *)buf) + size && *cur) {
		dkprintf("looking at %.*s, size left %d\n",
			size - (cur - (char *)buf), cur,
			(char *)buf - cur + size);

		if (strncmp(cur, "func ", 5) == 0) {
			cur += 5;
			func = cur;
		} else if (strncmp(cur, "file ", 5) == 0) {
			cur += 5;
			file = cur;
		} else if (strncmp(cur, "line ", 5) == 0) {
			cur += 5;
			if (*cur != '-') {
				line_start = strtol(cur, &cur, 0);
			}
			if (*cur != '-') {
				line_end = line_start;
			} else {
				cur++;
				if (*cur == ' ' || *cur == '\0') {
					line_end = INT_MAX;
				} else {
					line_end = strtol(cur, &cur, 0);
				}
			}
		} else if (strchr("+-=", *cur)) {
			switch ((*cur) + 256 * (*(cur+1))) {
			case '+' + 256*'p':
			case '=' + 256*'p':
				set_flag = DDEBUG_PRINT;
				break;
			case '-' + 256*'p':
			case '=' + 256*'_':
				set_flag = DDEBUG_NONE;
				break;
			default:
				kprintf("invalid flag: %.*s\n",
					size - (cur - (char *)buf), cur);
				return -EINVAL;
			}
			/* XXX check 3rd char is end of input or \n or ; */
			cur += 3;
			break;

		} else {
			kprintf("dynamic debug control: unrecognized keyword: %.*s\n",
				size - (cur - (char *)buf), cur);
			return -EINVAL;
		}
		cur = strpbrk(cur, " \n");
		if (cur) {
			*cur = '\0';
			cur++;
		}
	}
	dkprintf("func %s, file %s, lines %d-%d, flag %x\n",
		func, file, line_start, line_end, set_flag);

	if (set_flag < 0) {
		kprintf("dynamic debug control: no flag set?\n");
		return -EINVAL;
	}
	if (!func && !file) {
		kprintf("at least file or func should be set\n");
		return -EINVAL;
	}

	for (dbg = __start___verbose; dbg < __stop___verbose; dbg++) {
		/* TODO: handle wildcards */
		if ((!func || strcmp(func, dbg->func) == 0) &&
		    (!file || strcmp(file, dbg->file) == 0) &&
		    dbg->line >= line_start &&
		    dbg->line <= line_end) {
			dbg->flags = set_flag;
		}
	}

	if (cur && cur < ((char *)buf) + size && *cur)
		goto again;

	return size;
}

static struct sysfs_ops dynamic_debug_sysfs_ops = {
	.show = &dynamic_debug_sysfs_show,
	.store = &dynamic_debug_sysfs_store,
};

void dynamic_debug_sysfs_setup(void)
{
	int error;

	error = sysfs_createf(&dynamic_debug_sysfs_ops, NULL, 0644,
			      "/sys/kernel/debug/dynamic_debug/control");
	if (error) {
		kprintf("%s: ERROR: creating dynamic_debug/control sysfs file",
			__func__);
	}
}
