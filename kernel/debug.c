#include <stdarg.h>
#include <string.h>
#include <kmsg.h>
#include <aal/debug.h>
#include <aal/lock.h>

struct aal_kmsg_buf kmsg_buf AAL_KMSG_ALIGN;

extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
static aal_spinlock_t kmsg_lock;

/* TODO: lock */
void kputs(char *buf)
{
	int len = strlen(buf);
	unsigned long flags;

	flags = aal_mc_spinlock_lock(&kmsg_lock);

	if (len + kmsg_buf.tail > kmsg_buf.len) {
		len = kmsg_buf.len - kmsg_buf.tail;
	}
	
	strncpy(kmsg_buf.str + kmsg_buf.tail, buf, len);
	kmsg_buf.tail += len;

	aal_mc_spinlock_unlock(&kmsg_lock, flags);
}

int kprintf(const char *format, ...)
{
	int len;
	va_list va;
	unsigned long flags;

	va_start(va, format);

	flags = aal_mc_spinlock_lock(&kmsg_lock);

	len = vsnprintf(kmsg_buf.str + kmsg_buf.tail,
	                kmsg_buf.len - kmsg_buf.tail, format, va);
	kmsg_buf.tail += len;

	aal_mc_spinlock_unlock(&kmsg_lock, flags);

	va_end(va);

	return len;
}

void kmsg_init(void)
{
	aal_mc_spinlock_init(&kmsg_lock);
	kmsg_buf.tail = 0;
	kmsg_buf.len = sizeof(kmsg_buf.str);
}
