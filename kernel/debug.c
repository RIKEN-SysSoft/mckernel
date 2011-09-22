#include <stdarg.h>
#include <string.h>
#include <kmsg.h>
#include <aal/debug.h>

struct aal_kmsg_buf kmsg_buf AAL_KMSG_ALIGN;

extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);

/* TODO: lock */
void kputs(char *buf)
{
	int len = strlen(buf);
	
	if (len + kmsg_buf.tail > kmsg_buf.len) {
		len = kmsg_buf.len - kmsg_buf.tail;
	}
	
	strncpy(kmsg_buf.str, buf, len);
	kmsg_buf.tail += len;
}

int kprintf(const char *format, ...)
{
	int len;
	va_list va;

	va_start(va, format);

	len = vsnprintf(kmsg_buf.str + kmsg_buf.tail,
	                kmsg_buf.len - kmsg_buf.tail, format, va);
	kmsg_buf.tail += len;

	va_end(va);

	return len;
}

void kmsg_init(void)
{
	kmsg_buf.tail = 0;
	kmsg_buf.len = sizeof(kmsg_buf.str);
}
