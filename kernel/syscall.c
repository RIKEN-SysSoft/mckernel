#include <types.h>
#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <errno.h>

int syscall(int num, aal_mc_user_context_t *ctx)
{
	kprintf("System call #%d\n", num);

	return -ENOSYS;
}
