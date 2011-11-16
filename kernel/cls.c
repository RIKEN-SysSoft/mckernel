#include <kmsg.h>
#include <string.h>
#include <aal/cpu.h>
#include <aal/debug.h>
#include <aal/lock.h>
#include <aal/mm.h>
#include <aal/page_alloc.h>
#include <cls.h>
#include <page.h>

extern int num_processors;

static struct cpu_local_var *clv;

void cpu_local_var_init(void)
{
	int z;

	z = sizeof(struct cpu_local_var) * num_processors;
	z = (z + PAGE_SIZE - 1) >> PAGE_SHIFT;

	clv = allocate_pages(z, 0);
	memset(clv, 0, z * PAGE_SIZE);
}

struct cpu_local_var *get_cpu_local_var(int id)
{
	return clv + id;
}
