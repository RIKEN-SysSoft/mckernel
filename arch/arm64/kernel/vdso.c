/* vdso.c COPYRIGHT FUJITSU LIMITED 2016-2018 */
/* @ref.impl arch/arm64/kernel/vdso.c */

#include <arch-memory.h>
#include <compiler.h>
#include <errno.h>
#include <kmalloc.h>
#include <linkage.h>
#include <memory.h>
#include <page.h>
#include <process.h>
#include <string.h>
#include <syscall.h>
#include <ikc/queue.h>
#include <vdso.h>
#include <ihk/debug.h>

//#define DEBUG_PRINT_VDSO

#ifdef DEBUG_PRINT_VDSO
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#define VDSO_MAXPAGES 1
struct vdso {
	long busy;
	int vdso_npages;
	int padding;
	long vdso_physlist[VDSO_MAXPAGES];
	long vvar_phys;
	long lbase;
	long offset_sigtramp;
};

extern char vdso_start, vdso_end;
static struct vdso vdso;

struct tod_data_s tod_data
		__attribute__ ((section (".vdso.data"))) = {
	.do_local = 0,
	.version = IHK_ATOMIC64_INIT(0),
};

void* vdso_symbol_sigtramp(unsigned long base)
{
	return (void *)(vdso.offset_sigtramp - vdso.lbase + base);
}

static int vdso_get_vdso_info(void)
{
	int error;
	struct ikc_scd_packet packet;
	struct ihk_ikc_channel_desc *ch = cpu_local_var(ikc2linux);

	dkprintf("vdso_get_vdso_info()\n");
	memset(&vdso, '\0', sizeof vdso);
	vdso.busy = 1;
	vdso.vdso_npages = 0;

	packet.msg = SCD_MSG_GET_VDSO_INFO;
	packet.arg = virt_to_phys(&vdso);

	error = ihk_ikc_send(ch, &packet, 0);
	if (error) {
		ekprintf("vdso_get_vdso_info: ihk_ikc_send failed. %d\n", error);
		goto out;
	}

	while (vdso.busy) {
		cpu_pause();
	}
	error = 0;
out:
	if (error) {
		vdso.vdso_npages = 0;
	}
	dkprintf("vdso_get_vdso_info(): %d\n", error);
	return error;
}

int arch_setup_vdso(void)
{
	if (!vdso_get_vdso_info() && vdso.vdso_npages != 0) {
		kprintf("Enable Host mapping vDSO.\n");
		return 0;
	}

	panic("Only support host mapping vDSO");
	return -1;
}

static int get_free_area(struct process_vm *vm, size_t len, intptr_t hint,
		      int pgshift, intptr_t *addrp)
{
	struct vm_regions *region = &vm->region;
	intptr_t addr;
	int error;
	struct vm_range *range;
	size_t pgsize = (size_t)1 << pgshift;

	dkprintf("get_free_area(%lx,%lx,%d,%p)\n", len, hint, pgshift, addrp);

	addr = hint;
	for (;;) {
		addr = (addr + pgsize - 1) & ~(pgsize - 1);
		if ((region->user_end <= addr)
				|| ((region->user_end - len) < addr)) {
			ekprintf("get_free_area(%lx,%lx,%p):"
					"no space. %lx %lx\n",
					len, hint, addrp, addr,
					region->user_end);
			error = -ENOMEM;
			goto out;
		}

		range = lookup_process_memory_range(vm, addr, addr+len);
		if (range == NULL) {
			break;
		}
		addr = range->end;
	}

	error = 0;
	*addrp = addr;

out:
	dkprintf("get_free_area(%lx,%lx,%d,%p): %d %lx\n",
			len, hint, pgshift, addrp, error, addr);
	return error;
}

int arch_map_vdso(struct process_vm *vm)
{
	unsigned long vdso_base, vdso_text_len, vdso_mapping_len;
	unsigned long start, end;
	unsigned long flag;
	int ret;
	struct vm_range *range;

	vdso_text_len = vdso.vdso_npages << PAGE_SHIFT;
	/* Be sure to map the data page */
	vdso_mapping_len = vdso_text_len + PAGE_SIZE;

	ret = get_free_area(vm, vdso_mapping_len, TASK_UNMAPPED_BASE,
				PAGE_SHIFT, (intptr_t *)&vdso_base);
	if (ret != 0) {
		dkprintf("arch_map_vdso:get_free_area(%lx,%lx) failed. %d\n",
			 vdso_mapping_len, TASK_UNMAPPED_BASE, ret);
		goto exit;
	}

	start = vdso_base;
	end = vdso_base + PAGE_SIZE;
	flag = VR_REMOTE | VR_PROT_READ;
	flag |= VRFLAG_PROT_TO_MAXPROT(flag);
	ret = add_process_memory_range(vm, start, end, vdso.vvar_phys, flag,
				       NULL, 0, PAGE_SHIFT, NULL, &range);
	if (ret != 0){
		dkprintf("ERROR: adding memory range for tod_data\n");
		goto exit;
	}
	vm->vvar_addr = (void *)start;

	start = end;
	end = start + vdso_text_len;
	flag = VR_REMOTE | VR_PROT_READ | VR_PROT_EXEC;
	flag |= VRFLAG_PROT_TO_MAXPROT(flag);
	ret = add_process_memory_range(vm, start, end, vdso.vdso_physlist[0], flag,
				       NULL, 0, PAGE_SHIFT, NULL, &range);
	if (ret != 0) {
		dkprintf("ERROR: adding memory range for vdso_text\n");

		start = vdso_base;
		end = vdso_base + PAGE_SIZE;
		remove_process_memory_range(vm, start, end, NULL);

		goto exit;
	}
	vm->vdso_addr = (void *)start;

exit:
	return ret;
}
