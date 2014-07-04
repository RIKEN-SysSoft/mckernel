#include <ihk/debug.h>
#include <kmalloc.h>
#include <cls.h>
#include <list.h>
#include <process.h>
#include <elfcore.h>

#define DEBUG_PRINT_GENCORE

#ifdef DEBUG_PRINT_GENCORE
#define	dkprintf(...)	kprintf(__VA_ARGS__)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#else
#define dkprintf(...)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#endif

/*
 * Generate a core file image, which consists of many chunks.
 * Returns an allocated table, an etnry of which is a pair of the address 
 * of a chunk and its length.
 */

int gencore(struct process *proc, void *regs, 
	    struct coretable **coretable, int *chunks)
{
	Elf64_Ehdr eh;

	{
		struct vm_regions region = proc->vm->region;

		dkprintf("text: %x-%x\n", region.text_start, region.text_end);
		dkprintf("data: %x-%x\n", region.data_start, region.data_end);
		dkprintf("brk: %x-%x\n", region.brk_start, region.brk_end);
		dkprintf("map: %x-%x\n", region.map_start, region.map_end);
		dkprintf("stack: %x-%x\n", region.stack_start, region.stack_end);
		dkprintf("user: %x-%x\n", region.user_start, region.user_end);

	}

	{
		struct vm_range *range;
		struct process_vm *vm = proc->vm;

		if (vm == NULL) {
			dkprintf("no vm found.\n");
			return -1;
		}

		list_for_each_entry(range, &vm->vm_range_list, list) {
			dkprintf("start:%x end:%x flag:%x objoff:%x\n", 
				 range->start, range->end, range->flag, range->objoff);
		}
	}





	/* ELF header */

	eh.e_ident[EI_MAG0] = 0x7f;
	eh.e_ident[EI_MAG1] = 'E';
	eh.e_ident[EI_MAG2] = 'L';
	eh.e_ident[EI_MAG3] = 'F';
	eh.e_ident[EI_CLASS] = ELFCLASS64;
	eh.e_ident[EI_DATA] = ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = El_VERSION;
	eh.e_ident[EI_OSABI] = ELFOSABI_NONE;
	eh.e_ident[EI_ABIVERSION] = EI_ABIVERSION;
	eh.e_type = ET_CORE;
	eh.e_machine = EM_K10M;
	eh.e_version = EV_CURRENT;

	dkprintf("now generate a core file image\n");

	/* program header table */
	/* segments */

	*coretable = kmalloc(sizeof(struct coretable) * 3, IHK_MC_AP_NOWAIT);
	if (!*coretable) {
		dkprintf("could not alloc a coretable.\n");
		return -1;
	}

	(*coretable)[0].len = 8;
	(*coretable)[0].addr = virt_to_phys("this is ");
	(*coretable)[1].len = 7;
	(*coretable)[1].addr = virt_to_phys("a test ");
	(*coretable)[2].len = 15;
	(*coretable)[2].addr = virt_to_phys("for coredump.\n");

	dkprintf("generated a core table.\n");

	*chunks = 3;

	return 0;
}
