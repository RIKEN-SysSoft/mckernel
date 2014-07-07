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
	struct coretable *ct;
	Elf64_Ehdr eh;
	Elf64_Phdr *ph;
	void *note;
	struct vm_range *range;
	struct process_vm *vm = proc->vm;
	int segs = 1;	/* the first one is for NOTES */
	int notesize, phsize;
	unsigned int offset = 0;
	int i;

	if (vm == NULL) {
		dkprintf("no vm found.\n");
		return -1;
	}

	list_for_each_entry(range, &vm->vm_range_list, list) {
		dkprintf("start:%x end:%x flag:%x objoff:%x\n", 
			 range->start, range->end, range->flag, range->objoff);
		if ((range->flag && VR_RESERVED) == 0)
			segs++;
	}
	dkprintf("we have %d segs including one for NOTES.\n\n", segs);

	{
		struct vm_regions region = proc->vm->region;

		dkprintf("text:  %x-%x\n", region.text_start, region.text_end);
		dkprintf("data:  %x-%x\n", region.data_start, region.data_end);
		dkprintf("brk:   %x-%x\n", region.brk_start, region.brk_end);
		dkprintf("map:   %x-%x\n", region.map_start, region.map_end);
		dkprintf("stack: %x-%x\n", region.stack_start, region.stack_end);
		dkprintf("user:  %x-%x\n\n", region.user_start, region.user_end);

	}

	dkprintf("now generate a core file image\n");

#define DUMMY

#ifndef DUMMY

	/* ELF header */

	eh.e_ident[EI_MAG0] = 0x7f;
	eh.e_ident[EI_MAG1] = 'E';
	eh.e_ident[EI_MAG2] = 'L';
	eh.e_ident[EI_MAG3] = 'F';
	eh.e_ident[EI_CLASS] = ELFCLASS64;
	eh.e_ident[EI_DATA] = ELFDATA2LSB;
	eh.e_ident[EI_VERSION] = El_VERSION;
	eh.e_ident[EI_OSABI] = ELFOSABI_NONE;
	eh.e_ident[EI_ABIVERSION] = El_ABIVERSION_NONE;
	eh.e_type = ET_CORE;
	eh.e_machine = EM_K10M;
	eh.e_version = EV_CURRENT;
	eh.e_entry = 0;		/* Do we really need this? */
	eh.e_phoff = 64;	/* fixed */
	eh.e_shoff = 0;		/* no section header */
	eh.e_flags = 0;
	eh.e_ehsize = 64;	/* fixed */
	eh.e_phentsize = 56;	/* fixed */
	eh.e_phnum = segs;
	eh.e_shentsize = 0;
	eh.e_shnum = 0;
	eh.e_shstrndx = 0;

	offset += 64;

	notesize = 1024; /* dummy */

	/* program header table */

	phsize = sizeof(Elf64_Phdr) * segs;
	ph = kmalloc(phsize, IHK_MC_AP_NOWAIT);
	if (ph == NULL) {
		dkprintf("could not alloc a program header table.\n");
		goto fail;
	}

	offset += phsize;

	/* prgram header for NOTE segment is exceptional */

	ph[0].p_type = PT_NOTE;
	ph[0].p_flags = 0;
	ph[0].p_offset = offset;
	ph[0].p_vaddr = 0;
	ph[0].p_paddr = 0;
	ph[0].p_filesz = 0;
	ph[0].p_memsz = notesize;
	ph[0].p_align = 1024;

	/* program header for each memory chunk */
	i = 1;
	list_for_each_entry(range, &vm->vm_range_list, list) {
		unsigned long flag = range->flag;
		unsigned long size = range->end - range->start;

		ph[i].p_type = PT_LOAD;
/* xxx */
		ph[i].p_flags = ((flag & VR_PROT_READ) ? PF_R : 0)
			| ((flag & VR_PROT_WRITE) ? PF_W : 0)
			| ((flag & VR_PROT_EXEC) ? PF_X : 0);
		ph[i].p_offset = offset;
		ph[i].p_vaddr = range->start;
		ph[i].p_paddr = 0;
		ph[i].p_filesz = 0;	/* How can we know this? */ 
		ph[i].p_memsz = size;
		ph[i].p_align = 1024;	/* ??? */
		i++;
		offset += size;
	}

	/* note */ 

	note = kmalloc(notesize, IHK_MC_AP_NOWAIT);	
	if (note == NULL) {
		dkprintf("could not alloc note.\n");
		goto fail;
	}

	/* coretable to send to host */
	ct = kmalloc(sizeof(struct coretable) * (segs + 2), IHK_MC_AP_NOWAIT);
	if (!ct) {
		dkprintf("could not alloc a coretable.\n");
		goto fail;
	}

	ct[0].addr = virt_to_phys(&eh);	/* ELF header */
	ct[0].len = 64; 

	ct[1].addr = virt_to_phys(ph);	/* program header table */
	ct[1].len = phsize;

	ct[2].addr = virt_to_phys(note);	/* NOTE segment */
	ct[2].len = notesize;

	i = 3;	/* memory segments */
	list_for_each_entry(range, &vm->vm_range_list, list) {
		ct[i].addr = virt_to_phys(range->start);
		ct[i].len = range->end - range->start;
		i++;
	}
	*chunks = segs + 2;
	
#else /* dummy */
	*coretable = kmalloc(sizeof(struct coretable) * 3, IHK_MC_AP_NOWAIT);
	if (!*coretable) {
		dkprintf("could not alloc a coretable.\n");
		goto fail;
	}

	ct[0].len = 8;
	ct[0].addr = virt_to_phys("this is ");
	ct[1].len = 7;
	ct[1].addr = virt_to_phys("a test ");
	ct[2].len = 15;
	ct[2].addr = virt_to_phys("for coredump.\n");

	dkprintf("generated a core table.\n");

	*chunks = 3;
#endif
	*coretable = ct;
	return 0;

	fail:
	if (ct)
		kfree(ct);
	if (ph)
		kfree(ph);
	if (note)
		kfree(note);
	return -1;
}

/* Free all the allocated spaces. */

void freecore(struct coretable **coretable)
{
	struct coretable *ct = *coretable;
	kfree(phys_to_virt(ct[2].addr));	/* NOTE segment */
	kfree(phys_to_virt(ct[1].addr));	/* ph */
	kfree(*coretable);
}
