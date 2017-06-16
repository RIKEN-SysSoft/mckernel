#include <ihk/debug.h>
#include <kmalloc.h>
#include <cls.h>
#include <list.h>
#include <process.h>
#include <string.h>
#include <elfcore.h>

#define	align32(x) ((((x) + 3) / 4) * 4)
#define	alignpage(x) ((((x) + (PAGE_SIZE) - 1) / (PAGE_SIZE)) * (PAGE_SIZE))

//#define DEBUG_PRINT_GENCORE

#ifdef DEBUG_PRINT_GENCORE
#define	dkprintf(...)	kprintf(__VA_ARGS__)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#else
#define dkprintf(...)	do { if (0) kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#endif

/*
 * Generate a core file image, which consists of many chunks.
 * Returns an allocated table, an etnry of which is a pair of the address 
 * of a chunk and its length.
 */

/**
 * \brief Fill the elf header.
 *
 * \param eh An Elf64_Ehdr structure.
 * \param segs Number of segments of the core file.
 */

void fill_elf_header(Elf64_Ehdr *eh, int segs)
{
	eh->e_ident[EI_MAG0] = 0x7f;
	eh->e_ident[EI_MAG1] = 'E';
	eh->e_ident[EI_MAG2] = 'L';
	eh->e_ident[EI_MAG3] = 'F';
	eh->e_ident[EI_CLASS] = ELFCLASS64;
	eh->e_ident[EI_DATA] = ELFDATA2LSB;
	eh->e_ident[EI_VERSION] = El_VERSION;
	eh->e_ident[EI_OSABI] = ELFOSABI_NONE;
	eh->e_ident[EI_ABIVERSION] = El_ABIVERSION_NONE;

	eh->e_type = ET_CORE;
#ifdef CONFIG_MIC
	eh->e_machine = EM_K10M;
#else
	eh->e_machine = EM_X86_64;
#endif
	eh->e_version = EV_CURRENT;
	eh->e_entry = 0;	/* Do we really need this? */
	eh->e_phoff = 64;	/* fixed */
	eh->e_shoff = 0;	/* no section header */
	eh->e_flags = 0;
	eh->e_ehsize = 64;	/* fixed */
	eh->e_phentsize = 56;	/* fixed */
	eh->e_phnum = segs;
	eh->e_shentsize = 0;
	eh->e_shnum = 0;
	eh->e_shstrndx = 0;
}

/**
 * \brief Return the size of the prstatus entry of the NOTE segment.
 *
 */

int get_prstatus_size(void)
{
	return sizeof(struct note) + align32(sizeof("CORE")) 
		+ align32(sizeof(struct elf_prstatus64));
}

/**
 * \brief Fill a prstatus structure.
 *
 * \param head A pointer to a note structure.
 * \param thread A pointer to the current thread structure.
 * \param regs0 A pointer to a x86_regs structure.
 */

void fill_prstatus(struct note *head, struct thread *thread, void *regs0)
{
	void *name;
	struct elf_prstatus64 *prstatus; 
	struct x86_user_context *uctx = regs0;
	struct x86_basic_regs *regs = &uctx->gpr;
        register unsigned long _r12 asm("r12");
        register unsigned long _r13 asm("r13");
        register unsigned long _r14 asm("r14");
        register unsigned long _r15 asm("r15");

	head->namesz = sizeof("CORE");
	head->descsz = sizeof(struct elf_prstatus64);
	head->type = NT_PRSTATUS;
	name =  (void *) (head + 1);
	memcpy(name, "CORE", sizeof("CORE"));
	prstatus = (struct elf_prstatus64 *)(name + align32(sizeof("CORE")));

/*
  We ignore following entries for now.

	struct elf_siginfo pr_info;
	short int pr_cursig;
	a8_uint64_t pr_sigpend;
	a8_uint64_t pr_sighold;
	pid_t pr_pid;
	pid_t pr_ppid;
	pid_t pr_pgrp;
	pid_t pr_sid;
	struct prstatus64_timeval pr_utime;
	struct prstatus64_timeval pr_stime;
	struct prstatus64_timeval pr_cutime;
	struct prstatus64_timeval pr_cstime;
 */

	prstatus->pr_reg[0] = _r15;
	prstatus->pr_reg[1] = _r14;
	prstatus->pr_reg[2] = _r13;
	prstatus->pr_reg[3] = _r12;
	prstatus->pr_reg[4] = regs->rbp;
	prstatus->pr_reg[5] = regs->rbx;
	prstatus->pr_reg[6] = regs->r11;
	prstatus->pr_reg[7] = regs->r10;
	prstatus->pr_reg[8] = regs->r9;
	prstatus->pr_reg[9] = regs->r8;
	prstatus->pr_reg[10] = regs->rax;
	prstatus->pr_reg[11] = regs->rcx;
	prstatus->pr_reg[12] = regs->rdx;
	prstatus->pr_reg[13] = regs->rsi;
	prstatus->pr_reg[14] = regs->rdi;
	prstatus->pr_reg[15] = regs->rax;	/* ??? */
	prstatus->pr_reg[16] = regs->rip;
	prstatus->pr_reg[17] = regs->cs;
	prstatus->pr_reg[18] = regs->rflags;
	prstatus->pr_reg[19] = regs->rsp;
	prstatus->pr_reg[20] = regs->ss;
	prstatus->pr_reg[21] = rdmsr(MSR_FS_BASE);
	prstatus->pr_reg[22] = rdmsr(MSR_GS_BASE);
	/* There is no ds, es, fs and gs. */

	prstatus->pr_fpvalid = 0;	/* We assume no fp */
} 

/**
 * \brief Return the size of the prpsinfo entry of the NOTE segment.
 *
 */

int get_prpsinfo_size(void)
{
	return sizeof(struct note) + align32(sizeof("CORE")) 
		+ align32(sizeof(struct elf_prpsinfo64));
}

/**
 * \brief Fill a prpsinfo structure.
 *
 * \param head A pointer to a note structure.
 * \param thread A pointer to the current thread structure.
 * \param regs A pointer to a x86_regs structure.
 */

void fill_prpsinfo(struct note *head, struct thread *thread, void *regs)
{
	void *name;
	struct elf_prpsinfo64 *prpsinfo;

	head->namesz = sizeof("CORE");
	head->descsz = sizeof(struct elf_prpsinfo64);
	head->type = NT_PRPSINFO;
	name =  (void *) (head + 1);
	memcpy(name, "CORE", sizeof("CORE"));
	prpsinfo = (struct elf_prpsinfo64 *)(name + align32(sizeof("CORE")));

	prpsinfo->pr_state = thread->status;
	prpsinfo->pr_pid = thread->proc->pid;

/*
  We leave most of the fields unfilled.

	char pr_sname;
	char pr_zomb;
	char pr_nice;
	a8_uint64_t pr_flag;
	unsigned int pr_uid;
	unsigned int pr_gid;
	int pr_ppid, pr_pgrp, pr_sid;
	char pr_fname[16];
	char pr_psargs[ELF_PRARGSZ];
*/
} 

/**
 * \brief Return the size of the AUXV entry of the NOTE segment.
 *
 */

int get_auxv_size(void)
{
	return sizeof(struct note) + align32(sizeof("CORE")) 
		+ sizeof(unsigned long) * AUXV_LEN;
}

/**
 * \brief Fill an AUXV structure.
 *
 * \param head A pointer to a note structure.
 * \param thread A pointer to the current thread structure.
 * \param regs A pointer to a x86_regs structure.
 */

void fill_auxv(struct note *head, struct thread *thread, void *regs)
{
	void *name;
	void *auxv;

	head->namesz = sizeof("CORE");
	head->descsz = sizeof(unsigned long) * AUXV_LEN;
	head->type = NT_AUXV;
	name =  (void *) (head + 1);
	memcpy(name, "CORE", sizeof("CORE"));
	auxv = name + align32(sizeof("CORE"));
	memcpy(auxv, thread->proc->saved_auxv, sizeof(unsigned long) * AUXV_LEN);
} 

/**
 * \brief Return the size of the whole NOTE segment.
 *
 */

int get_note_size(void)
{
	return get_prstatus_size() + get_prpsinfo_size()
		+ get_auxv_size();
}

/**
 * \brief Fill the NOTE segment.
 *
 * \param head A pointer to a note structure.
 * \param thread A pointer to the current thread structure.
 * \param regs A pointer to a x86_regs structure.
 */

void fill_note(void *note, struct thread *thread, void *regs)
{
	fill_prstatus(note, thread, regs);
	note += get_prstatus_size();
	fill_prpsinfo(note, thread, regs);
	note += get_prpsinfo_size();
	fill_auxv(note, thread, regs);
}

/**
 * \brief Generate an image of the core file.
 *
 * \param thread A pointer to the current thread structure.
 * \param regs A pointer to a x86_regs structure.
 * \param coretable(out) An array of core chunks.
 * \param chunks(out) Number of the entires of coretable.
 *
 * A core chunk is represented by a pair of a physical 
 * address of memory region and its size. If there are
 * no corresponding physical address for a VM area 
 * (an unallocated demand-paging page, e.g.), the address
 * should be zero.
 */

/*@
  @ requires \valid(thread);
  @ requires \valid(regs);
  @ requires \valid(coretable);
  @ requires \valid(chunks);
  @ behavior success:
  @   ensures \result == 0;
  @   assigns coretable;
  @ behavior failure:
  @   ensures \result == -1;
  @*/
int gencore(struct thread *thread, void *regs, 
	    struct coretable **coretable, int *chunks)
{
	struct coretable *ct = NULL;
	Elf64_Ehdr eh;
	Elf64_Phdr *ph = NULL;
	void *note = NULL;
	struct vm_range *range;
	struct process_vm *vm = thread->vm;
	int segs = 1;	/* the first one is for NOTE */
	int notesize, phsize, alignednotesize;
	unsigned int offset = 0;
	int i;

	*chunks = 3; /* Elf header , header table and NOTE segment */

	if (vm == NULL) {
		dkprintf("no vm found.\n");
		return -1;
	}

	list_for_each_entry(range, &vm->vm_range_list, list) {
		dkprintf("start:%lx end:%lx flag:%lx objoff:%lx\n", 
			 range->start, range->end, range->flag, range->objoff);
		/* We omit reserved areas because they are only for
		   mckernel's internal use. */		   
		if (range->flag & VR_RESERVED)
			continue;
		/* We need a chunk for each page for a demand paging area.
		   This can be optimized for spacial complexity but we would
		   lose simplicity instead. */
		if (range->flag & VR_DEMAND_PAGING) {
			unsigned long p, phys;
			int prevzero = 0;
			for (p = range->start; p < range->end; p += PAGE_SIZE) {
				if (ihk_mc_pt_virt_to_phys(thread->vm->address_space->page_table, 
							    (void *)p, &phys) != 0) {
					prevzero = 1;
				} else {
					if (prevzero == 1)
						(*chunks)++;
					(*chunks)++;
					prevzero = 0;
				}
			}
			if (prevzero == 1)
				(*chunks)++;
		} else {
			(*chunks)++;
		}
		segs++;
	}
	dkprintf("we have %d segs and %d chunks.\n\n", segs, *chunks);

	{
		struct vm_regions region = thread->vm->region;

		dkprintf("text:  %lx-%lx\n", region.text_start, region.text_end);
		dkprintf("data:  %lx-%lx\n", region.data_start, region.data_end);
		dkprintf("brk:   %lx-%lx\n", region.brk_start, region.brk_end);
		dkprintf("map:   %lx-%lx\n", region.map_start, region.map_end);
		dkprintf("stack: %lx-%lx\n", region.stack_start, region.stack_end);
		dkprintf("user:  %lx-%lx\n\n", region.user_start, region.user_end);
	}

	dkprintf("now generate a core file image\n");

	offset += sizeof(eh);
	fill_elf_header(&eh, segs);

	/* program header table */
	phsize = sizeof(Elf64_Phdr) * segs;
	ph = kmalloc(phsize, IHK_MC_AP_NOWAIT);
	if (ph == NULL) {
		dkprintf("could not alloc a program header table.\n");
		goto fail;
	}
	memset(ph, 0, phsize);

	offset += phsize;

	/* NOTE segment
	 * To align the next segment page-sized, we prepare a padded
	 * region for our NOTE segment.
	 */
	notesize = get_note_size();
	alignednotesize = alignpage(notesize + offset) - offset;
	note = kmalloc(alignednotesize, IHK_MC_AP_NOWAIT);
	if (note == NULL) {
		dkprintf("could not alloc NOTE for core.\n");
		goto fail;
	}
	memset(note, 0, alignednotesize);
	fill_note(note, thread, regs);

	/* prgram header for NOTE segment is exceptional */
	ph[0].p_type = PT_NOTE;
	ph[0].p_flags = 0;
	ph[0].p_offset = offset;
	ph[0].p_vaddr = 0;
	ph[0].p_paddr = 0;
	ph[0].p_filesz = notesize;
	ph[0].p_memsz = notesize;
	ph[0].p_align = 0;

	offset += alignednotesize;

	/* program header for each memory chunk */
	i = 1;
	list_for_each_entry(range, &vm->vm_range_list, list) {
		unsigned long flag = range->flag;
		unsigned long size = range->end - range->start;

		if (range->flag & VR_RESERVED)
			continue;

		ph[i].p_type = PT_LOAD;
		ph[i].p_flags = ((flag & VR_PROT_READ) ? PF_R : 0)
			| ((flag & VR_PROT_WRITE) ? PF_W : 0)
			| ((flag & VR_PROT_EXEC) ? PF_X : 0);
		ph[i].p_offset = offset;
		ph[i].p_vaddr = range->start;
		ph[i].p_paddr = 0;
		ph[i].p_filesz = size;
		ph[i].p_memsz = size;
		ph[i].p_align = PAGE_SIZE;
		i++;
		offset += size;
	}

	/* coretable to send to host */
	ct = kmalloc(sizeof(struct coretable) * (*chunks), IHK_MC_AP_NOWAIT);
	if (!ct) {
		dkprintf("could not alloc a coretable.\n");
		goto fail;
	}

	ct[0].addr = virt_to_phys(&eh);	/* ELF header */
	ct[0].len = 64; 
	dkprintf("coretable[0]: %lx@%lx(%lx)\n", ct[0].len, ct[0].addr, &eh);

	ct[1].addr = virt_to_phys(ph);	/* program header table */
	ct[1].len = phsize;
	dkprintf("coretable[1]: %lx@%lx(%lx)\n", ct[1].len, ct[1].addr, ph);

	ct[2].addr = virt_to_phys(note);	/* NOTE segment */
	ct[2].len = alignednotesize;
	dkprintf("coretable[2]: %lx@%lx(%lx)\n", ct[2].len, ct[2].addr, note);

	i = 3;	/* memory segments */
	list_for_each_entry(range, &vm->vm_range_list, list) {
		unsigned long phys;

		if (range->flag & VR_RESERVED)
			continue;
		if (range->flag & VR_DEMAND_PAGING) {
			/* Just an ad hoc kluge. */
			unsigned long p, start, phys;
			int prevzero = 0;
			unsigned long size = 0;

			for (start = p = range->start; 
			     p < range->end; p += PAGE_SIZE) {
				if (ihk_mc_pt_virt_to_phys(thread->vm->address_space->page_table, 
							    (void *)p, &phys) != 0) {
					if (prevzero == 0) {
						/* We begin a new chunk */
						size = PAGE_SIZE;
						start = p;
					} else {
						/* We extend the previous chunk */
						size += PAGE_SIZE;
					}
					prevzero = 1;
				} else {
					if (prevzero == 1) {
						/* Flush out an empty chunk */
						ct[i].addr = 0;
						ct[i].len = size;
						dkprintf("coretable[%d]: %lx@%lx(%lx)\n", i, 
							 ct[i].len, ct[i].addr, start);
						i++;

					}
					ct[i].addr = phys;
					ct[i].len = PAGE_SIZE;
					dkprintf("coretable[%d]: %lx@%lx(%lx)\n", i, 
						 ct[i].len, ct[i].addr, p);
					i++;
					prevzero = 0;
				}
			}
			if (prevzero == 1) {
				/* An empty chunk */
				ct[i].addr = 0;
				ct[i].len = size;
				dkprintf("coretable[%d]: %lx@%lx(%lx)\n", i, 
					 ct[i].len, ct[i].addr, start);
				i++;
			}		
		} else {
			if ((thread->vm->region.user_start <= range->start) &&
			    (range->end <= thread->vm->region.user_end)) {
				if (ihk_mc_pt_virt_to_phys(thread->vm->address_space->page_table, 
							   (void *)range->start, &phys) != 0) {
					dkprintf("could not convert user virtual address %lx"
						 "to physical address", range->start);
					goto fail;
				}
			} else {
				phys = virt_to_phys((void *)range->start);
			}
			ct[i].addr = phys;
			ct[i].len = range->end - range->start;
			dkprintf("coretable[%d]: %lx@%lx(%lx)\n", i, 
				 ct[i].len, ct[i].addr, range->start);
			i++;
		}
	}
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

/**
 * \brief Free all the allocated spaces for an image of the core file.
 *
 * \param coretable An array of core chunks.
 */

/*@
  @ requires \valid(coretable);
  @ assigns \nothing;
  @*/
void freecore(struct coretable **coretable)
{
	struct coretable *ct = *coretable;
	kfree(phys_to_virt(ct[2].addr));	/* NOTE segment */
	kfree(phys_to_virt(ct[1].addr));	/* ph */
	kfree(*coretable);
}
