#include <ihk/debug.h>
#include <kmalloc.h>
#include <cls.h>
#include <list.h>
#include <process.h>
#include <string.h>
#include <elfcore.h>

#define	align32(x) ((((x) + 3) / 4) * 4)

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

/* ELF header */

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
	eh->e_machine = EM_K10M;
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

/* prstatus NOTE */

int get_prstatus_size(void)
{
	return sizeof(struct note) + align32(sizeof("CORE")) 
		+ align32(sizeof(struct elf_prstatus64));
}

void fill_prstatus(struct note *head, struct process *proc, void *regs0)
{
	void *name;
	struct elf_prstatus64 *prstatus; 
	struct x86_regs *regs = regs0;
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

/* prpsinfo NOTE */

int get_prpsinfo_size(void)
{
	return sizeof(struct note) + align32(sizeof("CORE")) 
		+ align32(sizeof(struct elf_prpsinfo64));
}

void fill_prpsinfo(struct note *head, struct process *proc, void *regs)
{
	void *name;
	struct elf_prpsinfo64 *prpsinfo;

	head->namesz = sizeof("CORE");
	head->descsz = sizeof(struct elf_prpsinfo64);
	head->type = NT_PRPSINFO;
	name =  (void *) (head + 1);
	memcpy(name, "CORE", sizeof("CORE"));
	prpsinfo = (struct elf_prpsinfo64 *)(name + align32(sizeof("CORE")));

	prpsinfo->pr_state = proc->status;
	prpsinfo->pr_pid = proc->pid;

/*
  We leave most of the fields unfilled.

	char pr_state;
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

/* auxv NOTE */

int get_auxv_size(void)
{
	return sizeof(struct note) + align32(sizeof("CORE")) 
		+ sizeof(unsigned long) * AUXV_LEN;
}

void fill_auxv(struct note *head, struct process *proc, void *regs)
{
	void *name;
	void *auxv;

	head->namesz = sizeof("CORE");
	head->descsz = sizeof(unsigned long) * AUXV_LEN;
	head->type = NT_AUXV;
	name =  (void *) (head + 1);
	memcpy(name, "CORE", sizeof("CORE"));
	auxv = name + align32(sizeof("CORE"));
	memcpy(auxv, proc->saved_auxv, sizeof(unsigned long) * AUXV_LEN);
} 

/* whole NOTE segment */

int get_note_size(void)
{
	return get_prstatus_size() + get_prpsinfo_size()
		+ get_auxv_size();
}

void fill_note(void *note, struct process *proc, void *regs)
{
	fill_prstatus(note, proc, regs);
	note += get_prstatus_size();
	fill_prpsinfo(note, proc, regs);
	note += get_prpsinfo_size();
	fill_auxv(note, proc, regs);
}

/* whole core image */

int gencore(struct process *proc, void *regs, 
	    struct coretable **coretable, int *chunks)
{
	struct coretable *ct;
	Elf64_Ehdr eh;
	Elf64_Phdr *ph;
	void *note;
	struct vm_range *range;
	struct process_vm *vm = proc->vm;
	int segs = 1;	/* the first one is for NOTE */
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
		/* We omit reserved areas because they are only for
		   mckernel's internal use. */		   
		if ((range->flag && VR_RESERVED) != 0)
			continue;
		segs++;
	}
	dkprintf("we have %d segs including one for NOTE.\n\n", segs);

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

	offset += sizeof(eh);
	fill_elf_header(&eh, segs);

	notesize = get_note_size();
	note = kmalloc(notesize, IHK_MC_AP_NOWAIT);
	if (note == NULL) {
		dkprintf("could not alloc NOTE for core.\n");
		goto fail;
	}
	fill_note(note, proc, regs);

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

		if ((range->flag && VR_RESERVED) != 0)
			continue;

		ph[i].p_type = PT_LOAD;
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
		if ((range->flag && VR_RESERVED) != 0)
			continue;
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
