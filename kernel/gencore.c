/* gencore.c COPYRIGHT FUJITSU LIMITED 2015-2019 */
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
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

/* Exclude reserved (mckernel's internal use), device file,
 * hole created by mprotect
 */
#define GENCORE_RANGE_IS_INACCESSIBLE(range) \
	    ((range->flag & (VR_RESERVED | VR_MEMTYPE_UC | VR_DONTDUMP)))

/* Generate a core file image, which consists of many chunks.
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
	eh->e_ident[EI_CLASS] = ELF_CLASS;
	eh->e_ident[EI_DATA] = ELF_DATA;
	eh->e_ident[EI_VERSION] = El_VERSION;
	eh->e_ident[EI_OSABI] = ELF_OSABI;
	eh->e_ident[EI_ABIVERSION] = ELF_ABIVERSION;

	eh->e_type = ET_CORE;
	eh->e_machine = ELF_ARCH;
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
 * \brief Return the size of the prpsinfo entry of the NOTE segment.
 *
 */

int get_prpsinfo_size(void)
{
	return sizeof(struct note) + align32(sizeof("CORE"))
		+ align32(sizeof(struct elf_prpsinfo64));
}

/**
 * \brief Fill a prstatus structure.
 *
 * \param head A pointer to a note structure.
 * \param proc A pointer to the current process structure.
 * \param regs0 A pointer to a ihk_mc_user_context_t structure.
 */
void fill_prstatus(struct note *head, struct thread *thread)
{
	void *name;
	struct elf_prstatus64 *prstatus;

	head->namesz = sizeof("CORE");
	head->descsz = sizeof(struct elf_prstatus64);
	head->type = NT_PRSTATUS;
	name =  (void *) (head + 1);
	memcpy(name, "CORE", sizeof("CORE"));
	prstatus = (struct elf_prstatus64 *)(name + align32(sizeof("CORE")));

	arch_fill_prstatus(prstatus, thread, thread->coredump_regs);
}

/**
 * \brief Fill a prpsinfo structure.
 *
 * \param head A pointer to a note structure.
 * \param proc A pointer to the current process structure.
 * \param regs A pointer to a ihk_mc_user_context_t structure.
 */

void fill_prpsinfo(struct note *head, struct process *proc, char *cmdline)
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

	memcpy(prpsinfo->pr_fname, cmdline, 16);

/* TODO: Fill the following fields:
 *	char pr_sname;
 *	char pr_zomb;
 *	char pr_nice;
 *	a8_uint64_t pr_flag;
 *	unsigned int pr_uid;
 *	unsigned int pr_gid;
 *	int pr_ppid, pr_pgrp, pr_sid;
 *	char pr_fname[16];
 *	char pr_psargs[ELF_PRARGSZ];
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
 * \param proc A pointer to the current process structure.
 * \param regs A pointer to a ihk_mc_user_context_t structure.
 */

void fill_auxv(struct note *head, struct process *proc)
{
	void *name;
	void *auxv;

	head->namesz = sizeof("CORE");
	head->descsz = sizeof(unsigned long) * AUXV_LEN;
	head->type = NT_AUXV;
	name =  (void *) (head + 1);
	memcpy(name, "CORE", sizeof("CORE"));
	auxv = name + align32(sizeof("CORE"));
	memcpy(auxv, proc->saved_auxv,
	       sizeof(unsigned long) * AUXV_LEN);
}

/**
 * \brief Return the size of the whole NOTE segment.
 *
 */

int get_note_size(struct process *proc)
{
	int note = 0;
	struct thread *thread_iter;
	struct mcs_rwlock_node lock;

	mcs_rwlock_reader_lock_noirq(&proc->threads_lock, &lock);
	list_for_each_entry(thread_iter, &proc->threads_list, siblings_list) {
		note += get_prstatus_size();
		note += arch_get_thread_core_info_size();
		if (thread_iter->tid == proc->pid) {
			note += get_prpsinfo_size();
			note += get_auxv_size();
		}
	}
	mcs_rwlock_reader_unlock_noirq(&proc->threads_lock, &lock);


	return note;
}

/**
 * \brief Fill the NOTE segment.
 *
 * \param head A pointer to a note structure.
 * \param proc A pointer to the current process structure.
 * \param regs A pointer to a ihk_mc_user_context_t structure.
 */

void fill_note(void *note, struct process *proc, char *cmdline)
{
	struct thread *thread_iter;
	struct mcs_rwlock_node lock;

	mcs_rwlock_reader_lock_noirq(&proc->threads_lock, &lock);
	list_for_each_entry(thread_iter, &proc->threads_list, siblings_list) {
		fill_prstatus(note, thread_iter);
		note += get_prstatus_size();

		arch_fill_thread_core_info(note, thread_iter,
					   thread_iter->coredump_regs);
		note += arch_get_thread_core_info_size();

		if (thread_iter->tid == proc->pid) {
			fill_prpsinfo(note, proc, cmdline);
			note += get_prpsinfo_size();

#if 0
			fill_siginfo(note, proc);
			note += get_siginfo_size();
#endif

			fill_auxv(note, proc);
			note += get_auxv_size();

#if 0
			fill_file(note, proc);
			note += get_file_size();
#endif
		}

#if 0
		fill_fpregset(note, thread);
		note += get_fpregset_size();

		fill_x86_xstate(note, thread);
		note += get_x86_xstate_size();
#endif
	}
	mcs_rwlock_reader_unlock_noirq(&proc->threads_lock, &lock);

}

/**
 * \brief Generate an image of the core file.
 *
 * \param proc A pointer to the current process structure.
 * \param regs A pointer to a ihk_mc_user_context_t structure.
 * \param coretable(out) An array of core chunks.
 * \param chunks(out) Number of the entires of coretable.
 *
 * A core chunk is represented by a pair of a physical
 * address of memory region and its size. If there are
 * no corresponding physical address for a VM area
 * (an unallocated demand-paging page, e.g.), the address
 * should be zero.
 */

int gencore(struct process *proc, struct coretable **coretable, int *chunks,
	    char *cmdline)
{
	int error = 0;
	struct coretable *ct = NULL;
	Elf64_Ehdr *eh = NULL;
	Elf64_Phdr *ph = NULL;
	void *note = NULL;
	struct vm_range *range, *next;
	struct process_vm *vm = proc->vm;
	int segs = 1;	/* the first one is for NOTE */
	int notesize, phsize, alignednotesize;
	unsigned int offset = 0;
	int i;

	*chunks = 3; /* Elf header , header table and NOTE segment */

	if (vm == NULL) {
		kprintf("%s: ERROR: vm not found\n", __func__);
		error = -EINVAL;
		goto fail;
	}

	next = lookup_process_memory_range(vm, 0, -1);
	while ((range = next)) {
		next = next_process_memory_range(vm, range);

		dkprintf("start:%lx end:%lx flag:%lx objoff:%lx\n",
			 range->start, range->end, range->flag, range->objoff);

		if (GENCORE_RANGE_IS_INACCESSIBLE(range)) {
			continue;
		}
		/* We need a chunk for each page for a demand paging area.
		 * This can be optimized for spacial complexity but we would
		 * lose simplicity instead.
		 */
		if (range->flag & VR_DEMAND_PAGING) {
			unsigned long p, phys;
			int prevzero = 0;

			for (p = range->start; p < range->end; p += PAGE_SIZE) {
				if (ihk_mc_pt_virt_to_phys(vm->address_space->page_table,
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
		struct vm_regions region = vm->region;

		dkprintf("text:  %lx-%lx\n", region.text_start,
			 region.text_end);
		dkprintf("data:  %lx-%lx\n", region.data_start,
			 region.data_end);
		dkprintf("brk:   %lx-%lx\n", region.brk_start, region.brk_end);
		dkprintf("map:   %lx-%lx\n", region.map_start, region.map_end);
		dkprintf("stack: %lx-%lx\n", region.stack_start,
			 region.stack_end);
		dkprintf("user:  %lx-%lx\n\n", region.user_start,
			 region.user_end);
	}

	dkprintf("now generate a core file image\n");

	eh = kmalloc(sizeof(*eh), IHK_MC_AP_NOWAIT);
	if (eh == NULL) {
		dkprintf("could not alloc a elf header table.\n");
		error = -ENOMEM;
		goto fail;
	}
	memset(eh, 0, sizeof(*eh));

	offset += sizeof(*eh);
	fill_elf_header(eh, segs);

	/* program header table */
	phsize = sizeof(Elf64_Phdr) * segs;
	ph = kmalloc(phsize, IHK_MC_AP_NOWAIT);
	if (ph == NULL) {
		kprintf("%s: ERROR: allocating program header\n", __func__);
		error = -ENOMEM;
		goto fail;
	}
	memset(ph, 0, phsize);

	offset += phsize;

	/* NOTE segment
	 * To align the next segment page-sized, we prepare a padded
	 * region for our NOTE segment.
	 */
	notesize = get_note_size(proc);
	alignednotesize = alignpage(notesize + offset) - offset;
	note = kmalloc(alignednotesize, IHK_MC_AP_NOWAIT);
	if (note == NULL) {
		kprintf("%s: ERROR: allocating NOTE\n", __func__);
		error = -ENOMEM;
		goto fail;
	}
	memset(note, 0, alignednotesize);
	fill_note(note, proc, cmdline);

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
	next = lookup_process_memory_range(vm, 0, -1);
	while ((range = next)) {
		next = next_process_memory_range(vm, range);

		unsigned long flag = range->flag;
		unsigned long size = range->end - range->start;

		if (GENCORE_RANGE_IS_INACCESSIBLE(range)) {
			continue;
		}

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
		kprintf("%s: ERROR: allocating coretable\n", __func__);
		error = -ENOMEM;
		goto fail;
	}
	memset(ct, 0, sizeof(struct coretable) * (*chunks));

	ct[0].addr = virt_to_phys(eh);	/* ELF header */
	ct[0].len = 64;
	dkprintf("coretable[0]: %lx@%lx(%lx)\n", ct[0].len, ct[0].addr, eh);

	ct[1].addr = virt_to_phys(ph);	/* program header table */
	ct[1].len = phsize;
	dkprintf("coretable[1]: %lx@%lx(%lx)\n", ct[1].len, ct[1].addr, ph);

	ct[2].addr = virt_to_phys(note);	/* NOTE segment */
	ct[2].len = alignednotesize;
	dkprintf("coretable[2]: %lx@%lx(%lx)\n", ct[2].len, ct[2].addr, note);

	i = 3;	/* memory segments */
	next = lookup_process_memory_range(vm, 0, -1);
	while ((range = next)) {
		next = next_process_memory_range(vm, range);

		unsigned long phys;

		if (GENCORE_RANGE_IS_INACCESSIBLE(range)) {
			continue;
		}

		if (range->flag & VR_DEMAND_PAGING) {

			/* Just an ad hoc kluge. */
			unsigned long p, start, phys;
			int prevzero = 0;
			unsigned long size = 0;

			for (start = p = range->start;
			     p < range->end; p += PAGE_SIZE) {
				if (ihk_mc_pt_virt_to_phys(vm->address_space->page_table,
							    (void *)p, &phys) != 0) {
					if (prevzero == 0) {
						/* Start chunk with page */
						size = PAGE_SIZE;
						start = p;
					} else {
						/* Extend the previous chunk */
						size += PAGE_SIZE;
					}
					prevzero = 1;
				} else {
					if (prevzero == 1) {
						/* Skip chunk without page */
						dkprintf("%s: skipping %lx-%lx\n",
							 __func__, start,
							 start + size);
					}

					/* Flush chunk with page */
					ct[i].addr = phys;
					ct[i].len = PAGE_SIZE;
					dkprintf("coretable[%d]: %lx@%lx(%lx)\n",
						 i, ct[i].len, ct[i].addr, p);
					i++;
					prevzero = 0;
				}
			}
			if (prevzero == 1) {
				/* Skip chunk without page */
				dkprintf("%s: skipping %lx-%lx\n",
					 __func__, start, start + size);
			}
		} else {
			if ((vm->region.user_start <= range->start) &&
			    (range->end <= vm->region.user_end)) {
				error = ihk_mc_pt_virt_to_phys(vm->address_space->page_table,
							       (void *)range->start,
							       &phys);
				if (error) {
					if (error != -EFAULT) {
						kprintf("%s: error: ihk_mc_pt_virt_to_phys for %lx failed (%d)\n",
							__func__, range->start,
							error);
						goto fail;
					}
					/* VR_PROT_NONE range */
					phys = 0;
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

	return error;

fail:
	kfree(eh);
	kfree(ct);
	kfree(ph);
	kfree(note);
	return error;
}

/**
 * \brief Free all the allocated spaces for an image of the core file.
 *
 * \param coretable An array of core chunks.
 */

void freecore(struct coretable **coretable)
{
	struct coretable *ct = *coretable;

	kfree(phys_to_virt(ct[2].addr));	/* NOTE segment */
	kfree(phys_to_virt(ct[1].addr));	/* ph */
	kfree(phys_to_virt(ct[0].addr));	/* eh */
	kfree(*coretable);
}
