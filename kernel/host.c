/* host.c COPYRIGHT FUJITSU LIMITED 2015-2018 */
/**
 * \file host.c
 *  License details are found in the file LICENSE.
 * \brief
 *  host call handlers
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * 	Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 * 	Copyright (C) 2012  RIKEN AICS
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <ikc/master.h>
#include <cls.h>
#include <syscall.h>
#include <process.h>
#include <page.h>
#include <mman.h>
#include <init.h>
#include <kmalloc.h>
#include <sysfs.h>
#include <ihk/perfctr.h>
#include <rusage_private.h>
#include <debug.h>

//#define DEBUG_PRINT_HOST

#ifdef DEBUG_PRINT_HOST
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

/* Linux channel table, indexec by Linux CPU id */
static struct ihk_ikc_channel_desc **ikc2linuxs = NULL;

void check_mapping_for_proc(struct thread *thread, unsigned long addr)
{
	unsigned long __phys;

	if (ihk_mc_pt_virt_to_phys(thread->vm->address_space->page_table, (void*)addr, &__phys)) {
		kprintf("check_map: no mapping for 0x%lX\n", addr);
	}
	else {
		kprintf("check_map: 0x%lX -> 0x%lX\n", addr, __phys);
	}
}

static int fill_zero_to_user(unsigned long dest, unsigned long length)
{
	void *zero_buf;
	unsigned long len, offset, remain;
	int ret = 0;

	remain = length;
	offset = 0;

	zero_buf = kmalloc(PAGE_SIZE, IHK_MC_AP_NOWAIT);
	if (!zero_buf) {
		ret = -ENOMEM;
		goto out;
	}
	memset(zero_buf, 0, PAGE_SIZE);

	len = length;

	while (remain > 0) {
		if (remain > PAGE_SIZE) {
			len = PAGE_SIZE;
		}
		else {
			len = remain;
		}

		ret = copy_to_user((void *)dest + offset, zero_buf, len);
		if (ret) {
			goto out;
		}

		remain -= len;
		offset += len;
	}

 out:
	kfree(zero_buf);
	return ret;
}

/* 
 * Prepares the process ranges based on the ELF header described 
 * in program_load_desc and updates physical address in "p" so that
 * host can copy program image.
 * It also prepares args, envs and the process stack.
 * 
 * NOTE: if args, args_len, envs, envs_len are zero, 
 * the function constructs them based on the descriptor 
 */
int prepare_process_ranges_args_envs(struct thread *thread, 
		struct program_load_desc *pn,
		struct program_load_desc *p,
		enum ihk_mc_pt_attribute attr,
		char *args, int args_len,
		char *envs, int envs_len) 
{
	char *args_envs, *args_envs_r;
	unsigned long args_envs_p, args_envs_rp, envs_offset;
	unsigned long e, fmap_start, fmap_end, anon_end;
	char **argv;
	int i, n, argc, envc, args_envs_npages;
	char **env;
	unsigned long addr;
	unsigned long flags;
	uintptr_t interp_obase = -1;
	uintptr_t interp_nbase = -1;
	size_t map_size;
	struct process *proc = thread->proc;
	struct process_vm *vm = proc->vm;
	struct address_space *as = vm->address_space;
	long aout_base;
	int error;
	
	n = p->num_sections;

	aout_base = (pn->reloc)? vm->region.map_end: 0;
	for (i = 0; i < n; i++) {
		if (pn->sections[i].interp && (interp_nbase == (uintptr_t)-1)) {
			interp_obase = pn->sections[i].vaddr;
			interp_obase -= (interp_obase % pn->interp_align);
			interp_nbase = vm->region.map_end;
			interp_nbase = (interp_nbase + pn->interp_align - 1)
				& ~(pn->interp_align - 1);
		}

		if (pn->sections[i].interp) {
			pn->sections[i].vaddr -= interp_obase;
			pn->sections[i].vaddr += interp_nbase;
			p->sections[i].vaddr = pn->sections[i].vaddr;
		}
		else{
			pn->sections[i].vaddr += aout_base;
			p->sections[i].vaddr = pn->sections[i].vaddr;
		}
		fmap_start = (pn->sections[i].vaddr) & PAGE_MASK;
		fmap_end = (pn->sections[i].vaddr + pn->sections[i].filesz
				+ PAGE_SIZE - 1) & PAGE_MASK;
		anon_end = (pn->sections[i].vaddr + pn->sections[i].len
				+ PAGE_SIZE - 1) & PAGE_MASK;

		if (pn->sections[i].interp) {
			vm->region.map_end = anon_end;
		}
		else if (pn->sections[i].prot & PROT_EXEC) {
			vm->region.text_start = fmap_start;
			vm->region.text_end = fmap_end;
		} 
		else {
			vm->region.data_start =
				(fmap_start < vm->region.data_start ?
				 fmap_start : vm->region.data_start);
			vm->region.data_end = 
				(anon_end > vm->region.data_end ?
				 anon_end : vm->region.data_end);
		}

		if (aout_base) {
			vm->region.map_end = anon_end;
		}
	}

	if (interp_nbase != (uintptr_t)-1) {
		pn->entry -= interp_obase;
		pn->entry += interp_nbase;
		p->entry = pn->entry;
		ihk_mc_modify_user_context(thread->uctx,
		                           IHK_UCR_PROGRAM_COUNTER, 
		                           pn->entry);
	}

	if (aout_base) {
		pn->at_phdr += aout_base;
		pn->at_entry += aout_base;
	}

	vm->region.map_start = vm->region.map_end = TASK_UNMAPPED_BASE;

	vm->region.brk_start = vm->region.brk_end =
		(vm->region.data_end + LARGE_PAGE_SIZE - 1) & LARGE_PAGE_MASK;

	if (vm->region.brk_start >= vm->region.map_start) {
		kprintf("%s: ERROR: data section is too large (end addr: %lx)\n",
			__func__, vm->region.data_end);
	}

#if 0
	{
		void *heap;

		dkprintf("%s: requested heap size: %lu\n",
				__FUNCTION__, proc->heap_extension);
		heap = ihk_mc_alloc_aligned_pages(proc->heap_extension >> PAGE_SHIFT,
				LARGE_PAGE_P2ALIGN, IHK_MC_AP_NOWAIT |
				(!(proc->mpol_flags & MPOL_NO_HEAP) ? IHK_MC_AP_USER : 0));

		if (!heap) {
			kprintf("%s: error: allocating heap\n", __FUNCTION__);
			goto err;
		}

		flags = VR_PROT_READ | VR_PROT_WRITE;
		flags |= VRFLAG_PROT_TO_MAXPROT(flags);
		if (add_process_memory_range(vm, vm->region.brk_start,
					vm->region.brk_start + proc->heap_extension,
					virt_to_phys(heap),
					flags, NULL, 0, LARGE_PAGE_P2ALIGN, NULL) != 0) {
			ihk_mc_free_pages(heap, proc->heap_extension >> PAGE_SHIFT);
			kprintf("%s: error: adding memory range for heap\n", __FUNCTION__);
			goto err;
		}
		// heap: Add when memory_stat_rss_add() is called in downstream, i.e. add_process_memory_range()

		vm->region.brk_end_allocated = vm->region.brk_end +
			proc->heap_extension;
		dkprintf("%s: heap @ 0x%lx:%lu\n",
				__FUNCTION__, vm->region.brk_start, proc->heap_extension);
	}
#else
	vm->region.brk_end_allocated = vm->region.brk_end;
#endif

	/* Map, copy and update args and envs */
	flags = VR_PROT_READ | VR_PROT_WRITE;
	flags |= VRFLAG_PROT_TO_MAXPROT(flags);
	addr = vm->region.map_start - PAGE_SIZE * SCD_RESERVED_COUNT;
	e = addr + PAGE_SIZE * ARGENV_PAGE_COUNT;

	if((args_envs = ihk_mc_alloc_pages_user(ARGENV_PAGE_COUNT,
	                                        IHK_MC_AP_NOWAIT, -1)) == NULL){
		kprintf("ERROR: allocating pages for args/envs\n");
		goto err;
	}
	args_envs_p = virt_to_phys(args_envs);

	dkprintf("%s: args_envs: %d pages\n",
			 __FUNCTION__, ARGENV_PAGE_COUNT);
	if(add_process_memory_range(vm, addr, e, args_envs_p,
				flags, NULL, 0, PAGE_SHIFT, NULL) != 0){
		ihk_mc_free_pages_user(args_envs, ARGENV_PAGE_COUNT);
		kprintf("ERROR: adding memory range for args/envs\n");
		goto err;
	}
	// memory_stat_rss_add() is called in downstream, i.e. add_process_memory_range()

	dkprintf("args_envs mapping\n");

	dkprintf("args: 0x%lX, args_len: %d\n", p->args, p->args_len);

	/* Only map remote address if it wasn't specified as an argument */
	if (!args) {
		// Map in remote physical addr of args and copy it
		map_size = ((uintptr_t)p->args & (PAGE_SIZE - 1)) + p->args_len;
		args_envs_npages = (map_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
		dkprintf("args_envs_npages: %d\n", args_envs_npages);
		args_envs_rp = ihk_mc_map_memory(NULL, 
				(unsigned long)p->args, p->args_len);

		dkprintf("args_envs_rp: 0x%lX\n", args_envs_rp);
		if ((args_envs_r = (char *)ihk_mc_map_virtual(args_envs_rp, 
						args_envs_npages, attr)) == NULL){
			goto err;
		}
		dkprintf("args_envs_r: 0x%lX\n", args_envs_r);
	}
	else {
		args_envs_r = args;
		p->args_len = args_len;
	}

	dkprintf("args copy, nr: %d\n", *((long *)args_envs_r));

	memcpy_long(args_envs, args_envs_r, p->args_len + sizeof(long) - 1);

	/* Only unmap remote address if it wasn't specified as an argument */
	if (!args) {
		ihk_mc_unmap_virtual(args_envs_r, args_envs_npages);
		ihk_mc_unmap_memory(NULL, args_envs_rp, p->args_len);
	}
	flush_tlb();

	dkprintf("envs: 0x%lX, envs_len: %d\n", p->envs, p->envs_len);

	/* Only map remote address if it wasn't specified as an argument */
	if (!envs) {
		// Map in remote physical addr of envs and copy it after args
		map_size = ((uintptr_t)p->envs & (PAGE_SIZE - 1)) + p->envs_len;
		args_envs_npages = (map_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
		dkprintf("args_envs_npages: %d\n", args_envs_npages);
		args_envs_rp = ihk_mc_map_memory(NULL, (unsigned long)p->envs, 
				p->envs_len);

		dkprintf("args_envs_rp: 0x%lX\n", args_envs_rp);
		
		if ((args_envs_r = (char *)ihk_mc_map_virtual(args_envs_rp, 
						args_envs_npages, attr)) == NULL) {
			goto err;
		}
		dkprintf("args_envs_r: 0x%lX\n", args_envs_r);
	}
	else {
		args_envs_r = envs;
		p->envs_len = envs_len;
	}

	dkprintf("envs copy, nr: %d\n", *((long *)args_envs_r));

	/* p->args_len is not necessarily long-aligned, even if the memory
	 * below exists and is zeroed out - env must start aligned
	 */
	envs_offset = (p->args_len + sizeof(long) - 1) & ~(sizeof(long) - 1);

	memcpy_long(args_envs + envs_offset, args_envs_r,
		    p->envs_len + sizeof(long) - 1);

	/* Only map remote address if it wasn't specified as an argument */
	if (!envs) {
		ihk_mc_unmap_virtual(args_envs_r, args_envs_npages);
		ihk_mc_unmap_memory(NULL, args_envs_rp, p->envs_len);
	}
	flush_tlb();

	// Update variables
	argc = *((long *)(args_envs));
	dkprintf("argc: %d\n", argc);
	argv = (char **)(args_envs + (sizeof(long)));

	if (proc->saved_cmdline) {
		kfree(proc->saved_cmdline);
		proc->saved_cmdline = NULL;
		proc->saved_cmdline_len = 0;
	}

	proc->saved_cmdline_len = p->args_len - ((argc + 2) * sizeof(char **));
	proc->saved_cmdline = kmalloc(proc->saved_cmdline_len,
				      IHK_MC_AP_NOWAIT);
	if (!proc->saved_cmdline) {
		goto err;
	}

	memcpy(proc->saved_cmdline,
			(char *)args_envs + ((argc + 2) * sizeof(char **)),
			proc->saved_cmdline_len);
	dkprintf("%s: saved_cmdline: %s\n",
			__FUNCTION__,
			proc->saved_cmdline);

	for (i = 0; i < argc; i++) {
		// Process' address space!
		argv[i] = (char *)addr + (unsigned long)argv[i];
	}

	envc = *((long *)(args_envs + envs_offset));
	dkprintf("envc: %d\n", envc);

	env = (char **)(args_envs + envs_offset + sizeof(long));
	for (i = 0; i < envc; i++) {
		env[i] = addr + envs_offset + env[i];
	}

	dkprintf("env OK\n");

	if (pn->enable_vdso) {
		error = arch_map_vdso(vm);
		if (error) {
			kprintf("ERROR: mapping vdso pages. %d\n", error);
			goto err;
		}
	}
	else {
		vm->vdso_addr = NULL;
	}

	p->rprocess = (unsigned long)thread;
	p->rpgtable = virt_to_phys(as->page_table);

	if (init_process_stack(thread, pn, argc, argv, envc, env) != 0) {
		goto err;
	}

	return 0;

err:
	/* TODO: cleanup allocated ranges */
	return -1;
}

int load_executable(void)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct process_vm *vm = proc->vm;
	struct program_load_desc *desc = proc->desc;
	ihk_mc_user_context_t ctx1, ctx2;
	int i, n, fd, error, ret = 0;
	unsigned long fmap_start, fmap_end, anon_start, anon_end;
	struct vm_range *range;
	intptr_t map_addr;
	unsigned long section_start, section_file_end;

	if (!desc) {
		/* loading is not needed */
		goto out;
	}

	n = desc->num_sections;

	for (i = 0; i < n; i++) {
		fmap_start = (desc->sections[i].vaddr) & PAGE_MASK;
		fmap_end = (desc->sections[i].vaddr + desc->sections[i].filesz
				+ PAGE_SIZE - 1) & PAGE_MASK;
		anon_start = fmap_end;
		anon_end = (desc->sections[i].vaddr + desc->sections[i].len
				+ PAGE_SIZE - 1) & PAGE_MASK;

		/* open ELF file (exec/interp) */
		memset(&ctx1, '0', sizeof(ihk_mc_user_context_t));
		memset(&ctx2, '0', sizeof(ihk_mc_user_context_t));

		ihk_mc_syscall_arg0(&ctx1) = -100; /* dirfd = AT_FDCWD */
		if (desc->sections[i].interp) {
			ihk_mc_syscall_arg1(&ctx1) = desc->interp_path_va;
		}
		else {
			ihk_mc_syscall_arg1(&ctx1) = desc->exec_path_va;
		}
		ihk_mc_syscall_arg2(&ctx1) = 0x0; //O_RDONLY

		fd = (int)syscall_generic_forwarding(__NR_openat, &ctx1);
		if (fd < 0) {
			kprintf("ERROR: opening exec/interp\n");
			ret = -1;
			goto out;
		}

		/* load section by file_map */
		map_addr = do_mmap(fmap_start, fmap_end - fmap_start,
				PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE,
				fd, desc->sections[i].offset & PAGE_MASK);
		if (map_addr != fmap_start) {
			kprintf("ERROR: file map FIXED\n");
			ret = -1;
			goto out;
		}

		/* close ELF file */
		ihk_mc_syscall_arg0(&ctx2) = fd;
		syscall_generic_forwarding(__NR_close, &ctx2);
		fd = -1;

		/* zero clear unintented part from vm_range */
		section_start = desc->sections[i].vaddr;
		section_file_end = desc->sections[i].vaddr +
				desc->sections[i].filesz;

		if (fmap_start < section_start) {
			if (fill_zero_to_user(fmap_start,
					section_start - fmap_start)) {
				kprintf("ERROR: filling zero to user space\n");
				ret = -1;
				goto out;
			}
		}
		if (fmap_end > section_file_end) {
			if (fill_zero_to_user(section_file_end,
					fmap_end - section_file_end)) {
				kprintf("ERROR: filling zero to user space\n");
				ret = -1;
				goto out;
			}
		}

		range = lookup_process_memory_range(vm, fmap_start,
				fmap_start + 1);
		if (!range) {
			kprintf("ERROR: vm_range is not found\n");
			ret = -1;
			goto out;
		}

		/* Non-TEXT sections that are large respect user allocation
		 * policy unless user explicitly requests otherwise
		 */
		if (i >= 1 && desc->sections[i].len >= desc->mpol_threshold &&
				!(desc->mpol_flags & MPOL_NO_BSS)) {
			dkprintf("%s: section: %d size: %d pages -> IHK_MC_AP_USER\n",
				__func__, i,
				(fmap_end - fmap_start) / PAGE_SIZE);
			range->flag |= VR_AP_USER;
		}

		/* update prot with desc's prot */
		error = do_mprotect(fmap_start, fmap_end - fmap_start,
				desc->sections[i].prot);
		if (error) {
			kprintf("ERROR: mprotect to file map space\n");
			ret = -1;
			goto out;
		}

		/* allocating extra space by anon_map */
		if (anon_start != anon_end) {
			map_addr = do_mmap(anon_start, anon_end - anon_start,
					PROT_READ | PROT_WRITE,
					MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
					-1, 0);
			if (map_addr != anon_start) {
				kprintf("ERROR: anonymous map FIXED\n");
				ret = -1;
				goto out;
			}

			if (fill_zero_to_user(anon_start,
					anon_end - anon_start)) {
				kprintf("ERROR: filling zero to user space\n");
				ret = -1;
				goto out;
			}
		}
	}

 out:
	kfree(proc->desc);
	proc->desc = NULL;

	return ret;
}

/*
 * Communication with host 
 */
static int process_msg_prepare_process(unsigned long rphys)
{
	unsigned long phys, sz;
	struct program_load_desc *p, *pn;
	int npages, n;
	struct thread *thread;
	struct process *proc;
	struct process_vm *vm;
	enum ihk_mc_pt_attribute attr;

	attr = PTATTR_NO_EXECUTE | PTATTR_WRITABLE | PTATTR_FOR_USER;

	sz = sizeof(struct program_load_desc)
		+ sizeof(struct program_image_section) * 16;
	npages = ((rphys + sz - 1) >> PAGE_SHIFT) - (rphys >> PAGE_SHIFT) + 1;

	phys = ihk_mc_map_memory(NULL, rphys, sz);
	if((p = ihk_mc_map_virtual(phys, npages, attr)) == NULL){
		ihk_mc_unmap_memory(NULL, phys, sz);
		return -ENOMEM;
	}

#ifdef POSTK_DEBUG_TEMP_FIX_76 /* add program_load_desc magic */
	if (p->magic != PLD_MAGIC) {
		kprintf("%s: broken mcexec program_load_desc\n", __func__);
		ihk_mc_unmap_virtual(p, npages);
		ihk_mc_unmap_memory(NULL, phys, sz);
		return -EFAULT;
	}
#endif /* POSTK_DEBUG_TEMP_FIX_76 */

	n = p->num_sections;
	if (n > 16 || 0 >= n) {
		kprintf("%s: ERROR: ELF sections other than 1 to 16 ??\n",
			__FUNCTION__);
		return -ENOMEM;
	}
	dkprintf("# of sections: %d\n", n);

	if((pn = kmalloc(sizeof(struct program_load_desc) 
					+ sizeof(struct program_image_section) * n,
					IHK_MC_AP_NOWAIT)) == NULL){
		ihk_mc_unmap_virtual(p, npages);
		ihk_mc_unmap_memory(NULL, phys, sz);
		return -ENOMEM;
	}
	memcpy_long(pn, p, sizeof(struct program_load_desc) 
	            + sizeof(struct program_image_section) * n);

	if ((thread = create_thread(p->entry,
					(unsigned long *)&p->cpu_set,
					sizeof(p->cpu_set))) == NULL) {
		kfree(pn);
		ihk_mc_unmap_virtual(p, npages);
		ihk_mc_unmap_memory(NULL, phys, sz);
		return -ENOMEM;
	}
	proc = thread->proc;
	vm = thread->vm;

	proc->pid = pn->pid;
	proc->vm->address_space->pids[0] = pn->pid;
	proc->pgid = pn->pgid;
	proc->ruid = pn->cred[0];
	proc->euid = pn->cred[1];
	proc->suid = pn->cred[2];
	proc->fsuid = pn->cred[3];
	proc->rgid = pn->cred[4];
	proc->egid = pn->cred[5];
	proc->sgid = pn->cred[6];
	proc->fsgid = pn->cred[7];
	proc->termsig = SIGCHLD;
	proc->mpol_flags = pn->mpol_flags;
	proc->mpol_threshold = pn->mpol_threshold;
	proc->thp_disable = pn->thp_disable;
	proc->nr_processes = pn->nr_processes;
	proc->process_rank = pn->process_rank;
	proc->heap_extension = pn->heap_extension;

	/* Update NUMA binding policy if requested */
	if (pn->mpol_bind_mask) {
		int bit;

		memset(&vm->numa_mask, 0, sizeof(vm->numa_mask));

		for_each_set_bit(bit, &pn->mpol_bind_mask,
				sizeof(pn->mpol_bind_mask) * BITS_PER_BYTE) {

			if (bit >= ihk_mc_get_nr_numa_nodes()) {
				kprintf("%s: error: NUMA id %d is larger than mask size!\n",
						__FUNCTION__, bit);
				return -EINVAL;
			}

			set_bit(bit, &vm->numa_mask[0]);
		}
		vm->numa_mem_policy = MPOL_BIND;
	}

	proc->uti_thread_rank = pn->uti_thread_rank;
	proc->uti_use_last_cpu = pn->uti_use_last_cpu;

#ifdef PROFILE_ENABLE
	proc->profile = pn->profile;
	thread->profile = pn->profile;
#endif

	vm->region.user_start = pn->user_start;
	vm->region.user_end = pn->user_end;
	if(vm->region.user_end > USER_END)
		vm->region.user_end = USER_END;

	/* map_start / map_end is used to track memory area
	 * to which the program is loaded
	 */
	vm->region.map_start = vm->region.map_end = LD_TASK_UNMAPPED_BASE;

	memcpy(proc->rlimit, pn->rlimit, sizeof(struct rlimit) * MCK_RLIM_MAX);
	dkprintf("%s: rlim_cur: %ld, rlim_max: %ld, stack_premap: %ld\n",
			__FUNCTION__,
			proc->rlimit[MCK_RLIMIT_STACK].rlim_cur,
			proc->rlimit[MCK_RLIMIT_STACK].rlim_max,
			pn->stack_premap);

	if (prepare_process_ranges_args_envs(thread, pn, p, attr, 
				NULL, 0, NULL, 0) != 0) {
		kprintf("error: preparing process ranges, args, envs, stack\n");
		goto err;
	}

	dkprintf("new process : %p [%d] / table : %p\n", proc, proc->pid,
	        vm->address_space->page_table);

	/* pn must be freed in load_executable or release_process */
	thread->proc->desc = pn;

	ihk_mc_unmap_virtual(p, npages);
	ihk_mc_unmap_memory(NULL, phys, sz);
	flush_tlb();

	return 0;
err:
	kfree(pn);
	ihk_mc_unmap_virtual(p, npages);
	ihk_mc_unmap_memory(NULL, phys, sz);
	destroy_thread(thread);
	return -ENOMEM;
}

static void syscall_channel_send(struct ihk_ikc_channel_desc *c,
                                 struct ikc_scd_packet *packet)
{
	ihk_ikc_send(c, packet, 0);
}

extern unsigned long do_kill(struct thread *, int, int, int, struct siginfo *, int ptracecont);
extern void terminate_host(int pid);
extern void debug_log(long);

static int syscall_packet_handler(struct ihk_ikc_channel_desc *c,
                                  void *__packet, void *ihk_os)
{
	struct ikc_scd_packet *packet = __packet;
	struct ikc_scd_packet pckt;
	struct ihk_ikc_channel_desc *resp_channel = cpu_local_var(ikc2linux);
	int rc;
	struct thread *thread;
	struct process *proc;
	struct mcctrl_signal {
		int	cond;
		int	sig;
		int	pid;
		int	tid;
		struct siginfo	info;
	} *sp, info;
	unsigned long pp;
	int cpuid;
	int ret = 0;
	struct perf_ctrl_desc *pcd;
	unsigned int mode = 0;

	switch (packet->msg) {
	case SCD_MSG_INIT_CHANNEL_ACKED:
		dkprintf("SCD_MSG_INIT_CHANNEL_ACKED\n");
		ret = 0;
		break;

	case SCD_MSG_PREPARE_PROCESS:

		pckt.err = process_msg_prepare_process(packet->arg);
		pckt.msg = SCD_MSG_PREPARE_PROCESS_ACKED;
		pckt.reply = packet->reply;
		pckt.ref = packet->ref;
		pckt.arg = packet->arg;
		syscall_channel_send(resp_channel, &pckt);

		ret = 0;
		break;

	case SCD_MSG_SCHEDULE_PROCESS:
		thread = (struct thread *)packet->arg;

		cpuid = obtain_clone_cpuid(&thread->cpu_set, 0);
		if (cpuid == -1) {
			kprintf("No CPU available\n");
			ret = -1;
			break;
		}

		dkprintf("SCD_MSG_SCHEDULE_PROCESS: %lx\n", packet->arg);
		proc = thread->proc;
		thread->tid = proc->pid;
		proc->status = PS_RUNNING;
		thread->status = PS_RUNNING;
		chain_thread(thread);
		chain_process(proc);
		runq_add_thread(thread, cpuid);

		ret = 0;
		break;

	/*
	 * Used for syscall offload reply message to explicitly schedule in
	 * the waiting thread
	 */
	case SCD_MSG_WAKE_UP_SYSCALL_THREAD:
		thread = find_thread(0, packet->ttid);
		if (!thread) {
			kprintf("%s: WARNING: no thread for SCD reply? TID: %d\n",
				__FUNCTION__, packet->ttid);
			ret = -EINVAL;
			break;
		}
		thread_unlock(thread);

		dkprintf("%s: SCD_MSG_WAKE_UP_SYSCALL_THREAD: waking up tid %d\n",
			__FUNCTION__, packet->ttid);
		waitq_wakeup(&thread->scd_wq);
		ret = 0;
		break;

	case SCD_MSG_SEND_SIGNAL:
		pp = ihk_mc_map_memory(NULL, packet->arg, sizeof(struct mcctrl_signal));
		sp = (struct mcctrl_signal *)ihk_mc_map_virtual(pp, 1, PTATTR_WRITABLE | PTATTR_ACTIVE);
		memcpy(&info, sp, sizeof(struct mcctrl_signal));
		ihk_mc_unmap_virtual(sp, 1);
		ihk_mc_unmap_memory(NULL, pp, sizeof(struct mcctrl_signal));
		pckt.msg = SCD_MSG_SEND_SIGNAL_ACK;
		pckt.err = 0;
		pckt.ref = packet->ref;
		pckt.arg = packet->arg;
		pckt.reply = packet->reply;
		syscall_channel_send(resp_channel, &pckt);

		rc = do_kill(NULL, info.pid, info.tid, info.sig, &info.info, 0);
		dkprintf("SCD_MSG_SEND_SIGNAL: do_kill(pid=%d, tid=%d, sig=%d)=%d\n", info.pid, info.tid, info.sig, rc);
		ret = 0;
		break;

	case SCD_MSG_PROCFS_REQUEST:
	case SCD_MSG_PROCFS_RELEASE:
		pckt.msg = SCD_MSG_PROCFS_ANSWER;
		pckt.ref = packet->ref;
		pckt.arg = packet->arg;
		pckt.err = process_procfs_request(packet);
		pckt.reply = packet->reply;
		pckt.pid = packet->pid;
		syscall_channel_send(resp_channel, &pckt);
		ret = 0;
		break;

	case SCD_MSG_CLEANUP_PROCESS:
		dkprintf("SCD_MSG_CLEANUP_PROCESS pid=%d\n", packet->pid);
		terminate_host(packet->pid);
		ret = 0;
		break;

	case SCD_MSG_DEBUG_LOG:
		dkprintf("SCD_MSG_DEBUG_LOG code=%lx\n", packet->arg);
		debug_log(packet->arg);
		ret = 0;
		break;

	case SCD_MSG_SYSFS_REQ_SHOW:
	case SCD_MSG_SYSFS_REQ_STORE:
	case SCD_MSG_SYSFS_REQ_RELEASE:
		sysfss_packet_handler(c, packet->msg, packet->err,
				packet->sysfs_arg1, packet->sysfs_arg2,
				packet->sysfs_arg3);
		ret = 0;
		break;

	case SCD_MSG_PERF_CTRL:
		pp = ihk_mc_map_memory(NULL, packet->arg, sizeof(struct perf_ctrl_desc));
		pcd = (struct perf_ctrl_desc *)ihk_mc_map_virtual(pp, 1, PTATTR_WRITABLE | PTATTR_ACTIVE);

		switch (pcd->ctrl_type) {
		case PERF_CTRL_SET:
			if (!pcd->exclude_kernel) {
				mode |= PERFCTR_KERNEL_MODE;
			}
			if (!pcd->exclude_user) {
				mode |= PERFCTR_USER_MODE;
			}

			ret = ihk_mc_perfctr_init_raw(pcd->target_cntr, pcd->config, mode);
			if (ret != 0) {
				break;
			}

#ifdef POSTK_DEBUG_ARCH_DEP_107 /* Add perfctr_first_stop I/F */
			ret = ihk_mc_perfctr_first_stop(1 << pcd->target_cntr);
#else /* POSTK_DEBUG_ARCH_DEP_107 */
			ret = ihk_mc_perfctr_stop(1 << pcd->target_cntr);
#endif /* POSTK_DEBUG_ARCH_DEP_107 */
			if (ret != 0) {
				break;
			}

			ret = ihk_mc_perfctr_reset(pcd->target_cntr);
			break;

		case PERF_CTRL_ENABLE:
			ret = ihk_mc_perfctr_start(pcd->target_cntr_mask);
			break;
			
		case PERF_CTRL_DISABLE:
			ret = ihk_mc_perfctr_stop(pcd->target_cntr_mask);
			break;

		case PERF_CTRL_GET:
			pcd->read_value = ihk_mc_perfctr_read(pcd->target_cntr);
			break;
			
		default:
			kprintf("%s: SCD_MSG_PERF_CTRL unexpected ctrl_type\n", __FUNCTION__);
		}

		ihk_mc_unmap_virtual(pcd, 1);
		ihk_mc_unmap_memory(NULL, pp, sizeof(struct perf_ctrl_desc));

		pckt.msg = SCD_MSG_PERF_ACK;
		pckt.err = ret;
		pckt.arg = packet->arg;
		pckt.reply = packet->reply;
		ihk_ikc_send(resp_channel, &pckt, 0);

		break;

	case SCD_MSG_CPU_RW_REG:

		pckt.msg = SCD_MSG_CPU_RW_REG_RESP;
		memcpy(&pckt.desc, &packet->desc,
				sizeof(struct ihk_os_cpu_register));
		pckt.resp = packet->resp;
		pckt.err = arch_cpu_read_write_register(&pckt.desc, packet->op);

		ihk_ikc_send(resp_channel, &pckt, 0);
		break;

	default:
		kprintf("syscall_pakcet_handler:unknown message "
				"(%d.%d.%d.%d.%d.%#lx)\n",
				packet->msg, packet->ref, packet->osnum,
				packet->pid, packet->err, packet->arg);
		ret = 0;
		break;

	}

	ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet);
	return ret;
}

static int dummy_packet_handler(struct ihk_ikc_channel_desc *c,
                                  void *__packet, void *__os)
{
	struct ikc_scd_packet *packet = __packet;
	ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet);
	return 0;
}

void init_host_ikc2linux(int linux_cpu)
{
	struct ihk_ikc_connect_param param;
	struct ihk_ikc_channel_desc *c;

	/* Main thread allocates channel pointer table */
	if (!ikc2linuxs) {
		ikc2linuxs = kmalloc(sizeof(*ikc2linuxs) *
				ihk_mc_get_nr_linux_cores(), IHK_MC_AP_NOWAIT);
		if (!ikc2linuxs) {
			kprintf("%s: error: allocating Linux channels\n", __FUNCTION__);
			panic("");
		}

		memset(ikc2linuxs, 0, sizeof(*ikc2linuxs) *
				ihk_mc_get_nr_linux_cores());
	}

	c = ikc2linuxs[linux_cpu];

	if (!c) {
		param.port = 503;
		param.intr_cpu = linux_cpu;
		param.pkt_size = sizeof(struct ikc_scd_packet);
		param.queue_size = 2 * num_processors * sizeof(struct ikc_scd_packet);
		if (param.queue_size < PAGE_SIZE * 4) {
			param.queue_size = PAGE_SIZE * 4;
		}
		param.magic = 0x1129;
		param.handler = dummy_packet_handler;

		dkprintf("(ikc2linux) Trying to connect host ...");
		while (ihk_ikc_connect(NULL, &param) != 0) {
			dkprintf(".");
			ihk_mc_delay_us(1000 * 1000);
		}
		dkprintf("connected.\n");

		ikc2linuxs[linux_cpu] = param.channel;
		c = param.channel;
	}

	get_this_cpu_local_var()->ikc2linux = c;
}

void init_host_ikc2mckernel(void)
{
	struct ihk_ikc_connect_param param;

	param.port = 501;
	param.intr_cpu = -1;
	param.pkt_size = sizeof(struct ikc_scd_packet);
	param.queue_size = PAGE_SIZE * 4;
	param.magic = 0x1329;
	param.handler = syscall_packet_handler;

	dkprintf("(ikc2mckernel) Trying to connect host ...");
	while (ihk_ikc_connect(NULL, &param) != 0) {
		dkprintf(".");
		ihk_mc_delay_us(1000 * 1000);
	}
	dkprintf("connected.\n");

	ihk_ikc_set_regular_channel(NULL, param.channel, ihk_ikc_get_processor_id());
}

