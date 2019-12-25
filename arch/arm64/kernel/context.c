/* context.c COPYRIGHT FUJITSU LIMITED 2015-2017 */
#include <ihk/context.h>
#include <ihk/debug.h>
#include <thread_info.h>
#include <cputype.h>
#include <mmu_context.h>
#include <arch-memory.h>
#include <irqflags.h>
#include <lwk/compiler.h>
#include <bitops.h>

/* @ref.impl arch/arm64/include/asm/mmu_context.h::MAX_ASID_BITS */
#define MAX_ASID_BITS		16
#define ASID_FIRST_VERSION	(1 << MAX_ASID_BITS)
#define ASID_MASK		((1 << MAX_ASID_BITS) - 1)
#define VERSION_MASK		(0xFFFF << MAX_ASID_BITS)

/* @ref.impl arch/arm64/mm/context.c::asid_bits */
#define asid_bits(reg) \
	(((read_cpuid(ID_AA64MMFR0_EL1) & 0xf0) >> 2) + 8)

#define MAX_CTX_NR		(1UL << MAX_ASID_BITS)
DECLARE_BITMAP(mmu_context_bmap, MAX_CTX_NR) = { 1 };	/* context number 0 reserved. */

/* cpu_asid lock */
static ihk_spinlock_t cpu_asid_lock = SPIN_LOCK_UNLOCKED;

/* last allocation ASID, initialized by 0x0001_0000 */
static unsigned int cpu_last_asid = ASID_FIRST_VERSION;

/* @ref.impl arch/arm64/mm/context.c::set_mm_context */
/* set asid for kernel_context_t.context */
static void set_mm_context(struct page_table *pgtbl, unsigned int asid)
{
	unsigned int context = get_address_space_id(pgtbl);
	if (likely((context ^ cpu_last_asid) >> MAX_ASID_BITS)) {
		set_address_space_id(pgtbl, asid);
	}
}

/* @ref.impl arch/arm64/mm/context.c::__new_context */
/* ASID allocation for new process function */
static inline void __new_context(struct page_table *pgtbl)
{
	unsigned int asid;
	unsigned int bits = asid_bits();
	unsigned long flags;
	unsigned int context = get_address_space_id(pgtbl);
	unsigned long index = 0;

	flags = ihk_mc_spinlock_lock(&cpu_asid_lock);

	/* already assigned context number? */
	if (!unlikely((context ^ cpu_last_asid) >> MAX_ASID_BITS)) {
		/* true, unnecessary assigned context number */
		ihk_mc_spinlock_unlock(&cpu_asid_lock, flags);
		return;
	}

	/* false, necessary assigned context number */
	/* search from the previous assigned number */
	index = (cpu_last_asid & ASID_MASK) + 1;
	asid = find_next_zero_bit(mmu_context_bmap, MAX_CTX_NR, index);

	/* upper limit exceeded */
	if (asid >= (1 << bits)) {
		/* re assigned context number, search from 1 */
		asid = find_next_zero_bit(mmu_context_bmap, index, 1);

		/* upper previous assigned number, goto panic */
		if (unlikely(asid >= index)) {
			ihk_mc_spinlock_unlock(&cpu_asid_lock, flags);
			panic("__new_context(): PANIC: Context Number Depletion.\n");
		}
	}

	/* set assigned context number bitmap */
	mmu_context_bmap[asid >> 6] |= (1UL << (asid & 63));

	/* set previous assigned context number */
	cpu_last_asid = asid | (cpu_last_asid & VERSION_MASK);

	set_mm_context(pgtbl, cpu_last_asid);
	ihk_mc_spinlock_unlock(&cpu_asid_lock, flags);
}

void free_mmu_context(struct page_table *pgtbl)
{
	unsigned int context = get_address_space_id(pgtbl);
	unsigned int nr = context & ASID_MASK;
	unsigned long flags = ihk_mc_spinlock_lock(&cpu_asid_lock);

	/* clear used context number bitmap */
	mmu_context_bmap[nr >> 6] &= ~(1UL << (nr & 63));
	ihk_mc_spinlock_unlock(&cpu_asid_lock, flags);
}

/* set ttbr0 assembler code extern */
/* in arch/arm64/kernel/proc.S */
extern void *cpu_do_switch_mm(translation_table_t* tt_pa, unsigned int asid);

/* @ref.impl arch/arm64/include/asm/mmu_context.h::switch_new_context */
/* ASID allocation for new process */
static inline void switch_new_context(struct page_table *pgtbl)
{
	unsigned long flags;
	translation_table_t* tt_pa;
	unsigned int context;

	/* ASID allocation */
	__new_context(pgtbl);
	context = get_address_space_id(pgtbl);

	/* disable interrupt save */
	flags = cpu_disable_interrupt_save();

	tt_pa = get_translation_table_as_paddr(pgtbl);
	//kprintf("%s: -> ASID: %d\n", __func__, (context & ASID_MASK));
	cpu_do_switch_mm(tt_pa, context & ASID_MASK);

	/* interrupt restore */
	cpu_restore_interrupt(flags);
}

/* @ref.impl arch/arm64/include/asm/mmu_context.h::check_and_switch_context */
/* ASID allocation */
void switch_mm(struct page_table *pgtbl)
{
#if 0
	unsigned int context = get_address_space_id(pgtbl);

	/* During switch_mm, you want to disable the TTBR */
	cpu_set_reserved_ttbr0();

	/* check new process or existing process */
	if (!((context ^ cpu_last_asid) >> MAX_ASID_BITS)) {
		translation_table_t* tt_pa;

		/* for existing process */
		tt_pa = get_translation_table_as_paddr(pgtbl);
		//kprintf("%s: -> ASID: %d\n", __func__, (context & ASID_MASK));
		cpu_do_switch_mm(tt_pa, context & ASID_MASK);

/* TODO: tif_switch_mm / after context switch */
//	} else if (irqs_disabled()) {
//		/*
//		 * Defer the new ASID allocation until after the context
//		 * switch critical region since __new_context() cannot be
//		 * called with interrupts disabled.
//		 */
//		set_ti_thread_flag(task_thread_info(tsk), TIF_SWITCH_MM);
	} else {
		/* for new process */
		/* ASID allocation & set ttbr0 */
		switch_new_context(pgtbl);
	}
#else
	translation_table_t* tt_pa;
	unsigned int context = get_address_space_id(pgtbl);

	//kprintf("%s: -> ASID: %d\n", __func__, (context & ASID_MASK));

	/* During switch_mm, you want to disable the TTBR */
	cpu_set_reserved_ttbr0();

	/* ASID is inherited from Linux */
	tt_pa = get_translation_table_as_paddr(pgtbl);
	cpu_do_switch_mm(tt_pa, context & ASID_MASK);
#endif
}

/* context switch assembler code extern */
/* in arch/arm64/kernel/entry.S */
extern void *cpu_switch_to(struct thread_info *prev, struct thread_info *next, void *prev_proc);

/* context switch C function */
/* TODO: fpreg etc.. save & restore */
static inline void *switch_to(struct thread_info *prev,
		       struct thread_info *next,
		       void *prev_proc)
{
	void *last = NULL;

	next->cpu = ihk_mc_get_processor_id();
	last = cpu_switch_to(prev, next, prev_proc);

	return last;
}

/* common unit I/F, for context switch */
void *ihk_mc_switch_context(ihk_mc_kernel_context_t *old_ctx,
			    ihk_mc_kernel_context_t *new_ctx,
			    void *prev)
{
	struct thread_info *prev_ti = NULL;
	struct thread_info *next_ti = NULL;

	/* get next thread_info addr */
	next_ti = new_ctx->thread;
	if (likely(old_ctx)) {
		/* get prev thread_info addr */
		prev_ti = old_ctx->thread;
	}

	/* switch next thread_info & process */
	return switch_to(prev_ti, next_ti, prev);
}
