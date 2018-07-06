/* head.S COPYRIGHT FUJITSU LIMITED 2015-2018 */

#include <linkage.h>
#include <ptrace.h>
#include <assembler.h>
#include <asm-offsets.h>
#include <virt.h>
#include <cache.h>
#include <arch-memory.h>
#include <smp.h>
#include <arm-gic-v3.h>

#define KERNEL_RAM_VADDR	MAP_KERNEL_START

//#ifndef CONFIG_SMP
//# define PTE_FLAGS	PTE_TYPE_PAGE | PTE_AF
//# define PMD_FLAGS	PMD_TYPE_SECT | PMD_SECT_AF
//#else
# define PTE_FLAGS	PTE_TYPE_PAGE | PTE_AF | PTE_SHARED
# define PMD_FLAGS	PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_S
//#endif /*CONFIG_SMP*/

#ifdef CONFIG_ARM64_64K_PAGES
# define MM_MMUFLAGS	PTE_ATTRINDX(MT_NORMAL) | PTE_FLAGS
#else
# define MM_MMUFLAGS	PMD_ATTRINDX(MT_NORMAL) | PMD_FLAGS
#endif

	.macro	pgtbl_init_core, name, dir, tbl, ents, virt_to_phys
	ldr	\tbl, =\name
	ldr	\ents, =\dir
	add	\tbl, \tbl, \virt_to_phys
	str	\ents, [\tbl]
	add	\tbl, \tbl, #8
	add	\ents, \ents, \virt_to_phys
	str	\ents, [\tbl]
	.endm
		
	.macro	pgtbl_init, tbl, ents, virt_to_phys
	pgtbl_init_core	swapper_page_table, swapper_pg_dir, \tbl, \ents, \virt_to_phys
	pgtbl_init_core	idmap_page_table, idmap_pg_dir, \tbl, \ents, \virt_to_phys
	.endm

	.macro	pgtbl, ttb0, ttb1, virt_to_phys
	ldr	\ttb1, =swapper_pg_dir
	ldr	\ttb0, =idmap_pg_dir
	add	\ttb1, \ttb1, \virt_to_phys
	add	\ttb0, \ttb0, \virt_to_phys
	.endm

#define KERNEL_START	KERNEL_RAM_VADDR
#define KERNEL_END	_end

/* ihk param offset */
#define TRAMPOLINE_DATA_RESERVED_SIZE          0x08
#define TRAMPOLINE_DATA_PGTBL_SIZE             0x08
#define TRAMPOLINE_DATA_LOAD_SIZE              0x08
#define TRAMPOLINE_DATA_STACK_SIZE             0x08
#define TRAMPOLINE_DATA_BOOT_PARAM_SIZE        0x08
#define TRAMPOLINE_DATA_STARTUP_DATA_SIZE      0x08
#define TRAMPOLINE_DATA_ST_PHYS_BASE_SIZE      0x08
#define TRAMPOLINE_DATA_ST_PHYS_SIZE_SIZE      0x08
#define TRAMPOLINE_DATA_GIC_DIST_PA_SIZE       0x08
#define TRAMPOLINE_DATA_GIC_DIST_MAP_SIZE_SIZE 0x08
#define TRAMPOLINE_DATA_GIC_CPU_PA_SIZE        0x08
#define TRAMPOLINE_DATA_GIC_CPU_MAP_SIZE_SIZE  0x08
#define TRAMPOLINE_DATA_GIC_PERCPU_OFF_SIZE    0x04
#define TRAMPOLINE_DATA_GIC_VERSION_SIZE       0x04
#define TRAMPOLINE_DATA_LPJ_SIZE               0x08
#define TRAMPOLINE_DATA_HZ_SIZE                0x08
#define TRAMPOLINE_DATA_PSCI_METHOD_SIZE       0x08
#define TRAMPOLINE_DATA_USE_VIRT_TIMER_SIZE    0x08
#define TRAMPOLINE_DATA_EVTSTRM_TIMER_RATE_SIZE	0x08
#define TRAMPOLINE_DATA_DEFAULT_VL_SIZE        0x08
#define TRAMPOLINE_DATA_CPU_MAP_SIZE_SIZE      0x08
#define TRAMPOLINE_DATA_CPU_MAP_SIZE           (NR_CPUS * 8)
#define TRAMPOLINE_DATA_DATA_RDISTS_PA_SIZE    (NR_CPUS * 8)
#define TRAMPOLINE_DATA_RETENTION_STATE_FLAG_PA_SIZE 0x08
#define TRAMPOLINE_DATA_NR_PMU_AFFI_SIZE       0x04
#define TRAMPOLINE_DATA_PMU_AFF_SIZE           (CONFIG_SMP_MAX_CORES * 4)

#define STARTUP_DATA_RESERVED		0x00
#define STARTUP_DATA_BASE		0x08
#define STARTUP_DATA_PGTBL		0x10
#define STARTUP_DATA_STACK		0x18
#define STARTUP_DATA_ARG2		0x20
#define STARTUP_DATA_TRAMPILINE		0x28
#define STARTUP_DATA_NEXT_PC		0x30

/* ihk param save area */
	.globl	ihk_param_head
	.globl	ihk_param_gic_dist_base_pa, ihk_param_gic_cpu_base_pa
	.globl	ihk_param_gic_dist_map_size, ihk_param_gic_cpu_map_size
	.globl	ihk_param_gic_percpu_offset, ihk_param_gic_version
	.globl	ihk_param_lpj, ihk_param_hz, ihk_param_psci_method
	.globl	ihk_param_cpu_logical_map, ihk_param_gic_rdist_base_pa
	.globl	ihk_param_pmu_irq_affi, ihk_param_nr_pmu_irq_affi
	.globl	ihk_param_use_virt_timer, ihk_param_evtstrm_timer_rate
	.globl	ihk_param_retention_state_flag_pa, ihk_param_default_vl
ihk_param_head:
ihk_param_param_addr:
	.quad	0
ihk_param_phys_addr:
	.quad	0
ihk_param_st_phys_base:
	.quad	0
ihk_param_st_phys_size:
	.quad	0
ihk_param_gic_dist_base_pa:
	.quad	0
ihk_param_gic_dist_map_size:
	.quad	0
ihk_param_gic_cpu_base_pa:
	.quad	0
ihk_param_gic_cpu_map_size:
	.quad	0
ihk_param_gic_percpu_offset:
	.word	0
ihk_param_gic_version:
	.word	0
ihk_param_lpj:
	.quad	0		/* udelay loops value */
ihk_param_hz:
	.quad	0		/* host HZ value */
ihk_param_psci_method:
	.quad	0		/* hvc or smc ? */
ihk_param_use_virt_timer:
	.quad	0		/* virt timer or phys timer ? */
ihk_param_evtstrm_timer_rate:
	.quad	0		/* event stream timer rate */
ihk_param_default_vl:
	.quad	0		/* SVE default VL */
ihk_param_cpu_logical_map:
	.skip	NR_CPUS * 8	/* array of the MPIDR and the core number */
ihk_param_gic_rdist_base_pa:
	.skip	NR_CPUS * 8	/* per-cpu re-distributer PA */
ihk_param_retention_state_flag_pa:
	.quad	0
ihk_param_pmu_irq_affi:
	.skip	CONFIG_SMP_MAX_CORES * 4	/* array of the pmu affinity list */
ihk_param_nr_pmu_irq_affi:
	.word	0		/* number of pmu affinity list elements. */

/* @ref.impl arch/arm64/include/asm/kvm_arm.h */
#define HCR_E2H		(UL(1) << 34)
#define HCR_RW_SHIFT	31
#define HCR_RW		(UL(1) << HCR_RW_SHIFT)
#define HCR_TGE		(UL(1) << 27)

/*
 * end early head section, begin head code that is also used for
 * hotplug and needs to have the same protections as the text region
 */
	.section ".text","ax"

ENTRY(arch_start)
	/* store ihk param */
	/* x4 = ihk_smp_trampoline_data PA */
	add x0, x4, #TRAMPOLINE_DATA_RESERVED_SIZE
	/* header_pgtbl */
	add x0, x0, #TRAMPOLINE_DATA_PGTBL_SIZE
	/* header_load */
	add x0, x0, #TRAMPOLINE_DATA_LOAD_SIZE
	/* stack_ptr */
	add x0, x0, #TRAMPOLINE_DATA_STACK_SIZE
	/* notify_address */
	ldr	x16, [x0], #TRAMPOLINE_DATA_BOOT_PARAM_SIZE
	adr	x15, ihk_param_param_addr
	str	x16, [x15]
	/* startup_data */
	ldr	x16, [x0], #TRAMPOLINE_DATA_STARTUP_DATA_SIZE
	ldr	x15, [x16, #STARTUP_DATA_ARG2]
	adr	x17, ihk_param_phys_addr
	str	x15, [x17]
	/* st_phys_base */
	ldr	x16, [x0], #TRAMPOLINE_DATA_ST_PHYS_BASE_SIZE
	adr	x15, ihk_param_st_phys_base
	str	x16, [x15]
	/* st_phys_size */
	ldr	x16, [x0], #TRAMPOLINE_DATA_ST_PHYS_SIZE_SIZE
	adr	x15, ihk_param_st_phys_size
	str	x16, [x15]
	/* dist_base_pa */
	ldr	x16, [x0], #TRAMPOLINE_DATA_GIC_DIST_PA_SIZE
	adr	x15, ihk_param_gic_dist_base_pa
	str	x16, [x15]
	/* dist_map_size */
	ldr	x16, [x0], #TRAMPOLINE_DATA_GIC_DIST_MAP_SIZE_SIZE
	adr	x15, ihk_param_gic_dist_map_size
	str	x16, [x15]
	/* cpu_base_pa */
	ldr	x16, [x0], #TRAMPOLINE_DATA_GIC_CPU_PA_SIZE
	adr	x15, ihk_param_gic_cpu_base_pa
	str	x16, [x15]
	/* cpu_map_size */
	ldr	x16, [x0], #TRAMPOLINE_DATA_GIC_CPU_MAP_SIZE_SIZE
	adr	x15, ihk_param_gic_cpu_map_size
	str	x16, [x15]
	/* percpu_offset */
	ldr	w16, [x0], #TRAMPOLINE_DATA_GIC_PERCPU_OFF_SIZE
	adr	x15, ihk_param_gic_percpu_offset
	str	w16, [x15]
	/* gic_version */
	ldr	w16, [x0], #TRAMPOLINE_DATA_GIC_VERSION_SIZE
	adr	x15, ihk_param_gic_version
	str	w16, [x15]
	/* loops_per_jiffy */
	ldr	x16, [x0], #TRAMPOLINE_DATA_LPJ_SIZE
	adr	x15, ihk_param_lpj
	str	x16, [x15]
	/* hz */
	ldr	x16, [x0], #TRAMPOLINE_DATA_HZ_SIZE
	adr	x15, ihk_param_hz
	str	x16, [x15]
	/* psci_method */
	ldr	x16, [x0], #TRAMPOLINE_DATA_PSCI_METHOD_SIZE
	adr	x15, ihk_param_psci_method
	str	x16, [x15]
	/* use_virt_timer */
	ldr	x16, [x0], #TRAMPOLINE_DATA_USE_VIRT_TIMER_SIZE
	adr	x15, ihk_param_use_virt_timer
	str	x16, [x15]
	/* evtstrm_timer_rate */
	ldr	x16, [x0], #TRAMPOLINE_DATA_EVTSTRM_TIMER_RATE_SIZE
	adr	x15, ihk_param_evtstrm_timer_rate
	str	x16, [x15]
	/* SVE default VL */
	ldr	x16, [x0], #TRAMPOLINE_DATA_DEFAULT_VL_SIZE
	adr	x15, ihk_param_default_vl
	str	x16, [x15]
	/* cpu_logical_map_size */
	ldr	x16, [x0], #TRAMPOLINE_DATA_CPU_MAP_SIZE_SIZE
	mov	x1, x16
	/* cpu_logical_map */
	adr	x15, ihk_param_cpu_logical_map
	mov	x18, x0
1:	ldr	x17, [x18], #8
	str	x17, [x15], #8
	sub	x16, x16, #1
	cmp	x16, #0
	b.ne	1b
	mov x16, #NR_CPUS /* calc next data */
	lsl x16, x16, 3
	add x0, x0, x16

	/* reset cpu_logical_map_size */
	mov	x16, x1
	/* gic_rdist_base_pa */
	adr	x15, ihk_param_gic_rdist_base_pa
	mov	x18, x0
1:	ldr	x17, [x18], #8
	str	x17, [x15], #8
	sub	x16, x16, #1
	cmp	x16, #0
	b.ne	1b
	mov x16, #NR_CPUS /* calc next data */
	lsl x16, x16, 3
	add x0, x0, x16
	/* retention_state_flag_pa */
	ldr	x16, [x0], #TRAMPOLINE_DATA_RETENTION_STATE_FLAG_PA_SIZE
	adr	x15, ihk_param_retention_state_flag_pa
	str	x16, [x15]
	/* nr_pmu_irq_affi */
	ldr	w16, [x0], #TRAMPOLINE_DATA_NR_PMU_AFFI_SIZE
	adr	x15, ihk_param_nr_pmu_irq_affi
	str	w16, [x15]
	/* pmu_irq_affi */
	mov x18, x0
	adr	x15, ihk_param_pmu_irq_affi
	b	2f
1:	ldr	w17, [x18], #4
	str	w17, [x15], #4
	sub	w16, w16, #1
2:	cmp	w16, #0
	b.ne	1b

	mov x16, #CONFIG_SMP_MAX_CORES  /* calc next data */
	lsl x16, x16, 2
	add x0, x0, x16
	/* */
	bl	__calc_phys_offset	// x24=PHYS_OFFSET, x28=PHYS_OFFSET-KERNEL_START
	bl	__create_page_tables	// x25=TTBR0, x26=TTBR1
	b	secondary_entry_common
ENDPROC(arch_start)

ENTRY(arch_ap_start)
	bl	__calc_phys_offset	// x24=PHYS_OFFSET, x28=PHYS_OFFSET-KERNEL_START
	b	secondary_entry_common
ENDPROC(arch_ap_start)

/*
 * Macro to create a table entry to the next page.
 *
 *	tbl:	page table address
 *	virt:	virtual address
 *	shift:	#imm page table shift
 *	ptrs:	#imm pointers per table page
 *
 * Preserves:	virt
 * Corrupts:	tmp1, tmp2
 * Returns:	tbl -> next level table page address
 */
	.macro	create_table_entry, tbl, virt, shift, ptrs, tmp1, tmp2
	lsr	\tmp1, \virt, #\shift
	and	\tmp1, \tmp1, #\ptrs - 1	// table index
	add	\tmp2, \tbl, #PAGE_SIZE
	orr	\tmp2, \tmp2, #PMD_TYPE_TABLE	// address of next table and entry type
	str	\tmp2, [\tbl, \tmp1, lsl #3]
	add	\tbl, \tbl, #PAGE_SIZE		// next level table page
	.endm

/*
 * Macro to populate the PGD (and possibily PUD) for the corresponding
 * block entry in the next level (tbl) for the given virtual address.
 *
 * Preserves:	tbl, next, virt
 * Corrupts:	tmp1, tmp2
 */
	.macro	create_pgd_entry, tbl, virt, tmp1, tmp2
	create_table_entry \tbl, \virt, PGDIR_SHIFT, PTRS_PER_PGD, \tmp1, \tmp2
#if SWAPPER_PGTABLE_LEVELS == 3
	create_table_entry \tbl, \virt, TABLE_SHIFT, PTRS_PER_PTE, \tmp1, \tmp2
#endif
	.endm

/*
 * Macro to populate block entries in the page table for the start..end
 * virtual range (inclusive).
 *
 * Preserves:	tbl, flags
 * Corrupts:	phys, start, end, pstate
 */
	.macro	create_block_map, tbl, flags, phys, start, end
	lsr	\phys, \phys, #BLOCK_SHIFT
	lsr	\start, \start, #BLOCK_SHIFT
	and	\start, \start, #PTRS_PER_PTE - 1	// table index
	orr	\phys, \flags, \phys, lsl #BLOCK_SHIFT	// table entry
	lsr	\end, \end, #BLOCK_SHIFT
	and	\end, \end, #PTRS_PER_PTE - 1		// table end index
9999:	str	\phys, [\tbl, \start, lsl #3]		// store the entry
	add	\start, \start, #1			// next entry
	add	\phys, \phys, #BLOCK_SIZE		// next block
	cmp	\start, \end
	b.ls	9999b
	.endm

/*
 * Setup the initial page tables. We only setup the barest amount which is
 * required to get the kernel running. The following sections are required:
 *   - identity mapping to enable the MMU (low address, TTBR0)
 *   - first few MB of the kernel linear mapping to jump to once the MMU has
 *     been enabled, including the FDT blob (TTBR1)
 *   - pgd entry for fixed mappings (TTBR1)
 */
__create_page_tables:
	pgtbl_init x25, x26, x28
	pgtbl	x25, x26, x28			// idmap_pg_dir and swapper_pg_dir addresses
	mov	x27, lr

	/*
	 * Invalidate the idmap and swapper page tables to avoid potential
	 * dirty cache lines being evicted.
	 */
	mov	x0, x25
	add	x1, x26, #SWAPPER_DIR_SIZE
	bl	__inval_cache_range

	/*
	 * Clear the idmap and swapper page tables.
	 */
	mov	x0, x25
	add	x6, x26, #SWAPPER_DIR_SIZE
1:	stp	xzr, xzr, [x0], #16
	stp	xzr, xzr, [x0], #16
	stp	xzr, xzr, [x0], #16
	stp	xzr, xzr, [x0], #16
	cmp	x0, x6
	b.lo	1b

	ldr	x7, =MM_MMUFLAGS

	/*
	 * Create the identity mapping.
	 */
	mov	x0, x25				// idmap_pg_dir
	ldr	x3, =KERNEL_START
	add	x3, x3, x28			// __pa(KERNEL_START)
	create_pgd_entry x0, x3, x5, x6
	ldr	x6, =KERNEL_END
	mov	x5, x3				// __pa(KERNEL_START)
	add	x6, x6, x28			// __pa(KERNEL_END)
	create_block_map x0, x7, x3, x5, x6

	/*
	 * Map the kernel image (starting with PHYS_OFFSET).
	 */
	mov	x0, x26				// swapper_pg_dir
	ldr	x5, =KERNEL_START
	create_pgd_entry x0, x5, x3, x6
	ldr	x6, =KERNEL_END
	mov	x3, x24				// phys offset
	create_block_map x0, x7, x3, x5, x6

	/*
	 * Map the early_alloc_pages area, kernel_img next block
	 */
	ldr	x3, =KERNEL_END
	add	x3, x3, x28			// __pa(KERNEL_END)
	add	x3, x3, #BLOCK_SIZE
	sub	x3, x3, #1
	bic	x3, x3, #(BLOCK_SIZE - 1)	// start PA calc.
	ldr	x5, =KERNEL_END			// get start VA
	add     x5, x5, #BLOCK_SIZE
	sub	x5, x5, #1
	bic	x5, x5, #(BLOCK_SIZE - 1)	// start VA calc.
	mov	x6, #MAP_EARLY_ALLOC_SIZE
	add	x6, x5, x6			// end VA calc
	mov	x23, x6				// save end VA
	sub	x6, x6, #1			// inclusive range
	create_block_map x0, x7, x3, x5, x6

	/*
	 * Map the boot_param area
	 */
	adr	x3, ihk_param_param_addr
	ldr	x3, [x3]			// get boot_param PA
	mov	x5, x23				// get start VA
	add     x5, x5, #BLOCK_SIZE
	sub	x5, x5, #1
	bic	x5, x5, #(BLOCK_SIZE - 1)	// start VA calc
	mov	x6, #MAP_BOOT_PARAM_SIZE
	add	x6, x5, x6			// end VA calc.
	sub	x6, x6, #1			// inclusive range
	create_block_map x0, x7, x3, x5, x6

	/*
	 * Map the FDT blob (maximum 2MB; must be within 512MB of
	 * PHYS_OFFSET).
	 */
/* FDT disable for McKernel */
//	mov	x3, x21				// FDT phys address
//	and	x3, x3, #~((1 << 21) - 1)	// 2MB aligned
//	mov	x6, #PAGE_OFFSET
//	sub	x5, x3, x24			// subtract PHYS_OFFSET
//	tst	x5, #~((1 << 29) - 1)		// within 512MB?
//	csel	x21, xzr, x21, ne		// zero the FDT pointer
//	b.ne	1f
//	add	x5, x5, x6			// __va(FDT blob)
//	add	x6, x5, #1 << 21		// 2MB for the FDT blob
//	sub	x6, x6, #1			// inclusive range
//	create_block_map x0, x7, x3, x5, x6
1:
	/*
	 * Since the page tables have been populated with non-cacheable
	 * accesses (MMU disabled), invalidate the idmap and swapper page
	 * tables again to remove any speculatively loaded cache lines.
	 */
	mov	x0, x25
	add	x1, x26, #SWAPPER_DIR_SIZE
	bl	__inval_cache_range

	mov	lr, x27
	ret
ENDPROC(__create_page_tables)
	.ltorg

/*
 * If we're fortunate enough to boot at EL2, ensure that the world is
 * sane before dropping to EL1.
 *
 * Returns either BOOT_CPU_MODE_EL1 or BOOT_CPU_MODE_EL2 in x20 if
 * booted in EL1 or EL2 respectively.
 */
ENTRY(el2_setup)
	mrs	x0, CurrentEL
	cmp	x0, #CurrentEL_EL2
	b.ne	1f
	mrs	x0, sctlr_el2
CPU_BE(	orr	x0, x0, #(1 << 25)	)	// Set the EE bit for EL2
CPU_LE(	bic	x0, x0, #(1 << 25)	)	// Clear the EE bit for EL2
	msr	sctlr_el2, x0
	b	2f
1:	mrs	x0, sctlr_el1
CPU_BE(	orr	x0, x0, #(3 << 24)	)	// Set the EE and E0E bits for EL1
CPU_LE(	bic	x0, x0, #(3 << 24)	)	// Clear the EE and E0E bits for EL1
	msr	sctlr_el1, x0
	mov	w20, #BOOT_CPU_MODE_EL1		// This cpu booted in EL1
	isb
	ret

2:
#ifdef CONFIG_ARM64_VHE
	/*
	 * Check for VHE being present. For the rest of the EL2 setup,
	 * x2 being non-zero indicates that we do have VHE, and that the
	 * kernel is intended to run at EL2.
	 */
	mrs	x2, id_aa64mmfr1_el1
	ubfx	x2, x2, #8, #4
#else /* CONFIG_ARM64_VHE */
	mov	x2, xzr
#endif /* CONFIG_ARM64_VHE */

	/* Hyp configuration. */
	mov	x0, #HCR_RW			// 64-bit EL1
	cbz	x2, set_hcr
	orr	x0, x0, #HCR_TGE		// Enable Host Extensions
	orr	x0, x0, #HCR_E2H
set_hcr:
	msr	hcr_el2, x0
	isb

	/* Generic timers. */
	mrs	x0, cnthctl_el2
	orr	x0, x0, #3			// Enable EL1 physical timers
	msr	cnthctl_el2, x0
	msr	cntvoff_el2, xzr		// Clear virtual offset

#ifdef CONFIG_ARM_GIC_V3
	/* GICv3 system register access */
	mrs	x0, id_aa64pfr0_el1
	ubfx	x0, x0, #24, #4
	cmp	x0, #1
	b.ne	3f

	mrs_s	x0, ICC_SRE_EL2
	orr	x0, x0, #ICC_SRE_EL2_SRE	// Set ICC_SRE_EL2.SRE==1
	orr	x0, x0, #ICC_SRE_EL2_ENABLE	// Set ICC_SRE_EL2.Enable==1
	msr_s	ICC_SRE_EL2, x0
	isb					// Make sure SRE is now set
	msr_s	ICH_HCR_EL2, xzr		// Reset ICC_HCR_EL2 to defaults

3:
#endif

	/* Populate ID registers. */
	mrs	x0, midr_el1
	mrs	x1, mpidr_el1
	msr	vpidr_el2, x0
	msr	vmpidr_el2, x1

	/*
	 * When VHE is not in use, early init of EL2 and EL1 needs to be
	 * done here.
	 * When VHE _is_ in use, EL1 will not be used in the host and
	 * requires no configuration, and all non-hyp-specific EL2 setup
	 * will be done via the _EL1 system register aliases in __cpu_setup.
	 */
	cbnz	x2, 1f

	/* sctlr_el1 */
	mov	x0, #0x0800			// Set/clear RES{1,0} bits
CPU_BE(	movk	x0, #0x33d0, lsl #16	)	// Set EE and E0E on BE systems
CPU_LE(	movk	x0, #0x30d0, lsl #16	)	// Clear EE and E0E on LE systems
	msr	sctlr_el1, x0

	/* Coprocessor traps. */
	mov	x0, #0x33ff

	/* SVE register access */
	mrs	x1, id_aa64pfr0_el1
	ubfx	x1, x1, #ID_AA64PFR0_SVE_SHIFT, #4
	cbz	x1, 4f

	bic	x0, x0, #CPTR_EL2_TZ		// Disable SVE traps to EL2
	msr	cptr_el2, x0			// Disable copro. traps to EL2
	isb
 
	mov	x1, #ZCR_EL1_LEN_MASK		// SVE: Enable full vector
	msr_s	SYS_ZCR_EL1, x1			// length for EL1.
	b	1f

4:	msr	cptr_el2, x0			// Disable copro. traps to EL2
1:
#ifdef CONFIG_COMPAT
	msr	hstr_el2, xzr			// Disable CP15 traps to EL2
#endif

	/* Stage-2 translation */
	msr	vttbr_el2, xzr

	cbz	x2, install_el2_stub

	mov	w20, #BOOT_CPU_MODE_EL2		// This CPU booted in EL2
	isb
	ret

install_el2_stub:
	/* Hypervisor stub */
	adrp	x0, __hyp_stub_vectors
	add	x0, x0, #:lo12:__hyp_stub_vectors
	msr	vbar_el2, x0

	/* spsr */
	mov	x0, #(PSR_F_BIT | PSR_I_BIT | PSR_A_BIT | PSR_D_BIT |\
		      PSR_MODE_EL1h)
	msr	spsr_el2, x0
	msr	elr_el2, lr
	mov	w20, #BOOT_CPU_MODE_EL2		// This CPU booted in EL2
	eret
ENDPROC(el2_setup)

/*
 * Sets the __boot_cpu_mode flag depending on the CPU boot mode passed
 * in x20. See arch/arm64/include/asm/virt.h for more info.
 */
ENTRY(set_cpu_boot_mode_flag)
	ldr	x1, =__boot_cpu_mode		// Compute __boot_cpu_mode
	add	x1, x1, x28
	cmp	w20, #BOOT_CPU_MODE_EL2
	b.ne	1f
	add	x1, x1, #4
1:	str	w20, [x1]			// This CPU has booted in EL1
	dmb	sy
	dc	ivac, x1			// Invalidate potentially stale cache line
	ret
ENDPROC(set_cpu_boot_mode_flag)

#if defined(CONFIG_HAS_NMI)
/*
 * void maybe_switch_to_sysreg_gic_cpuif(void)
 *
 * Enable interrupt controller system register access if this feature
 * has been detected by the alternatives system.
 *
 * Before we jump into generic code we must enable interrupt controller system
 * register access because this is required by the irqflags macros.  We must
 * also mask interrupts at the PMR and unmask them within the PSR. That leaves
 * us set up and ready for the kernel to make its first call to
 * arch_local_irq_enable().
 *
 */
ENTRY(maybe_switch_to_sysreg_gic_cpuif)
	mrs_s	x0, ICC_SRE_EL1
	orr	x0, x0, #1
	msr_s	ICC_SRE_EL1, x0		// Set ICC_SRE_EL1.SRE==1
	isb				// Make sure SRE is now set
	mov	x0, ICC_PMR_EL1_MASKED
	msr_s	ICC_PMR_EL1, x0		// Prepare for unmask of I bit
	msr	daifclr, #2		// Clear the I bit
	ret
ENDPROC(maybe_switch_to_sysreg_gic_cpuif)
#else
ENTRY(maybe_switch_to_sysreg_gic_cpuif)
	ret
ENDPROC(maybe_switch_to_sysreg_gic_cpuif)
#endif /* defined(CONFIG_HAS_NMI) */

/*
 * We need to find out the CPU boot mode long after boot, so we need to
 * store it in a writable variable.
 *
 * This is not in .bss, because we set it sufficiently early that the boot-time
 * zeroing of .bss would clobber it.
 */
	.pushsection	.data..cacheline_aligned
ENTRY(__boot_cpu_mode)
	.align	L1_CACHE_SHIFT
	.long	BOOT_CPU_MODE_EL2
	.long	0
	.popsection

ENTRY(secondary_entry_common)
	bl	el2_setup		// Drop to EL1
	bl	set_cpu_boot_mode_flag
	b	secondary_startup
ENDPROC(secondary_entry_common)

ENTRY(secondary_startup)
	/*
	 * Common entry point for secondary CPUs.
	 */
	mrs	x22, midr_el1			// x22=cpuid
	mov	x0, x22
	bl	lookup_processor_type
	mov	x23, x0				// x23=current cpu_table
	cbz	x23, __error_p			// invalid processor (x23=0)?

	pgtbl	x25, x26, x28			// x25=TTBR0, x26=TTBR1
	ldr	x12, [x23, #CPU_INFO_SETUP]
	add	x12, x12, x28			// __virt_to_phys
	blr	x12				// initialise processor

	ldr	x21, =secondary_data
	ldr	x27, =__secondary_switched	// address to jump to after enabling the MMU
	b	__enable_mmu
ENDPROC(secondary_startup)

ENTRY(__secondary_switched)
	ldr	x0, [x21, #SECONDARY_DATA_STACK]	// get secondary_data.stack
	mov	sp, x0
	
	/*
	 * Conditionally switch to GIC PMR for interrupt masking (this
	 * will be a nop if we are using normal interrupt masking)
	 */
	bl	maybe_switch_to_sysreg_gic_cpuif
	mov	x29, #0

	adr	x1, secondary_data
	ldr	x0, [x1, #SECONDARY_DATA_ARG]		// get secondary_data.arg
	ldr	x27, [x1, #SECONDARY_DATA_NEXT_PC]	// get secondary_data.next_pc
	br	x27					// secondary_data.next_pc(secondary_data.arg);
ENDPROC(__secondary_switched)

/*
 * Setup common bits before finally enabling the MMU. Essentially this is just
 * loading the page table pointer and vector base registers.
 *
 * On entry to this code, x0 must contain the SCTLR_EL1 value for turning on
 * the MMU.
 */
__enable_mmu:
	ldr	x5, =vectors
	msr	vbar_el1, x5
	msr	ttbr0_el1, x25			// load TTBR0
	msr	ttbr1_el1, x26			// load TTBR1
	isb
	b	__turn_mmu_on
ENDPROC(__enable_mmu)

/*
 * Enable the MMU. This completely changes the structure of the visible memory
 * space. You will not be able to trace execution through this.
 *
 *  x0  = system control register
 *  x27 = *virtual* address to jump to upon completion
 *
 * other registers depend on the function called upon completion
 *
 * We align the entire function to the smallest power of two larger than it to
 * ensure it fits within a single block map entry. Otherwise were PHYS_OFFSET
 * close to the end of a 512MB or 1GB block we might require an additional
 * table to map the entire function.
 */
	.align	4
__turn_mmu_on:
	msr	sctlr_el1, x0
	isb
	br	x27
ENDPROC(__turn_mmu_on)

/*
 * Calculate the start of physical memory.
 */
__calc_phys_offset:
	adr	x0, 1f
	ldp	x1, x2, [x0]
	sub	x28, x0, x1		// x28 = PHYS_OFFSET - KERNEL_START
	add	x24, x2, x28		// x24 = PHYS_OFFSET
	ret
ENDPROC(__calc_phys_offset)

	.align 3
1:	.quad	.
	.quad	KERNEL_START

/*
 * Exception handling. Something went wrong and we can't proceed. We ought to
 * tell the user, but since we don't have any guarantee that we're even
 * running on the right architecture, we do virtually nothing.
 */
__error_p:
ENDPROC(__error_p)

__error:
1:	nop
	b	1b
ENDPROC(__error)

/*
 * This function gets the processor ID in w0 and searches the cpu_table[] for
 * a match. It returns a pointer to the struct cpu_info it found. The
 * cpu_table[] must end with an empty (all zeros) structure.
 *
 * This routine can be called via C code and it needs to work with the MMU
 * both disabled and enabled (the offset is calculated automatically).
 */
ENTRY(lookup_processor_type)
	adr	x1, __lookup_processor_type_data
	ldp	x2, x3, [x1]
	sub	x1, x1, x2			// get offset between VA and PA
	add	x3, x3, x1			// convert VA to PA
1:
	ldp	w5, w6, [x3]			// load cpu_id_val and cpu_id_mask
	cbz	w5, 2f				// end of list?
	and	w6, w6, w0
	cmp	w5, w6
	b.eq	3f
	add	x3, x3, #CPU_INFO_SZ
	b	1b
2:
	mov	x3, #0				// unknown processor
3:
	mov	x0, x3
	ret
ENDPROC(lookup_processor_type)

	.align	3
	.type	__lookup_processor_type_data, %object
__lookup_processor_type_data:
	.quad	.
	.quad	cpu_table
	.size	__lookup_processor_type_data, . - __lookup_processor_type_data

