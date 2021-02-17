/* cpu.c COPYRIGHT FUJITSU LIMITED 2018-2019 */
/**
 * \file cpu.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Control CPU. 
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY
 *  2015/02/26: bgerofi - set pstate, turbo mode and power/perf bias MSRs
 *  2015/02/12: Dave - enable AVX if supported
 */

#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <types.h>
#include <errno.h>
#include <list.h>
#include <memory.h>
#include <string.h>
#include <registers.h>
#include <cpulocal.h>
#include <march.h>
#include <signal.h>
#include <process.h>
#include <cls.h>
#include <prctl.h>
#include <page.h>
#include <kmalloc.h>
#include <ihk/debug.h>

#define LAPIC_ID            0x020
#define LAPIC_TIMER         0x320
#define LAPIC_LVTPC         0x340
#define LAPIC_TIMER_INITIAL 0x380
#define LAPIC_TIMER_CURRENT 0x390
#define LAPIC_TIMER_DIVIDE  0x3e0
#define LAPIC_SPURIOUS      0x0f0
#define LAPIC_EOI           0x0b0
#define LAPIC_ICR0          0x300
#define LAPIC_ICR2          0x310
#define LAPIC_ESR           0x280
#define LOCAL_TIMER_VECTOR  0xef
#define LOCAL_PERF_VECTOR   0xf0
#define LOCAL_SMP_FUNC_CALL_VECTOR   0xf1

#define APIC_INT_LEVELTRIG      0x08000
#define APIC_INT_ASSERT         0x04000
#define APIC_ICR_BUSY           0x01000
#define APIC_DEST_PHYSICAL      0x00000
#define APIC_DM_FIXED           0x00000
#define APIC_DM_NMI             0x00400
#define APIC_DM_INIT            0x00500
#define APIC_DM_STARTUP         0x00600
#define APIC_DIVISOR            16
#define APIC_LVT_TIMER_PERIODIC (1 << 17)

#define APIC_BASE_MSR		0x800
#define IA32_X2APIC_APICID	0x802
#define IA32_X2APIC_ICR		0x830
#define X2APIC_ENABLE		(1UL << 10)
#define NMI_VECTOR		0x02

//#define DEBUG_PRINT_CPU

#ifdef DEBUG_PRINT_CPU
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

static void *lapic_vp;
static int x2apic;
static void (*lapic_write)(int reg, unsigned int value);
static unsigned int (*lapic_read)(int reg);
static void (*lapic_icr_write)(unsigned int h, unsigned int l);
static void (*lapic_wait_icr_idle)(void);
void (*x86_issue_ipi)(unsigned int apicid, unsigned int low);
int running_on_kvm(void);
void smp_func_call_handler(void);
int ihk_mc_get_smp_handler_irq(void)
{
	return LOCAL_SMP_FUNC_CALL_VECTOR;
}

void init_processors_local(int max_id);
void assign_processor_id(void);
void arch_delay(int);
void x86_set_warm_reset(unsigned long ip, char *first_page_va);
void x86_init_perfctr(void);
int gettime_local_support = 0;

extern int kprintf(const char *format, ...);
extern int interrupt_from_user(void *);
extern void perf_start(struct mc_perf_event *event);
extern void perf_reset(struct mc_perf_event *event);

static struct idt_entry{
	uint32_t desc[4];
} idt[256] __attribute__((aligned(16)));

static struct x86_desc_ptr idt_desc, gdt_desc;

static uint64_t gdt[] __attribute__((aligned(16))) = {
	0,                  /* 0 */
	0,                  /* 8 */
	0,                  /* 16 */
	0,                  /* 24 */
	0x00af9b000000ffff, /* 32 : KERNEL_CS */
	0x00cf93000000ffff, /* 40 : KERNEL_DS */
	0x00affb000000ffff, /* 48 : USER_CS */
	0x00aff3000000ffff, /* 56 : USER_DS */
	0x0000890000000067, /* 64 : TSS */
	0,                  /* (72: TSS) */
	0,                  /* 80 */
	0,                  /* 88 */
	0,                  /* 96 */
	0,                  /* 104 */
	0,                  /* 112 */
	0x0000f10000000000, /* 120 : GETCPU */
};

struct tss64 tss __attribute__((aligned(16)));

static void set_idt_entry(int idx, unsigned long addr)
{
	idt[idx].desc[0] = (addr & 0xffff) | (KERNEL_CS << 16);
	idt[idx].desc[1] = (addr & 0xffff0000) | 0x8e00;
	idt[idx].desc[2] = (addr >> 32);
	idt[idx].desc[3] = 0;
}

static void set_idt_entry_trap_gate(int idx, unsigned long addr)
{
	idt[idx].desc[0] = (addr & 0xffff) | (KERNEL_CS << 16);
	idt[idx].desc[1] = (addr & 0xffff0000) | 0xef00;
	idt[idx].desc[2] = (addr >> 32);
	idt[idx].desc[3] = 0;
}

extern uint64_t generic_common_handlers[];

void reload_idt(void)
{
	asm volatile("lidt %0" : : "m"(idt_desc) : "memory");
}

static struct list_head handlers[256 - 32];
extern char nmi_handler[];
extern char page_fault[], general_protection_exception[];
extern char debug_exception[], int3_exception[];

uint64_t boot_pat_state = 0;
int no_turbo = 1; /* May be updated by early parsing of kargs */

extern int num_processors; /* kernel/ap.c */
struct pvclock_vsyscall_time_info *pvti = NULL;
int pvti_npages;
static long pvti_msr = -1;


static void init_idt(void)
{
	int i;

	idt_desc.size = sizeof(idt) - 1;
	idt_desc.address = (unsigned long)idt;
        
	for (i = 0; i < 256; i++) {
		if (i >= 32) {
			INIT_LIST_HEAD(&handlers[i - 32]);
		}
		set_idt_entry(i, generic_common_handlers[i]);
	}

	set_idt_entry(2, (uintptr_t)nmi_handler);
	set_idt_entry(13, (unsigned long)general_protection_exception);
	set_idt_entry(14, (unsigned long)page_fault);

	set_idt_entry_trap_gate(1, (unsigned long)debug_exception);
	set_idt_entry_trap_gate(3, (unsigned long)int3_exception);

	reload_idt();
}

static int xsave_available = 0;
static int xsave_size = 0;
static uint64_t xsave_mask = 0x0;

void init_fpu(void)
{
	unsigned long reg;
	unsigned long cpuid01_ecx;

	asm volatile("movq %%cr0, %0" : "=r"(reg));
	/* Unset EM and TS flag. */
	reg &= ~((1 << 2) | (1 << 3));
	/* Set MP flag */
	reg |= 1 << 1;
	asm volatile("movq %0, %%cr0" : : "r"(reg));

#ifdef ENABLE_SSE
	asm volatile("cpuid" : "=c" (cpuid01_ecx) : "a" (0x1) : "%rbx", "%rdx");
	asm volatile("movq %%cr4, %0" : "=r"(reg));
	/* Cr4 flags: 
	   OSFXSR[b9] - enables SSE instructions
	   OSXMMEXCPT[b10] - generate SIMD FP exception instead of invalid op
	   OSXSAVE[b18] - enables access to xcr0

	   CPUID.01H:ECX flags:
	   XSAVE[b26] - verify existence of extended crs/XSAVE
	   AVX[b28] - verify existence of AVX instructions
	*/
	reg |= ((1 << 9) | (1 << 10));
	if(cpuid01_ecx & (1 << 26)) {
		/* XSAVE set, enable access to xcr0 */
		dkprintf("init_fpu(): XSAVE available\n");
		xsave_available = 1;
		reg |= (1 << 18);
	}
	asm volatile("movq %0, %%cr4" : : "r"(reg));

	dkprintf("init_fpu(): SSE init: CR4 = 0x%016lX\n", reg);

	/* Set xcr0[2:1] to enable avx ops */
	if(xsave_available){
		unsigned long eax;
		unsigned long ebx;
		unsigned long ecx;
		unsigned long edx;
		asm volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx) : "a" (0x0d), "c" (0x00));
		xsave_size = ecx;
		dkprintf("init_fpu(): xsave_size = %d\n", xsave_size);

		if ((eax & (1 << 5)) && (eax & (1 << 6)) && (eax & (1 << 7))) {
			/* Set xcr0[7:5] to enable avx-512 ops */
			reg = xgetbv(0);
			reg |= 0xe6;
			xsetbv(0, reg);
			dkprintf("init_fpu(): AVX-512 init: XCR0 = 0x%016lX\n", reg);
		} else {
			reg = xgetbv(0);
			reg |= 0x6;
			xsetbv(0, reg);
			dkprintf("init_fpu(): AVX init: XCR0 = 0x%016lX\n", reg);
		}

		xsave_mask = xgetbv(0);
		dkprintf("init_fpu(): xsave_mask = 0x%016lX\n", xsave_mask);
	}

	/* TODO: set MSR_IA32_XSS to enable xsaves/xrstors */

#else
	kprintf("init_fpu(): SSE not enabled\n");
#endif

	asm volatile("finit");
}

int
get_xsave_size()
{
	return xsave_size;
}

uint64_t get_xsave_mask()
{
	return xsave_mask;
}

void reload_gdt(struct x86_desc_ptr *gdt_ptr)
{
	asm volatile("pushq %1\n"
	             "leaq 1f(%%rip), %%rbx\n"
	             "pushq %%rbx\n"
	             "lgdt %0\n"
	             "lretq\n"
	             "1:\n" : :
	             "m" (*gdt_ptr),
	             "i" (KERNEL_CS) : "rbx");
	asm volatile("movl %0, %%ds" : : "r"(KERNEL_DS));
	asm volatile("movl %0, %%ss" : : "r"(KERNEL_DS));
	/* And, set TSS */
	asm volatile("ltr %0" : : "r"((short)GLOBAL_TSS) : "memory");
}

void init_gdt(void)
{
	register unsigned long stack_pointer asm("rsp");
	unsigned long tss_addr = (unsigned long)&tss;

	memset(&tss, 0, sizeof(tss));
	tss.rsp0 = stack_pointer;
        
	/* 0x89 = Present (8) | Type = 9 (TSS) */
	gdt[GLOBAL_TSS_ENTRY] = (sizeof(tss) - 1) 
		| ((tss_addr & 0xffffff) << 16)
		| (0x89UL << 40) | ((tss_addr & 0xff000000) << 32);
	gdt[GLOBAL_TSS_ENTRY + 1] = (tss_addr >> 32);

	gdt_desc.size = sizeof(gdt) - 1;
	gdt_desc.address = (unsigned long)gdt;
        
	/* Load the new GDT, and set up CS, DS and SS. */
	reload_gdt(&gdt_desc);
}

static void
apic_write(int reg, unsigned int value)
{
	*(volatile unsigned int *)((char *)lapic_vp + reg) = value;
}

static void
x2apic_write(int reg, unsigned int value)
{
	reg >>= 4;
	reg |= APIC_BASE_MSR;
	wrmsr(reg, value);
}

static unsigned int
apic_read(int reg)
{
	return *(volatile unsigned int *)((char *)lapic_vp + reg);
}

static unsigned int
x2apic_read(int reg)
{
	unsigned long value;

	reg >>= 4;
	reg |= APIC_BASE_MSR;
	value = rdmsr(reg);
	return (int)value;
}

void
lapic_timer_enable(unsigned int clocks)
{
	unsigned int lvtt_value;

	lapic_write(LAPIC_TIMER_INITIAL, clocks / APIC_DIVISOR);
	lapic_write(LAPIC_TIMER_DIVIDE, 3);

	/* initialize periodic timer */
	lvtt_value = LOCAL_TIMER_VECTOR | APIC_LVT_TIMER_PERIODIC;
	lapic_write(LAPIC_TIMER, lvtt_value);
}

void
lapic_timer_disable()
{
	lapic_write(LAPIC_TIMER_INITIAL, 0);
}

void
lapic_ack(void)
{
	lapic_write(LAPIC_EOI, 0);
}

static void
x2apic_wait_icr_idle(void)
{
}

static void
apic_wait_icr_idle(void)
{
	while (lapic_read(LAPIC_ICR0) & APIC_ICR_BUSY) {
		cpu_pause();
	}
}

static void
x2apic_icr_write(unsigned int low, unsigned int apicid)
{
	wrmsr(IA32_X2APIC_ICR, (((unsigned long)apicid) << 32) | low);
}

static void
apic_icr_write(unsigned int h, unsigned int l)
{
	lapic_write(LAPIC_ICR2, (unsigned int)h);
	lapic_write(LAPIC_ICR0, l);
}

static void
x2apic_x86_issue_ipi(unsigned int apicid, unsigned int low)
{
	unsigned long icr = low;
	unsigned long flags;

	ihk_mc_mb();
	flags = cpu_disable_interrupt_save();
	x2apic_icr_write(icr, apicid);
	cpu_restore_interrupt(flags);
}

static void
apic_x86_issue_ipi(unsigned int apicid, unsigned int low)
{
	unsigned long flags;

	flags = cpu_disable_interrupt_save();
	apic_wait_icr_idle();
	apic_icr_write(apicid << LAPIC_ICR_ID_SHIFT, low);
	cpu_restore_interrupt(flags);
}

unsigned long
x2apic_is_enabled()
{
	unsigned long msr;

	msr = rdmsr(MSR_IA32_APIC_BASE);

	return (msr & X2APIC_ENABLE);
}

void init_lapic_bsp(void)
{
	if(x2apic_is_enabled()){
		x2apic = 1;
		lapic_write = x2apic_write;
		lapic_read = x2apic_read;
		lapic_icr_write = x2apic_icr_write;
		lapic_wait_icr_idle = x2apic_wait_icr_idle;
		x86_issue_ipi = x2apic_x86_issue_ipi;
	}
	else{
		x2apic = 0;
		lapic_write = apic_write;
		lapic_read = apic_read;
		lapic_icr_write = apic_icr_write;
		lapic_wait_icr_idle = apic_wait_icr_idle;
		x86_issue_ipi = apic_x86_issue_ipi;

	}
}

void
init_lapic()
{
	if(!x2apic){
		unsigned long baseaddr;

		/* Enable Local APIC */
		baseaddr = rdmsr(MSR_IA32_APIC_BASE);
		if (!lapic_vp) {
			lapic_vp = map_fixed_area(baseaddr & PAGE_MASK, PAGE_SIZE, 1);
		}
		baseaddr |= 0x800;
		wrmsr(MSR_IA32_APIC_BASE, baseaddr);
	}

	lapic_write(LAPIC_SPURIOUS, 0x1ff);
	lapic_write(LAPIC_LVTPC, LOCAL_PERF_VECTOR);
}

void print_msr(int idx)
{
	int bit;
	unsigned long long val;

	val = rdmsr(idx);

	__kprintf("MSR 0x%x val (dec): %llu\n", idx, val);
	__kprintf("MSR 0x%x val (hex): 0x%llx\n", idx, val);

	__kprintf("                    ");
	for (bit = 63; bit >= 0; --bit) {
		__kprintf("%3d", bit);
	}
	__kprintf("\n");

	__kprintf("MSR 0x%x val (bin):", idx);
	for (bit = 63; bit >= 0; --bit) {
		__kprintf("%3d", (val & ((unsigned long)1 << bit)) ? 1 : 0);
	}
	__kprintf("\n");
}


void init_pstate_and_turbo(void)
{
	uint64_t value;
	uint64_t eax, ecx;

	if (running_on_kvm()) return;

	asm volatile("cpuid" : "=a" (eax), "=c" (ecx) : "a" (0x6) : "%rbx", "%rdx");
	if (!(ecx & 0x01)) {
		/* P-states and/or Turbo Boost are not supported. */
		return;
	}

	/* Query and set max pstate value: 
	 *
	 * IA32_PERF_CTL (0x199H) bit 15:0:
	 * Target performance State Value
	 *
	 * The base operating ratio can be read 
	 * from MSR_PLATFORM_INFO[15:8].
	 */
	value = rdmsr(MSR_PLATFORM_INFO);
	value &= 0xFF00;

	/* Turbo boost setting:
	 * Bit 1 of EAX in Leaf 06H (i.e. CPUID.06H:EAX[1]) indicates opportunistic 
	 * processor performance operation, such as IDA, has been enabled by BIOS.
	 *
	 * IA32_PERF_CTL (0x199H) bit 32: IDA (i.e., turbo boost) Engage. (R/W)
	 * When set to 1: disengages IDA
	 * When set to 0: enables IDA
	 */
	if ((eax & (1 << 1))) {
		if (!no_turbo) {
			uint64_t turbo_value;

			turbo_value = rdmsr(MSR_NHM_TURBO_RATIO_LIMIT);
			turbo_value &= 0xFF;
			value = turbo_value << 8;

			/* Enable turbo boost */
			value &= ~((uint64_t)1 << 32);
		}
		/* Turbo boost feature is supported, but requested to be turned off */
		else {
			/* Disable turbo boost */
			value |= (uint64_t)1 << 32; 
		}
	}

	wrmsr(MSR_IA32_PERF_CTL, value);

	/* IA32_ENERGY_PERF_BIAS (0x1B0H) bit 3:0:
	 * (The processor supports this capability if CPUID.06H:ECX.SETBH[bit 3] is set.)
	 * Power Policy Preference:
	 * 0 indicates preference to highest performance.
	 * 15 indicates preference to maximize energy saving.
	 *
	 * Set energy/perf bias to high performance 
	 */ 
	if (ecx & (1 << 3)) {
		wrmsr(MSR_IA32_ENERGY_PERF_BIAS, 0);
	}
	
	//print_msr(MSR_IA32_MISC_ENABLE);
	//print_msr(MSR_IA32_PERF_CTL);
	//print_msr(MSR_IA32_ENERGY_PERF_BIAS);
}

enum {
	PAT_UC = 0,		/* uncached */
	PAT_WC = 1,		/* Write combining */
	PAT_WT = 4,		/* Write Through */
	PAT_WP = 5,		/* Write Protected */
	PAT_WB = 6,		/* Write Back (default) */
	PAT_UC_MINUS = 7,	/* UC, but can be overriden by MTRR */
};

#define PAT(x, y)	((uint64_t)PAT_ ## y << ((x)*8))

void init_pat(void)
{
	uint64_t pat;
	uint64_t edx;

	/*
	 * An operating system or executive can detect the availability of the 
	 * PAT by executing the CPUID instruction with a value of 1 in the EAX 
	 * register. Support for the PAT is indicated by the PAT flag (bit 16 
	 * of the values returned to EDX register). If the PAT is supported, 
	 * the operating system or executive can use the IA32_PAT MSR to program 
	 * the PAT. When memory types have been assigned to entries in the PAT, 
	 * software can then use of the PAT-index bit (PAT) in the page-table and 
	 * page-directory entries along with the PCD and PWT bits to assign memory 
	 * types from the PAT to individual pages.
	 */

	asm volatile("cpuid" : "=d" (edx) : "a" (0x1) : "%rbx", "%rcx");
	if (!(edx & ((uint64_t)1 << 16))) {
		kprintf("PAT not supported.\n");
		return;	
	}
	
	/* Set PWT to Write-Combining. All other bits stay the same */
	/* (Based on Linux' settings)
	 *
	 * PTE encoding used in Linux:
	 *      PAT
	 *      |PCD
	 *      ||PWT
	 *      |||
	 *      000 WB		_PAGE_CACHE_WB
	 *      001 WC		_PAGE_CACHE_WC
	 *      010 UC-		_PAGE_CACHE_UC_MINUS
	 *      011 UC		_PAGE_CACHE_UC
	 * PAT bit unused
	 */
	pat = PAT(0, WB) | PAT(1, WC) | PAT(2, UC_MINUS) | PAT(3, UC) |
	      PAT(4, WB) | PAT(5, WC) | PAT(6, UC_MINUS) | PAT(7, UC);

	/* Boot CPU check */
	if (!boot_pat_state)
		boot_pat_state = rdmsr(MSR_IA32_CR_PAT);

	wrmsr(MSR_IA32_CR_PAT, pat);
	dkprintf("PAT support detected and reconfigured.\n");
}

static void set_kstack(unsigned long ptr)
{
	struct x86_cpu_local_variables *v;

	v = get_x86_this_cpu_local();
	v->kernel_stack = ptr;
	v->tss.rsp0 = ptr;
}

static void init_smp_processor(void)
{
	struct x86_cpu_local_variables *v;
	unsigned long tss_addr;
	unsigned node_cpu;

	v = get_x86_this_cpu_local();
	tss_addr = (unsigned long)&v->tss;

	if(x2apic_is_enabled()){
		v->apic_id = rdmsr(IA32_X2APIC_APICID);
	}
	else{
		v->apic_id = lapic_read(LAPIC_ID) >> LAPIC_ID_SHIFT;
	}

	memcpy(v->gdt, gdt, sizeof(v->gdt));
	
	memset(&v->tss, 0, sizeof(v->tss));

	v->gdt[GLOBAL_TSS_ENTRY] = (sizeof(v->tss) - 1) 
		| ((tss_addr & 0xffffff) << 16)
		| (0x89UL << 40) | ((tss_addr & 0xff000000) << 32);
	v->gdt[GLOBAL_TSS_ENTRY + 1] = (tss_addr >> 32);

	node_cpu = v->processor_id;	/* assumes NUMA node 0 */
	v->gdt[GETCPU_ENTRY] |= node_cpu;

	v->gdt_ptr.size = sizeof(v->gdt) - 1;
	v->gdt_ptr.address = (unsigned long)v->gdt;
        
	/* Load the new GDT, and set up CS, DS and SS. */
	reload_gdt(&v->gdt_ptr);

	set_kstack((unsigned long)get_x86_this_cpu_kstack());

	/* MSR_IA32_TSC_AUX on KVM seems broken */
	if (running_on_kvm()) return;
#define MSR_IA32_TSC_AUX 0xc0000103
	wrmsr(MSR_IA32_TSC_AUX, node_cpu);
}

static char *trampoline_va, *first_page_va;

/*@
  @ assigns torampoline_va;
  @ assigns first_page_va;
  @*/
void ihk_mc_init_ap(void)
{
	struct ihk_mc_cpu_info *cpu_info = ihk_mc_get_cpu_info();

	trampoline_va = map_fixed_area(ap_trampoline, AP_TRAMPOLINE_SIZE, 0);
	kprintf("Trampoline area: 0x%lx \n", ap_trampoline);
	first_page_va = map_fixed_area(0, PAGE_SIZE, 0);

	kprintf("# of cpus : %d\n", cpu_info->ncpus);
	init_processors_local(cpu_info->ncpus);
	
	/* Do initialization for THIS cpu (BSP) */
	assign_processor_id();

	init_smp_processor();
}

extern void init_page_table(void);

extern char x86_syscall[];
long (*__x86_syscall_handler)(int, ihk_mc_user_context_t *);

void init_syscall(void)
{
	unsigned long r;

	r = rdmsr(MSR_EFER);
	r |= 1; /* SYSCALL Enable */
	wrmsr(MSR_EFER, r);

	r = (((unsigned long)KERNEL_CS) << 32) 
		| (((unsigned long)USER_CS) << 48);
	wrmsr(MSR_STAR, r);
	
	wrmsr(MSR_LSTAR, (unsigned long)x86_syscall);
}

static void enable_page_protection_fault(void)
{
	asm volatile (
			"pushf	;"
			"cli	;"
			"mov	%%cr0,%%rax;"
			"or	$0x10000,%%rax;"
			"mov	%%rax,%%cr0;"
			"popf"
			::: "%rax");
	return;
}

static int no_execute_available = 0;

static void enable_no_execute(void)
{
	unsigned long efer;

	if (!no_execute_available) {
		return;
	}

	efer = rdmsr(MSR_EFER);
#define	IA32_EFER_NXE	(1UL << 11)
	efer |= IA32_EFER_NXE;
	wrmsr(MSR_EFER, efer);

	return;
}

static void check_no_execute(void)
{
	uint32_t edx;
	extern void enable_ptattr_no_execute(void);

	/* check Execute Disable Bit available bit */
	asm ("cpuid" : "=d" (edx) : "a" (0x80000001) : "%rbx", "%rcx");
	no_execute_available = (edx & (1 << 20))? 1: 0;
	kprintf("no_execute_available: %d\n", no_execute_available);

	if (no_execute_available) {
		enable_ptattr_no_execute();
	}

	return;
}

void init_gettime_support(void)
{
	uint64_t op;
	uint64_t eax;
	uint64_t ebx;
	uint64_t ecx;
	uint64_t edx;

	/* Check if Invariant TSC supported.
	 * Processor's support for invariant TSC is indicated by
	 * CPUID.80000007H:EDX[8].
	 * See page 2498 of the Intel64 and IA-32 Architectures Software
	 * Developer's Manual - combined */

	op = 0x80000007;
	asm volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx) : "a" (op));

	if (edx & (1 << 8)) {
		gettime_local_support = 1;
		kprintf("Invariant TSC supported.\n");
	}
}

void init_cpu(void)
{
	enable_page_protection_fault();
	enable_no_execute();
	init_fpu();
	init_lapic();
	init_syscall();
	x86_init_perfctr();
	init_pstate_and_turbo();
	init_pat();
}

void setup_x86_phase1(void)
{
	cpu_disable_interrupt();

	init_idt();

	init_gdt();

	init_page_table();
}

void setup_x86_phase2(void)
{
	check_no_execute();

	init_lapic_bsp();

	init_cpu();

	init_gettime_support();

	kprintf("setup_x86 done.\n");
}

static volatile int cpu_boot_status;

void call_ap_func(void (*next_func)(void))
{
	cpu_boot_status = 1;
	next_func();
}

struct page_table *get_init_page_table(void);
void setup_x86_ap(void (*next_func)(void))
{
	unsigned long rsp;
	cpu_disable_interrupt();

	ihk_mc_load_page_table(get_init_page_table());

	assign_processor_id();

	init_smp_processor();

	reload_idt();

	init_cpu();

	rsp = (unsigned long)get_x86_this_cpu_kstack();

	asm volatile("movq %0, %%rdi\n"
	             "movq %1, %%rsp\n"
	             "call *%2" : : "r"(next_func), "r"(rsp), "r"(call_ap_func)
	             : "rdi");
	while(1);
}

void arch_show_interrupt_context(const void *reg);
extern void tlb_flush_handler(int vector);

void __show_stack(uintptr_t *sp) {
	while (((uintptr_t)sp >= 0xffff800000000000)
			&& ((uintptr_t)sp <  0xffffffff80000000)) {
		uintptr_t fp;
		uintptr_t ip;

		fp = sp[0];
		ip = sp[1];
		kprintf("IP: %016lx, SP: %016lx, FP: %016lx\n", ip, (uintptr_t)sp, fp);
		sp = (void *)fp;
	}
	return;
}

void show_context_stack(uintptr_t *rbp) {
	__show_stack(rbp);
	return;
}

#ifdef ENABLE_FUGAKU_HACKS
void __show_context_stack(struct thread *thread,
        unsigned long pc, uintptr_t sp, int kprintf_locked)
{
    uintptr_t stack_top;
    unsigned long irqflags = 0;

    stack_top = ALIGN_UP(sp, (uintptr_t)KERNEL_STACK_SIZE);

    if (!kprintf_locked)
        irqflags = kprintf_lock();

    __kprintf("TID: %d, call stack (most recent first):\n",
        thread->tid);
    __kprintf("PC: %016lx, SP: %016lx\n", pc, sp);
    for (;;) {
        extern char _head[], _end[];
        uintptr_t *fp, *lr;
        fp = (uintptr_t *)sp;
        lr = (uintptr_t *)(sp + 8);

        if ((*fp <= sp)) {
            break;
        }

        if ((*fp > stack_top)) {
            break;
        }

        if ((*lr < (unsigned long)_head) ||
            (*lr > (unsigned long)_end)) {
            break;
        }

        __kprintf("PC: %016lx, SP: %016lx, FP: %016lx\n", *lr - 4, sp, *fp);
        sp = *fp;
    }

    if (!kprintf_locked)
        kprintf_unlock(irqflags);
}
#endif

void interrupt_exit(struct x86_user_context *regs)
{
	if (interrupt_from_user(regs)) {
		cpu_enable_interrupt();
		check_sig_pending();
		check_need_resched();
		check_signal(0, regs, -1);
	}
	else {
		check_sig_pending();
	}
}

void handle_interrupt(int vector, struct x86_user_context *regs)
{
	struct ihk_mc_interrupt_handler *h;
	struct cpu_local_var *v = get_this_cpu_local_var();

	lapic_ack();
	++v->in_interrupt;

	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);

	dkprintf("CPU[%d] got interrupt, vector: %d, RIP: 0x%lX\n", 
	         ihk_mc_get_processor_id(), vector, regs->gpr.rip);

	if (vector < 0 || vector > 255) {
		panic("Invalid interrupt vector.");
	} 
	else if (vector < 32) {
		struct siginfo info;
		switch(vector){
		    case 0:
			memset(&info, '\0', sizeof info);
			info.si_signo = SIGFPE;
			info.si_code = FPE_INTDIV;
			info._sifields._sigfault.si_addr = (void *)regs->gpr.rip;
			set_signal(SIGFPE, regs, &info);
			break;
		    case 9:
		    case 16:
		    case 19:
			set_signal(SIGFPE, regs, NULL);
			break;
		    case 4:
		    case 5:
			set_signal(SIGSEGV, regs, NULL);
			break;
		    case 6:
			memset(&info, '\0', sizeof info);
			info.si_signo = SIGILL;
			info.si_code = ILL_ILLOPN;
			info._sifields._sigfault.si_addr = (void *)regs->gpr.rip;
			set_signal(SIGILL, regs, &info);
			break;
		    case 10:
			set_signal(SIGSEGV, regs, NULL);
			break;
		    case 11:
		    case 12:
			set_signal(SIGBUS, regs, NULL);
			break;
		    case 17:
			memset(&info, '\0', sizeof info);
			info.si_signo = SIGBUS;
			info.si_code = BUS_ADRALN;
			set_signal(SIGBUS, regs, &info);
			break;
		    default:
			kprintf("Exception %d, rflags: 0x%lX CS: 0x%lX, RIP: 0x%lX\n",
			        vector, regs->gpr.rflags, regs->gpr.cs, regs->gpr.rip);
			arch_show_interrupt_context(regs);
			panic("Unhandled exception");
		}
	}
	else if (vector == LOCAL_TIMER_VECTOR) {
		unsigned long irqstate;
		/* Timer interrupt, enabled only on oversubscribed CPU cores,
		 * request reschedule */
		irqstate = ihk_mc_spinlock_lock(&v->runq_lock);
		v->flags |= CPU_FLAG_NEED_RESCHED;
		ihk_mc_spinlock_unlock(&v->runq_lock, irqstate);
		dkprintf("timer[%lu]: CPU_FLAG_NEED_RESCHED \n", rdtsc());

		do_backlog();
	}
	else if (vector == LOCAL_PERF_VECTOR) {
		struct siginfo info;
		unsigned long value;
		struct thread *thread = cpu_local_var(current);
        	struct process *proc = thread->proc;
		long irqstate;
		struct mckfd *fdp;

		lapic_write(LAPIC_LVTPC, LOCAL_PERF_VECTOR);

		value = rdmsr(MSR_PERF_GLOBAL_STATUS);
		wrmsr(MSR_PERF_GLOBAL_OVF_CTRL, value);
		wrmsr(MSR_PERF_GLOBAL_OVF_CTRL, 0);

		irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
	        for(fdp = proc->mckfd; fdp; fdp = fdp->next) {
			if(fdp->sig_no > 0)
                	        break;
		}
	        ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);

		if(fdp) {
			memset(&info, '\0', sizeof info);
			info.si_signo = fdp->sig_no;
			info._sifields._sigfault.si_addr = (void *)regs->gpr.rip;
			info._sifields._sigpoll.si_fd = fdp->fd;
			set_signal(fdp->sig_no, regs, &info); 
		}
		else {
			set_signal(SIGIO, regs, NULL);
		}
	}
	else if (vector >= IHK_TLB_FLUSH_IRQ_VECTOR_START && 
	         vector < IHK_TLB_FLUSH_IRQ_VECTOR_END) {

			tlb_flush_handler(vector);
	} 
	else if (vector == LOCAL_SMP_FUNC_CALL_VECTOR) {
		smp_func_call_handler();
	}
	else if (vector == 133) {
		show_context_stack((uintptr_t *)regs->gpr.rbp);
	}
	else {
		list_for_each_entry(h, &handlers[vector - 32], list) {
			if (h->func) {
				h->func(h->priv);
			}
		}
	}

	interrupt_exit(regs);
	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);

	--v->in_interrupt;

	/* for migration by IPI */
	if (v->flags & CPU_FLAG_NEED_MIGRATE) {
		schedule();
		check_signal(0, regs, 0);
	}
}

void gpe_handler(struct x86_user_context *regs)
{
	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);
	kprintf("General protection fault (err: %lx, %lx:%lx)\n",
	        regs->gpr.error, regs->gpr.cs, regs->gpr.rip);
	arch_show_interrupt_context(regs);
	if ((regs->gpr.cs & 3) == 0) {
		panic("gpe_handler");
	}
	set_signal(SIGSEGV, regs, NULL);
	interrupt_exit(regs);
	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);
	panic("GPF");
}

void debug_handler(struct x86_user_context *regs)
{
	unsigned long db6;
	int si_code = 0;
	struct siginfo info;

	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);
#ifdef DEBUG_PRINT_CPU
	kprintf("debug exception (err: %lx, %lx:%lx)\n",
	        regs->gpr.error, regs->gpr.cs, regs->gpr.rip);
	arch_show_interrupt_context(regs);
#endif

	asm("mov %%db6, %0" :"=r" (db6));
	if (db6 & DB6_BS) {
	        regs->gpr.rflags &= ~RFLAGS_TF;
		si_code = TRAP_TRACE;
	} else if (db6 & (DB6_B3|DB6_B2|DB6_B1|DB6_B0)) {
		si_code = TRAP_HWBKPT;
	}

	memset(&info, '\0', sizeof info);
	info.si_code = si_code;
	set_signal(SIGTRAP, regs, &info);
	interrupt_exit(regs);
	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);
}

void int3_handler(struct x86_user_context *regs)
{
	struct siginfo info;

	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);
#ifdef DEBUG_PRINT_CPU
	kprintf("int3 exception (err: %lx, %lx:%lx)\n",
	        regs->gpr.error, regs->gpr.cs, regs->gpr.rip);
	arch_show_interrupt_context(regs);
#endif

	memset(&info, '\0', sizeof info);
	info.si_code = TRAP_BRKPT;
	set_signal(SIGTRAP, regs, &info);
	interrupt_exit(regs);
	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);
}

static void outb(uint8_t v, uint16_t port)
{
	asm volatile("outb %0, %1" : : "a" (v), "d" (port));
}

static void set_warm_reset_vector(unsigned long ip)
{
	x86_set_warm_reset(ip, first_page_va);
}

static void __x86_wakeup(int apicid, unsigned long ip)
{
	int retry = 3;

	set_warm_reset_vector(ip);

	/* Clear the error */
	lapic_write(LAPIC_ESR, 0);
	lapic_read(LAPIC_ESR);

	/* INIT */
	x86_issue_ipi(apicid, 
	              APIC_INT_LEVELTRIG | APIC_INT_ASSERT | APIC_DM_INIT);

	x86_issue_ipi(apicid, 
	              APIC_INT_LEVELTRIG | APIC_DM_INIT);
	lapic_wait_icr_idle();

	while (retry--) {
		lapic_read(LAPIC_ESR);
		x86_issue_ipi(apicid, APIC_DM_STARTUP | (ip >> 12));
		lapic_wait_icr_idle();

		arch_delay(200);

		if (cpu_boot_status) 
			break;
	}
}

/** IHK Functions **/

/*@
  @ assigns \nothing;
  @ ensures \interrupt_disabled == 0;
  @*/
void cpu_halt(void)
{
	asm volatile("hlt");
}

#ifdef ENABLE_FUGAKU_HACKS
/*@
  @ assigns \nothing;
  @ ensures \interrupt_disabled == 0;
  @*/
void cpu_halt_panic(void)
{
    cpu_halt();
}
#endif

/*@
  @ assigns \nothing;
  @ ensures \interrupt_disabled == 0;
  @*/
void cpu_safe_halt(void)
{
    asm volatile("sti; hlt");
}

/*@
  @ assigns \nothing;
  @ ensures \interrupt_disabled == 0;
  @*/
void cpu_enable_interrupt(void)
{
	asm volatile("sti");
}

/*@
  @ assigns \nothing;
  @ ensures \interrupt_disabled > 0;
  @*/
void cpu_disable_interrupt(void)
{
	asm volatile("cli");
}

/*@
  @ assigns \nothing;
  @ behavior to_enabled:
  @   assumes flags & RFLAGS_IF;
  @   ensures \interrupt_disabled == 0;
  @ behavior to_disabled:
  @   assumes !(flags & RFLAGS_IF);
  @   ensures \interrupt_disabled > 0;
  @*/
void cpu_restore_interrupt(unsigned long flags)
{
	asm volatile("push %0; popf" : : "g"(flags) : "memory", "cc");
}

/*@
  @ assigns \nothing;
  @*/
void cpu_pause(void)
{
	asm volatile("pause" ::: "memory");
}

/*@
  @ assigns \nothing;
  @ ensures \interrupt_disabled > 0;
  @ behavior from_enabled:
  @   assumes \interrupt_disabled == 0;
  @   ensures \result & RFLAGS_IF;
  @ behavior from_disabled:
  @   assumes \interrupt_disabled > 0;
  @   ensures !(\result & RFLAGS_IF);
  @*/
unsigned long cpu_disable_interrupt_save(void)
{
	unsigned long flags;

	asm volatile("pushf; pop %0; cli" : "=r"(flags) : : "memory", "cc");

	return flags;
}

unsigned long cpu_enable_interrupt_save(void)
{
	unsigned long flags;

	asm volatile("pushf; pop %0; sti" : "=r"(flags) : : "memory", "cc");

	return flags;
}

/*@
  @ behavior valid_vector:
  @   assumes 32 <= vector <= 255;
  @   requires \valid(h);
  @   assigns handlers[vector-32];
  @   ensures \result == 0;
  @ behavior invalid_vector:
  @   assumes (vector < 32) || (255 < vector);
  @   assigns \nothing;
  @   ensures \result == -EINVAL;
  @*/
int ihk_mc_register_interrupt_handler(int vector,
                                      struct ihk_mc_interrupt_handler *h)
{
	if (vector < 32 || vector > 255) {
		return -EINVAL;
	}

	list_add_tail(&h->list, &handlers[vector - 32]);

	return 0;
}
int ihk_mc_unregister_interrupt_handler(int vector,
                                        struct ihk_mc_interrupt_handler *h)
{
	list_del(&h->list);

	return 0;
}

extern unsigned long __page_fault_handler_address;

/*@
  @ requires \valid(h);
  @ assigns __page_fault_handler_address;
  @ ensures __page_fault_handler_address == h;
  @*/
void ihk_mc_set_page_fault_handler(void (*h)(void *, uint64_t, void *))
{
	__page_fault_handler_address = (unsigned long)h;
}

extern char trampoline_code_data[], trampoline_code_data_end[];
struct page_table *get_boot_page_table(void);
unsigned long get_transit_page_table(void);

/* reusable, but not reentrant */
/*@
  @ requires \valid_apicid(cpuid);	// valid APIC ID or not
  @ requires \valid(pc);
  @ requires \valid(trampoline_va);
  @ requires \valid(trampoline_code_data
  @		+(0..(trampoline_code_data_end - trampoline_code_data)));
  @ requires \valid_physical(ap_trampoline);	// valid physical address or not
  @ assigns (char *)trampoline_va+(0..trampoline_code_data_end - trampoline_code_data);
  @ assigns cpu_boot_status;
  @ ensures cpu_boot_status != 0;
  @*/
void ihk_mc_boot_cpu(int cpuid, unsigned long pc)
{
	unsigned long *p;

	p = (unsigned long *)trampoline_va;

	memcpy(p, trampoline_code_data, 
	       trampoline_code_data_end - trampoline_code_data);

	p[1] = (unsigned long)virt_to_phys(get_boot_page_table());
	p[2] = (unsigned long)setup_x86_ap;
	p[3] = pc;
	p[4] = (unsigned long)get_x86_cpu_local_kstack(cpuid);
	p[6] = (unsigned long)get_transit_page_table();
	if (!p[6]) {
		p[6] = p[1];
	}

	cpu_boot_status = 0;

	__x86_wakeup(cpuid, ap_trampoline);

	/* XXX: Time out */
	while (!cpu_boot_status) {
		cpu_pause();
	}
}

/*@
  @ requires \valid(new_ctx);
  @ requires (stack_pointer == NULL) || \valid((unsigned long *)stack_pointer-1);
  @ requires \valid(next_function);
  @*/
void ihk_mc_init_context(ihk_mc_kernel_context_t *new_ctx,
                         void *stack_pointer, void (*next_function)(void))
{
	unsigned long *sp;

	if (!stack_pointer) {
		stack_pointer = get_x86_this_cpu_kstack();
	}

	sp = stack_pointer;
	memset(new_ctx, 0, sizeof(ihk_mc_kernel_context_t));

	/* Set the return address */
	new_ctx->rsp = (unsigned long)(sp - 1);
	sp[-1] = (unsigned long)next_function;
}

extern char enter_user_mode[];

/* 
 * Release runq_lock before entering user space.
 * This is needed because schedule() holds the runq lock throughout
 * the context switch and when a new process is created it starts
 * execution in enter_user_mode, which in turn calls this function.
 */
void release_runq_lock(void)
{
	ihk_mc_spinlock_unlock(&(cpu_local_var(runq_lock)), 
			cpu_local_var(runq_irqstate));
}
                                       
/*@
  @ requires \valid(ctx);
  @ requires \valid(puctx);
  @ requires \valid((ihk_mc_user_context_t *)stack_pointer-1);
  @ requires \valid_user(new_pc);	// valid user space address or not
  @ requires \valid_user(user_sp-1);
  @ assigns *((ihk_mc_user_context_t *)stack_pointer-1);
  @ assigns ctx->rsp0;
  @*/
void ihk_mc_init_user_process(ihk_mc_kernel_context_t *ctx,
                              ihk_mc_user_context_t **puctx,
                              void *stack_pointer, unsigned long new_pc,
                              unsigned long user_sp)
{
	char *sp;
	ihk_mc_user_context_t *uctx;

	sp = stack_pointer;
	sp -= sizeof(ihk_mc_user_context_t);
	uctx = (ihk_mc_user_context_t *)sp;

	*puctx = uctx;

	memset(uctx, 0, sizeof(ihk_mc_user_context_t));
	uctx->gpr.cs = USER_CS;
	uctx->gpr.rip = new_pc;
	uctx->gpr.ss = USER_DS;
	uctx->gpr.rsp = user_sp;
	uctx->gpr.rflags = RFLAGS_IF;
	uctx->is_gpr_valid = 1;

	ihk_mc_init_context(ctx, sp, (void (*)(void))enter_user_mode);
	ctx->rsp0 = (unsigned long)stack_pointer;
}

/*@
  @ behavior rsp:
  @   assumes reg == IHK_UCR_STACK_POINTER;
  @   requires \valid(uctx);
  @   assigns uctx->gpr.rsp;
  @   ensures uctx->gpr.rsp == value;
  @ behavior rip:
  @   assumes reg == IHK_UCR_PROGRAM_COUNTER;
  @   requires \valid(uctx);
  @   assigns uctx->gpr.rip;
  @   ensures uctx->gpr.rip == value;
  @*/
void ihk_mc_modify_user_context(ihk_mc_user_context_t *uctx,
                                enum ihk_mc_user_context_regtype reg,
                                unsigned long value)
{
	if (reg == IHK_UCR_STACK_POINTER) {
		uctx->gpr.rsp = value;
	} else if (reg == IHK_UCR_PROGRAM_COUNTER) {
		uctx->gpr.rip = value;
	}
}

#ifdef POSTK_DEBUG_ARCH_DEP_42 /* /proc/cpuinfo support added. */
long ihk_mc_show_cpuinfo(char *buf, size_t buf_size, unsigned long read_off, int *eofp)
{
	*eofp = 1;
	return -ENOMEM;
}
#endif /* POSTK_DEBUG_ARCH_DEP_42 */

void arch_clone_thread(struct thread *othread, unsigned long pc,
			unsigned long sp, struct thread *nthread)
{
	return;
}

void ihk_mc_print_user_context(ihk_mc_user_context_t *uctx)
{
	kprintf("CS:RIP = %04lx:%16lx\n", uctx->gpr.cs, uctx->gpr.rip);
	kprintf("%16lx %16lx %16lx %16lx\n%16lx %16lx %16lx\n",
	        uctx->gpr.rax, uctx->gpr.rbx, uctx->gpr.rcx, uctx->gpr.rdx,
	        uctx->gpr.rsi, uctx->gpr.rdi, uctx->gpr.rsp);
}

/*@
  @ requires \valid(handler);
  @ assigns __x86_syscall_handler;
  @ ensures __x86_syscall_handler == handler;
  @*/
void ihk_mc_set_syscall_handler(long (*handler)(int, ihk_mc_user_context_t *))
{
	__x86_syscall_handler = handler;
}

/*@
  @ assigns \nothing;
  @*/
void ihk_mc_delay_us(int us)
{
	arch_delay(us);
}

void arch_show_extended_context(void)
{
	unsigned long cr0, cr4, msr, xcr0 = 0;

	/*  Read and print CRs, MSR_EFER, XCR0  */
	asm volatile("movq %%cr0, %0" : "=r"(cr0));
	asm volatile("movq %%cr4, %0" : "=r"(cr4));
	msr = rdmsr(MSR_EFER);
	if (xsave_available) {
		xcr0 = xgetbv(0);
	}
	__kprintf("\n             CR0              CR4\n");
	__kprintf("%016lX %016lX\n", cr0, cr4);

	__kprintf("             MSR_EFER\n");
	__kprintf("%016lX\n", msr);

	if (xsave_available) {
		__kprintf("             XCR0\n");
		__kprintf("%016lX\n", xcr0);
	}
}

struct stack {
	struct stack *rbp;
	unsigned long eip;
};

/* KPRINTF_LOCAL_BUF_LEN is 1024, useless to go further */
#define STACK_BUF_LEN (1024-sizeof("[  0]: "))
static void __print_stack(struct stack *rbp, unsigned long first) {
	char buf[STACK_BUF_LEN];
	size_t len;

	/* Build string in buffer to output a single line */
	len = snprintf(buf, STACK_BUF_LEN,
		       "addr2line -e smp-x86/kernel/mckernel.img -fpia");

	if (first)
		len += snprintf(buf + len, STACK_BUF_LEN - len,
				" %#16lx", first);

	while ((unsigned long)rbp > 0xffff880000000000 &&
			STACK_BUF_LEN - len > sizeof(" 0x0123456789abcdef")) {
		len += snprintf(buf + len, STACK_BUF_LEN - len,
				" %#16lx", rbp->eip);
		rbp = rbp->rbp;
	}
	__kprintf("%s\n", buf);
}

void arch_print_pre_interrupt_stack(const struct x86_basic_regs *regs) {
	struct stack *rbp;

	/* only for kernel stack */
	if (regs->error & PF_USER)
		return;

	__kprintf("Pre-interrupt stack trace:\n");

	/* interrupt stack heuristics:
	 * - the first entry looks like it is always garbage, so skip.
	 * (that is done by taking regs->rsp instead of &regs->rsp)
	 * - that still looks sometimes wrong. For now, if it is not
	 * within 64k of itself, look for the next entry that matches.
	 */

	rbp = (struct stack*)regs->rsp;

	while ((uintptr_t)rbp > (uintptr_t)rbp->rbp
			|| (uintptr_t)rbp + 0x10000 < (uintptr_t)rbp->rbp)
		rbp = (struct stack *)(((uintptr_t *)rbp) + 1);

	__print_stack(rbp, regs->rip);
}

void arch_print_stack(void)
{
	struct stack *rbp;

	__kprintf("Approximative stack trace:\n");

	asm("mov %%rbp, %0" : "=r"(rbp) );

	__print_stack(rbp, 0);
}

#ifdef ENABLE_FUGAKU_HACKS
unsigned long arch_get_instruction_address(const void *reg)
{
	const struct x86_user_context *uctx = reg;
	const struct x86_basic_regs *regs = &uctx->gpr;

	return regs->rip;
}
#endif

/*@
  @ requires \valid(reg);
  @ assigns \nothing;
  @*/
void arch_show_interrupt_context(const void *reg)
{
	const struct x86_user_context *uctx = reg;
	const struct x86_basic_regs *regs = &uctx->gpr;
	unsigned long irqflags;

	irqflags = kprintf_lock();

	__kprintf("CS:RIP = %4lx:%16lx\n", regs->cs, regs->rip);
	__kprintf("             RAX              RBX              RCX              RDX\n");
	__kprintf("%16lx %16lx %16lx %16lx\n",
	        regs->rax, regs->rbx, regs->rcx, regs->rdx);
	__kprintf("             RSI              RDI              RSP              RBP\n");
	__kprintf("%16lx %16lx %16lx %16lx\n",
	        regs->rsi, regs->rdi, regs->rsp, regs->rbp);
	__kprintf("              R8               R9              R10              R11\n");
	__kprintf("%16lx %16lx %16lx %16lx\n",
	        regs->r8, regs->r9, regs->r10, regs->r11);
	__kprintf("             R12              R13              R14              R15\n");
	__kprintf("%16lx %16lx %16lx %16lx\n",
	        regs->r12, regs->r13, regs->r14, regs->r15);
	__kprintf("              CS               SS           RFLAGS            ERROR\n");
	__kprintf("%16lx %16lx %16lx %16lx\n",
	        regs->cs, regs->ss, regs->rflags, regs->error);

kprintf_unlock(irqflags);
return;
	arch_show_extended_context();

	arch_print_pre_interrupt_stack(regs);

	kprintf_unlock(irqflags);
}

void arch_cpu_stop(void)
{
	while (1) {
		cpu_halt();
	}
}

/*@
  @ behavior fs_base:
  @   assumes type == IHK_ASR_X86_FS;
  @   ensures \result == 0;
  @ behavior invaiid_type:
  @   assumes type != IHK_ASR_X86_FS;
  @   ensures \result == -EINVAL;
  @*/
int ihk_mc_arch_set_special_register(enum ihk_asr_type type,
                                     unsigned long value)
{
	/* GS modification is not permitted */
	switch (type) {
	case IHK_ASR_X86_FS:
		wrmsr(MSR_FS_BASE, value);
		return 0;
	default:
		return -EINVAL;
	}
}

/*@
  @ behavior fs_base:
  @   assumes type == IHK_ASR_X86_FS;
  @   requires \valid(value);
  @   ensures \result == 0;
  @ behavior invalid_type:
  @   assumes type != IHK_ASR_X86_FS;
  @   ensures \result == -EINVAL;
  @*/
int ihk_mc_arch_get_special_register(enum ihk_asr_type type,
                                     unsigned long *value)
{
	/* GS modification is not permitted */
	switch (type) {
	case IHK_ASR_X86_FS:
		*value = rdmsr(MSR_FS_BASE);
		return 0;
	default:
		return -EINVAL;
	}
}

/*@
  @ requires \valid_cpuid(cpu);     // valid CPU logical ID
  @ ensures \result == 0
  @*/
int ihk_mc_interrupt_cpu(int cpu, int vector)
{
	if (cpu < 0 || cpu >= num_processors) {
		kprintf("%s: invalid CPU id: %d\n", __func__, cpu);
		return -1;
	}
	dkprintf("[%d] ihk_mc_interrupt_cpu: %d\n", ihk_mc_get_processor_id(), cpu);

	x86_issue_ipi(get_x86_cpu_local_variable(cpu)->apic_id, vector);
	return 0;
}

struct thread *arch_switch_context(struct thread *prev, struct thread *next)
{
	struct thread *last;
	struct mcs_rwlock_node_irqsave lock;

	dkprintf("[%d] schedule: tlsblock_base: 0x%lX\n",
	         ihk_mc_get_processor_id(), next->tlsblock_base);

	/* Set up new TLS.. */
	ihk_mc_init_user_tlsbase(next->uctx, next->tlsblock_base);

#ifdef ENABLE_PERF
	/* Performance monitoring inherit */
	if(next->proc->monitoring_event) {
		if(next->proc->perf_status == PP_RESET)
			perf_reset(next->proc->monitoring_event);
		if(next->proc->perf_status != PP_COUNT) {
			perf_reset(next->proc->monitoring_event);
			perf_start(next->proc->monitoring_event);
		}
	}
#endif

#ifdef PROFILE_ENABLE
	if (prev && prev->profile && prev->profile_start_ts != 0) {
		prev->profile_elapsed_ts +=
			(rdtsc() - prev->profile_start_ts);
		prev->profile_start_ts = 0;
	}

	if (next->profile && next->profile_start_ts == 0) {
		next->profile_start_ts = rdtsc();
	}
#endif

	if (prev) {
		mcs_rwlock_writer_lock(&prev->proc->update_lock, &lock);
		if (prev->proc->status & (PS_DELAY_STOPPED | PS_DELAY_TRACED)) {
			switch (prev->proc->status) {
			case PS_DELAY_STOPPED:
				prev->proc->status = PS_STOPPED;
				break;
			case PS_DELAY_TRACED:
				prev->proc->status = PS_TRACED;
				break;
			default:
				break;
			}
			mcs_rwlock_writer_unlock(&prev->proc->update_lock,
						&lock);

			/* Wake up the parent who tried wait4 and sleeping */
			waitq_wakeup(&prev->proc->parent->waitpid_q);
		} else {
			mcs_rwlock_writer_unlock(&prev->proc->update_lock,
						&lock);
		}

		last = ihk_mc_switch_context(&prev->ctx, &next->ctx, prev);
	}
	else {
		last = ihk_mc_switch_context(NULL, &next->ctx, prev);
	}
	return last;
}

/*@
  @ requires \valid(thread);
  @ ensures thread->fp_regs == NULL;
  @*/
void
release_fp_regs(struct thread *thread)
{
	int	pages;

	if (thread && !thread->fp_regs)
		return;

	pages = (xsave_size + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
	dkprintf("release_fp_regs: pages=%d\n", pages);
	ihk_mc_free_pages(thread->fp_regs, pages);
	thread->fp_regs = NULL;
}

static int
check_and_allocate_fp_regs(struct thread *thread)
{
	int pages;
	int result = 0;

	if (!thread->fp_regs) {
		pages = (xsave_size + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
		dkprintf("save_fp_regs: pages=%d\n", pages);
		thread->fp_regs = ihk_mc_alloc_pages(pages, IHK_MC_AP_NOWAIT);

		if (!thread->fp_regs) {
			kprintf("error: allocating fp_regs pages\n");
			result = -ENOMEM;
			goto out;
		}

		memset(thread->fp_regs, 0, pages * PAGE_SIZE);
	}
out:
	return result;
}

/*@
  @ requires \valid(thread);
  @*/
int
save_fp_regs(struct thread *thread)
{
	int ret = 0;

	ret = check_and_allocate_fp_regs(thread);
	if (ret) {
		goto out;
	}

	if (xsave_available) {
		unsigned int low, high;

		/* Request full save of x87, SSE, AVX and AVX-512 states */
		low = (unsigned int)xsave_mask;
		high = (unsigned int)(xsave_mask >> 32);

		asm volatile("xsave %0" : : "m" (*thread->fp_regs), "a" (low), "d" (high) 
			: "memory");

		dkprintf("fp_regs for TID %d saved\n", thread->tid);
	}
out:
	return ret;
}

int copy_fp_regs(struct thread *from, struct thread *to)
{
	int ret = 0;

	if (from->fp_regs != NULL) {
		ret = check_and_allocate_fp_regs(to);
		if (!ret) {
			memcpy(to->fp_regs,
				from->fp_regs,
				sizeof(fp_regs_struct));
		}
	}
	return ret;
}

/*@
  @ requires \valid(thread);
  @ assigns thread->fp_regs;
  @*/
void
restore_fp_regs(struct thread *thread)
{
	if (!thread->fp_regs) {
		// only clear fpregs.
		clear_fp_regs();
		return;
	}

	if (xsave_available) {
		unsigned int low, high;

		/* Request full restore of x87, SSE, AVX and AVX-512 states */
		low = (unsigned int)xsave_mask;
		high = (unsigned int)(xsave_mask >> 32);

		asm volatile("xrstor %0" : : "m" (*thread->fp_regs), 
				"a" (low), "d" (high));
		
		dkprintf("fp_regs for TID %d restored\n", thread->tid);
	}

	// XXX: why release??
	//release_fp_regs(thread);
}

void clear_fp_regs(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();

	restore_fp_regs(&v->idle);
}

ihk_mc_user_context_t *lookup_user_context(struct thread *thread)
{
	ihk_mc_user_context_t *uctx = thread->uctx;

	if ((!(thread->status & (PS_INTERRUPTIBLE | PS_UNINTERRUPTIBLE
						| PS_STOPPED | PS_TRACED))
				&& (thread != cpu_local_var(current)))
			|| !uctx->is_gpr_valid) {
		return NULL;
	}

	if (!uctx->is_sr_valid) {
		uctx->sr.fs_base = thread->tlsblock_base;
		uctx->sr.gs_base = 0;
		uctx->sr.ds = 0;
		uctx->sr.es = 0;
		uctx->sr.fs = 0;
		uctx->sr.gs = 0;

		uctx->is_sr_valid = 1;
	}

	return uctx;
} /* lookup_user_context() */

extern long do_arch_prctl(unsigned long code, unsigned long address);
void
ihk_mc_init_user_tlsbase(ihk_mc_user_context_t *ctx,
                         unsigned long tls_base_addr)
{
	do_arch_prctl(ARCH_SET_FS, tls_base_addr);
}

void arch_flush_icache_all(void)
{
	return;
}

/*@
  @ assigns \nothing;
  @*/
void init_tick(void)
{
	dkprintf("init_tick():\n");
	return;
}

/*@
  @ assigns \nothing;
  @*/
void init_delay(void)
{
	dkprintf("init_delay():\n");
	return;
}

/*@
  @ assigns \nothing;
  @*/
void sync_tick(void)
{
	dkprintf("sync_tick():\n");
	return;
}

static int is_pvclock_available(void)
{
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;

	dkprintf("is_pvclock_available()\n");
#define KVM_CPUID_SIGNATURE 0x40000000
	asm ("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
			: "a" (KVM_CPUID_SIGNATURE));
	if ((eax && (eax < 0x40000001))
			|| (ebx != 0x4b4d564b)
			|| (ecx != 0x564b4d56)
			|| (edx != 0x0000004d)) {
		dkprintf("is_pvclock_available(): false (not kvm)\n");
		return 0;
	}

#define KVM_CPUID_FEATURES 0x40000001
	asm ("cpuid" : "=a"(eax)
			: "a"(KVM_CPUID_FEATURES)
			: "%ebx", "%ecx", "%edx");
#define KVM_FEATURE_CLOCKSOURCE2 3
	if (eax & (1 << KVM_FEATURE_CLOCKSOURCE2)) {
#define MSR_KVM_SYSTEM_TIME_NEW 0x4b564d01
		pvti_msr = MSR_KVM_SYSTEM_TIME_NEW;
		dkprintf("is_pvclock_available(): true (new)\n");
		return 1;
	}
#define KVM_FEATURE_CLOCKSOURCE 0
	else if (eax & (1 << KVM_FEATURE_CLOCKSOURCE)) {
#define MSR_KVM_SYSTEM_TIME 0x12
		pvti_msr = MSR_KVM_SYSTEM_TIME;
		dkprintf("is_pvclock_available(): true (old)\n");
		return 1;
	}

	dkprintf("is_pvclock_available(): false (not supported)\n");
	return 0;
} /* is_pvclock_available() */

int arch_setup_pvclock(void)
{
	size_t size;
	int npages;

	dkprintf("arch_setup_pvclock()\n");
	if (!is_pvclock_available()) {
		dkprintf("arch_setup_pvclock(): not supported\n");
		return 0;
	}

	size = num_processors * sizeof(*pvti);
	npages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
	pvti_npages = npages;

	pvti = ihk_mc_alloc_pages(npages, IHK_MC_AP_NOWAIT);
	if (!pvti) {
		ekprintf("arch_setup_pvclock: allocate_pages failed.\n");
		return -ENOMEM;
	}
	memset(pvti, 0, PAGE_SIZE*npages);

	dkprintf("arch_setup_pvclock(): ok\n");
	return 0;
} /* arch_setup_pvclock() */

void arch_start_pvclock(void)
{
	int cpu;
	intptr_t phys;

	dkprintf("arch_start_pvclock()\n");
	if (!pvti) {
		dkprintf("arch_start_pvclock(): not supported\n");
		return;
	}

	cpu = ihk_mc_get_processor_id();
	phys = virt_to_phys(&pvti[cpu]);
#define KVM_SYSTEM_TIME_ENABLE 0x1
	wrmsr(pvti_msr, phys|KVM_SYSTEM_TIME_ENABLE);
	dkprintf("arch_start_pvclock(): ok\n");
	return;
} /* arch_start_pvclock() */

#define KVM_CPUID_SIGNATURE	0x40000000

int running_on_kvm(void) {
	static const char signature[12] = "KVMKVMKVM\0\0";
	const uint32_t *sigptr = (const uint32_t *)signature;
	uint64_t op;
	uint64_t eax;
	uint64_t ebx;
	uint64_t ecx;
	uint64_t edx;

	op = KVM_CPUID_SIGNATURE;
	asm volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx) : "a" (op));

	if (ebx == sigptr[0] && ecx == sigptr[1] && edx == sigptr[2]) {
		return 1;
	}

	return 0;
}

void
mod_nmi_ctx(void *nmi_ctx, void (*func)())
{
	unsigned long *l = nmi_ctx;
	int i;
	unsigned long flags;

	asm volatile("pushf; pop %0" : "=r"(flags) : : "memory", "cc");
	for (i = 0; i < 22; i++)
		l[i] = l[i + 5];
	l[i++] = (unsigned long)func;		// return address
	l[i++] = 0x20;				// KERNEL CS
	l[i++] = flags & ~RFLAGS_IF;		// rflags (disable interrupt)
	l[i++] = (unsigned long)(l + 27);	// ols rsp
	l[i++] = 0x28;				// KERNEL DS
}

void arch_save_panic_regs(void *irq_regs)
{
	struct thread *current = cpu_local_var(current);
	struct x86_user_context *regs =
		(struct x86_user_context *)irq_regs;
	struct x86_cpu_local_variables *x86v =
		get_x86_cpu_local_variable(ihk_mc_get_processor_id());
	struct segment_regs {
		uint32_t rflags;
		uint32_t cs;
		uint32_t ss;
		uint32_t ds;
		uint32_t es;
		uint32_t fs;
		uint32_t gs;
	} *sregs;

	/* Kernel space? */
	if (regs->gpr.rip > USER_END) {
		x86v->panic_regs[0] = regs->gpr.rax;
		x86v->panic_regs[1] = regs->gpr.rbx;
		x86v->panic_regs[2] = regs->gpr.rcx;
		x86v->panic_regs[3] = regs->gpr.rdx;
		x86v->panic_regs[4] = regs->gpr.rsi;
		x86v->panic_regs[5] = regs->gpr.rdi;
		x86v->panic_regs[6] = regs->gpr.rbp;
		x86v->panic_regs[7] = regs->gpr.rsp;
		x86v->panic_regs[8] = regs->gpr.r8;
		x86v->panic_regs[9] = regs->gpr.r9;
		x86v->panic_regs[10] = regs->gpr.r10;
		x86v->panic_regs[11] = regs->gpr.r11;
		x86v->panic_regs[12] = regs->gpr.r12;
		x86v->panic_regs[13] = regs->gpr.r13;
		x86v->panic_regs[14] = regs->gpr.r14;
		x86v->panic_regs[15] = regs->gpr.r15;
		x86v->panic_regs[16] = regs->gpr.rip;
		sregs = (struct segment_regs *)&x86v->panic_regs[17];
		sregs->rflags = regs->gpr.rflags;
		sregs->cs = regs->gpr.cs;
		sregs->ss = regs->gpr.ss;
		sregs->ds = regs->sr.ds;
		sregs->es = regs->sr.es;
		sregs->fs = regs->sr.fs;
		sregs->gs = regs->sr.gs;
	}
	/* User-space, show kernel context */
	else {
		kprintf("%s: in user-space: %p\n", __func__, regs->gpr.rip);
		x86v->panic_regs[0] = 0;
		x86v->panic_regs[1] = current->ctx.rbx;
		x86v->panic_regs[2] = 0;
		x86v->panic_regs[3] = 0;
		x86v->panic_regs[4] = current->ctx.rsi;
		x86v->panic_regs[5] = current->ctx.rdi;
		x86v->panic_regs[6] = current->ctx.rbp;
		x86v->panic_regs[7] = current->ctx.rsp;
		x86v->panic_regs[8] = 0;
		x86v->panic_regs[9] = 0;
		x86v->panic_regs[10] = 0;
		x86v->panic_regs[11] = 0;
		x86v->panic_regs[12] = regs->gpr.r12;
		x86v->panic_regs[13] = regs->gpr.r13;
		x86v->panic_regs[14] = regs->gpr.r14;
		x86v->panic_regs[15] = regs->gpr.r15;
		x86v->panic_regs[16] = (unsigned long)enter_user_mode;
		sregs = (struct segment_regs *)&x86v->panic_regs[17];
		sregs->rflags = regs->gpr.rflags;
		sregs->cs = regs->gpr.cs;
		sregs->ss = regs->gpr.ss;
		sregs->ds = regs->sr.ds;
		sregs->es = regs->sr.es;
		sregs->fs = regs->sr.fs;
		sregs->gs = regs->sr.gs;
	}

	x86v->paniced = 1;
}

void arch_clear_panic(void)
{
	struct x86_cpu_local_variables *x86v =
		get_x86_cpu_local_variable(ihk_mc_get_processor_id());

	x86v->paniced = 0;
}

int arch_cpu_read_write_register(
		struct ihk_os_cpu_register *desc,
		enum mcctrl_os_cpu_operation op)
{
	if (op == MCCTRL_OS_CPU_READ_REGISTER) {
		desc->val = rdmsr(desc->addr);
	}
	else if (op == MCCTRL_OS_CPU_WRITE_REGISTER) {
		wrmsr(desc->addr, desc->val);
	}
	else {
		return -1;
	}

	return 0;
}

extern int nmi_mode;
extern long freeze_thaw(void *nmi_ctx);

void multi_nm_interrupt_handler(void *irq_regs)
{
	dkprintf("%s: ...\n", __func__);
	switch (nmi_mode) {
	case 1:
	case 2:
		/* mode == 1 or 2, for FREEZER NMI */
		dkprintf("%s: freeze mode NMI catch. (nmi_mode=%d)\n",
			 __func__, nmi_mode);
		freeze_thaw(NULL);
		break;

	case 0:
		/* mode == 0, for MEMDUMP NMI */
		arch_save_panic_regs(irq_regs);
		ihk_mc_query_mem_areas();
		/* memdump-nmi is halted McKernel, break is unnecessary. */
		/* fall through */
	case 3:
		/* mode == 3, for SHUTDOWN-WAIT NMI */
		kprintf("%s: STOP\n", __func__);
		while (nmi_mode != 4)
			cpu_halt();
		break;

	case 4:
		/* mode == 4, continue NMI */
		arch_clear_panic();
		if (!ihk_mc_get_processor_id()) {
			ihk_mc_clear_dump_page_completion();
		}
		kprintf("%s: RESUME, nmi_mode: %d\n", __func__, nmi_mode);
		break;

	default:
		ekprintf("%s: Unknown nmi-mode(%d) detected.\n",
			 __func__, nmi_mode);
		break;
	}
}

/*** end of file ***/
