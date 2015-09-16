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
#include <ihk/debug.h>
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

#define LAPIC_ID            0x020
#define LAPIC_TIMER         0x320
#define LAPIC_TIMER_INITIAL 0x380
#define LAPIC_TIMER_CURRENT 0x390
#define LAPIC_TIMER_DIVIDE  0x3e0
#define LAPIC_SPURIOUS      0x0f0
#define LAPIC_EOI           0x0b0
#define LAPIC_ICR0          0x300
#define LAPIC_ICR2          0x310
#define LAPIC_ESR           0x280
#define LOCAL_TIMER_VECTOR  0xef

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


//#define DEBUG_PRINT_CPU

#ifdef DEBUG_PRINT_CPU
#define dkprintf kprintf
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
#endif


void init_processors_local(int max_id);
void assign_processor_id(void);
void arch_delay(int);
void x86_set_warm_reset(unsigned long ip, char *first_page_va);
void x86_init_perfctr(void);
int gettime_local_support = 0;

extern int kprintf(const char *format, ...);

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
extern char nmi[];
extern char page_fault[], general_protection_exception[];
extern char debug_exception[], int3_exception[];

uint64_t boot_pat_state = 0;
int no_turbo = 0; /* May be updated by early parsing of kargs */

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

	set_idt_entry(2, (uintptr_t)nmi);
	set_idt_entry(13, (unsigned long)general_protection_exception);
	set_idt_entry(14, (unsigned long)page_fault);

	set_idt_entry_trap_gate(1, (unsigned long)debug_exception);
	set_idt_entry_trap_gate(3, (unsigned long)int3_exception);

	reload_idt();
}

static int xsave_available = 0;

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
	if(cpuid01_ecx & (1 << 28)) {
		reg = xgetbv(0);
		reg |= 0x6;
		xsetbv(0, reg);
		dkprintf("init_fpu(): AVX init: XCR0 = 0x%016lX\n", reg);
	}

	/* TODO: set MSR_IA32_XSS to enable xsaves/xrstors */

#else
	kprintf("init_fpu(): SSE not enabled\n");
#endif

	asm volatile("finit");
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

static void *lapic_vp;
void lapic_write(int reg, unsigned int value)
{
	*(volatile unsigned int *)((char *)lapic_vp + reg) = value;
}

unsigned int lapic_read(int reg)
{
	return *(volatile unsigned int *)((char *)lapic_vp + reg);
}

void lapic_icr_write(unsigned int h, unsigned int l)
{
	lapic_write(LAPIC_ICR2, (unsigned int)h);
	lapic_write(LAPIC_ICR0, l);
}


void lapic_timer_enable(unsigned int clocks)
{
	unsigned int lvtt_value;

	lapic_write(LAPIC_TIMER_INITIAL, clocks / APIC_DIVISOR);
	lapic_write(LAPIC_TIMER_DIVIDE, 3);

	/* initialize periodic timer */
	lvtt_value = LOCAL_TIMER_VECTOR | APIC_LVT_TIMER_PERIODIC;
	lapic_write(LAPIC_TIMER, lvtt_value);
}

void lapic_timer_disable()
{
	lapic_write(LAPIC_TIMER_INITIAL, 0);
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

	asm volatile("cpuid" : "=a" (eax), "=c" (ecx) : "a" (0x6) : "%rbx", "%rdx");

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

void init_lapic(void)
{
	unsigned long baseaddr;

	/* Enable Local APIC */
	baseaddr = rdmsr(MSR_IA32_APIC_BASE);
	if (!lapic_vp) {
		lapic_vp = map_fixed_area(baseaddr & PAGE_MASK, PAGE_SIZE, 1);
	}
	baseaddr |= 0x800;
	wrmsr(MSR_IA32_APIC_BASE, baseaddr);

	lapic_write(LAPIC_SPURIOUS, 0x1ff);
}

void lapic_ack(void)
{
	lapic_write(LAPIC_EOI, 0);
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

	v = get_x86_this_cpu_local();
	tss_addr = (unsigned long)&v->tss;

	v->apic_id = lapic_read(LAPIC_ID) >> LAPIC_ID_SHIFT;

	memcpy(v->gdt, gdt, sizeof(v->gdt));
	
	memset(&v->tss, 0, sizeof(v->tss));

	v->gdt[GLOBAL_TSS_ENTRY] = (sizeof(v->tss) - 1) 
		| ((tss_addr & 0xffffff) << 16)
		| (0x89UL << 40) | ((tss_addr & 0xff000000) << 32);
	v->gdt[GLOBAL_TSS_ENTRY + 1] = (tss_addr >> 32);

	v->gdt_ptr.size = sizeof(v->gdt) - 1;
	v->gdt_ptr.address = (unsigned long)v->gdt;
        
	/* Load the new GDT, and set up CS, DS and SS. */
	reload_gdt(&v->gdt_ptr);

	set_kstack((unsigned long)get_x86_this_cpu_kstack());
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
	
	kprintf("IKC IRQ vector: %d, IKC target CPU APIC: %d\n", 
			ihk_ikc_irq, ihk_ikc_irq_apicid);

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
	 * Processor’s support for invariant TSC is indicated by
	 * CPUID.80000007H:EDX[8].
	 * See page 2498 of the Intel64 and IA-32 Architectures Software
	 * Developer’s Manual - combined */

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

void setup_x86(void)
{
	cpu_disable_interrupt();

	init_idt();

	init_gdt();

	init_page_table();

	check_no_execute();

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

void setup_x86_ap(void (*next_func)(void))
{
	unsigned long rsp;
	cpu_disable_interrupt();

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
void set_signal(int sig, void *regs, struct siginfo *info);
void check_signal(unsigned long, void *, int);
extern void tlb_flush_handler(int vector);

void handle_interrupt(int vector, struct x86_user_context *regs)
{
	struct ihk_mc_interrupt_handler *h;
	struct cpu_local_var *v = get_this_cpu_local_var();

	lapic_ack();
	++v->in_interrupt;

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
	}
	else if (vector >= IHK_TLB_FLUSH_IRQ_VECTOR_START && 
	         vector < IHK_TLB_FLUSH_IRQ_VECTOR_END) {

			tlb_flush_handler(vector);
	} 
	else {
		list_for_each_entry(h, &handlers[vector - 32], list) {
			if (h->func) {
				h->func(h->priv);
			}
		}
	}

	check_signal(0, regs, 0);
	check_need_resched();

	--v->in_interrupt;
}

void gpe_handler(struct x86_user_context *regs)
{
	kprintf("General protection fault (err: %lx, %lx:%lx)\n",
	        regs->gpr.error, regs->gpr.cs, regs->gpr.rip);
	arch_show_interrupt_context(regs);
	if ((regs->gpr.cs & 3) == 0) {
		panic("gpe_handler");
	}
	set_signal(SIGSEGV, regs, NULL);
	check_signal(0, regs, 0);
	check_need_resched();
	// panic("GPF");
}

void debug_handler(struct x86_user_context *regs)
{
	unsigned long db6;
	int si_code = 0;
	struct siginfo info;

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
	check_signal(0, regs, 0);
	check_need_resched();
}

void int3_handler(struct x86_user_context *regs)
{
	struct siginfo info;

#ifdef DEBUG_PRINT_CPU
	kprintf("int3 exception (err: %lx, %lx:%lx)\n",
	        regs->gpr.error, regs->gpr.cs, regs->gpr.rip);
	arch_show_interrupt_context(regs);
#endif

	memset(&info, '\0', sizeof info);
	info.si_code = TRAP_BRKPT;
	set_signal(SIGTRAP, regs, &info);
	check_signal(0, regs, 0);
	check_need_resched();
}

void x86_issue_ipi(unsigned int apicid, unsigned int low)
{
	lapic_icr_write(apicid << LAPIC_ICR_ID_SHIFT, low);
}

static void outb(uint8_t v, uint16_t port)
{
	asm volatile("outb %0, %1" : : "a" (v), "d" (port));
}

static void set_warm_reset_vector(unsigned long ip)
{
	x86_set_warm_reset(ip, first_page_va);
}

static void wait_icr_idle(void)
{
	while (lapic_read(LAPIC_ICR0) & APIC_ICR_BUSY) {
		cpu_pause();
	}
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
	wait_icr_idle();

	x86_issue_ipi(apicid, 
	              APIC_INT_LEVELTRIG | APIC_DM_INIT);
	wait_icr_idle();

	while (retry--) {
		lapic_read(LAPIC_ESR);
		x86_issue_ipi(apicid, APIC_DM_STARTUP | (ip >> 12));
		wait_icr_idle();

		arch_delay(200);

		if (cpu_boot_status) 
			break;
	}
}

/** IHK Functions **/

void cpu_halt(void)
{
	asm volatile("hlt");
}

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
struct page_table *get_init_page_table(void);
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

	p[1] = (unsigned long)virt_to_phys(get_init_page_table());
	p[2] = (unsigned long)setup_x86_ap;
	p[3] = pc;
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

#define EXTENDED_ARCH_SHOW_CONTEXT
#ifdef EXTENDED_ARCH_SHOW_CONTEXT
void arch_show_extended_context(void)
{
	unsigned long cr0, cr4, msr, xcr0;

	/*  Read and print CRs, MSR_EFER, XCR0  */
	asm volatile("movq %%cr0, %0" : "=r"(cr0));
	asm volatile("movq %%cr4, %0" : "=r"(cr4));
	msr = rdmsr(MSR_EFER);
	xcr0 = xgetbv(0);

	__kprintf("\n             CR0              CR4\n");
	__kprintf("%016lX %016lX\n", cr0, cr4);

	__kprintf("             MSR_EFER\n");
	__kprintf("%016lX\n", msr);

	__kprintf("             XCR0\n");
	__kprintf("%016lX\n", xcr0);

}
#endif

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

#ifdef EXTENDED_ARCH_SHOW_CONTEXT
        arch_show_extended_context();
#endif	

	kprintf_unlock(irqflags);
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
  @ requires \valid_apicid(cpu);	// valid APIC ID or not
  @ ensures \result == 0
  @*/
int ihk_mc_interrupt_cpu(int cpu, int vector)
{
	dkprintf("[%d] ihk_mc_interrupt_cpu: %d\n", ihk_mc_get_processor_id(), cpu);

	wait_icr_idle();
	x86_issue_ipi(cpu, vector);
	return 0;
}

/*@
  @ requires \valid(proc);
  @ ensures proc->fp_regs == NULL;
  @*/
void
release_fp_regs(struct process *proc)
{
	int	pages;

	if (proc && !proc->fp_regs)
		return;

	pages = (sizeof(fp_regs_struct) + 4095) >> 12;
	ihk_mc_free_pages(proc->fp_regs, pages);
	proc->fp_regs = NULL;
}

void
save_fp_regs(struct process *proc)
{
	int	pages;

	if (!proc->fp_regs) {
		pages = (sizeof(fp_regs_struct) + 4095) >> 12;
		proc->fp_regs = ihk_mc_alloc_pages(pages, IHK_MC_AP_NOWAIT);

		if (!proc->fp_regs) {
			kprintf("error: allocating fp_regs pages\n");
			return;
		}

		memset(proc->fp_regs, 0, sizeof(fp_regs_struct));
	}

	if (xsave_available) {
		unsigned int low, high;

		/* Request full save of x87, SSE and AVX states */
		low = 0x7;
		high = 0;

		asm volatile("xsave %0" : : "m" (*proc->fp_regs), "a" (low), "d" (high) 
			: "memory");

		dkprintf("fp_regs for TID %d saved\n", proc->ftn->tid);
	}
}

void
restore_fp_regs(struct process *proc)
{
	if (!proc->fp_regs)
		return;

	if (xsave_available) {
		unsigned int low, high;

		/* Request full restore of x87, SSE and AVX states */
		low = 0x7;
		high = 0;

		asm volatile("xrstor %0" : : "m" (*proc->fp_regs), 
				"a" (low), "d" (high));
		
		dkprintf("fp_regs for TID %d restored\n", proc->ftn->tid);
	}

	// XXX: why release??
	//release_fp_regs(proc);
}

ihk_mc_user_context_t *lookup_user_context(struct process *proc)
{
	ihk_mc_user_context_t *uctx = proc->uctx;

	if ((!(proc->ftn->status & (PS_INTERRUPTIBLE | PS_UNINTERRUPTIBLE
						| PS_STOPPED | PS_TRACED))
				&& (proc != cpu_local_var(current)))
			|| !uctx->is_gpr_valid) {
		return NULL;
	}

	if (!uctx->is_sr_valid) {
		uctx->sr.fs_base = proc->thread.tlsblock_base;
		uctx->sr.gs_base = 0;
		uctx->sr.ds = 0;
		uctx->sr.es = 0;
		uctx->sr.fs = 0;
		uctx->sr.gs = 0;

		uctx->is_sr_valid = 1;
	}

	return uctx;
} /* lookup_user_context() */


void zero_tsc(void)
{
	wrmsr(MSR_IA32_TIME_STAMP_COUNTER, 0);
}
