#include <aal/cpu.h>
#include <aal/debug.h>
#include <types.h>
#include <errno.h>
#include <list.h>
#include <memory.h>
#include <string.h>
#include <registers.h>
#include <cpulocal.h>
#include <march.h>

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

#define APIC_INT_LEVELTRIG      0x08000
#define APIC_INT_ASSERT         0x04000
#define APIC_ICR_BUSY           0x01000
#define APIC_DEST_PHYSICAL      0x00000
#define APIC_DM_FIXED           0x00000
#define APIC_DM_NMI             0x00400
#define APIC_DM_INIT            0x00500
#define APIC_DM_STARTUP         0x00600


#define DEBUG_PRINT_CPU

#ifdef DEBUG_PRINT_CPU
#define dkprintf kprintf
#else
#define dkprintf(...)
#endif


struct x86_cpu_local_variables *get_x86_this_cpu_local(void);
void *get_x86_this_cpu_kstack(void);
void init_processors_local(int max_id);
void assign_processor_id(void);
void arch_delay(int);
void x86_set_warm_reset(void);
void x86_init_perfctr(void);

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
extern char page_fault[], general_protection_exception[];

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

	set_idt_entry(13, (unsigned long)general_protection_exception);
	set_idt_entry(14, (unsigned long)page_fault);

	reload_idt();
}

void init_fpu(void)
{
	unsigned long reg;

	asm volatile("movq %%cr0, %0" : "=r"(reg));
	/* Unset EM and TS flag. */
	reg &= ~((1 << 2) | (1 << 3));
	/* Set MP flag */
	reg |= 1 << 1;
	asm volatile("movq %0, %%cr0" : : "r"(reg));

#ifdef ENABLE_SSE
	asm volatile("movq %%cr4, %0" : "=r"(reg));
	/* Set OSFXSR flag. */
	reg |= (1 << 9);
	asm volatile("movq %0, %%cr4" : : "r"(reg));
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

void aal_mc_init_ap(void)
{
	struct aal_mc_cpu_info *cpu_info = aal_mc_get_cpu_info();

	trampoline_va = map_fixed_area(AP_TRAMPOLINE, AP_TRAMPOLINE_SIZE,
	                               0);
	first_page_va = map_fixed_area(0, PAGE_SIZE, 0);

	kprintf("# of cpus : %d\n", cpu_info->ncpus);
	init_processors_local(cpu_info->ncpus);

	/* Do initialization for THIS cpu (BSP) */
	assign_processor_id();

	init_smp_processor();
}

extern void init_page_table(void);

extern char x86_syscall[];
long (*__x86_syscall_handler)(int, aal_mc_user_context_t *);

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

void init_cpu(void)
{
	init_fpu();
	init_lapic();
	init_syscall();
	x86_init_perfctr();
}

void setup_x86(void)
{
	cpu_disable_interrupt();

	init_idt();

	init_gdt();

	init_page_table();

	init_cpu();

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

void handle_interrupt(int vector, struct x86_regs *regs)
{
	struct aal_mc_interrupt_handler *h;

	dkprintf("CPU[%d] got interrupt, vector: %d, RIP: 0x%lX\n", 
	         aal_mc_get_processor_id(), vector, regs->rip);

	if (vector < 0 || vector > 255) {
		panic("Invalid interrupt vector.");
	} else if (vector < 32) {
		if (vector == 8 || 
		    (vector >= 10 && vector <= 15) || vector == 17) {
			kprintf("Exception %d, rflags: 0x%lX CS: 0x%lX, RIP: 0x%lX\n",
			        vector, regs->rflags, regs->cs, regs->rip);
		} else {
			kprintf("Exception %d, rflags: 0x%lX CS: 0x%lX, RIP: 0x%lX\n",
			        vector, regs->rflags, regs->cs, regs->rip);
		}
		arch_show_interrupt_context(regs);
		panic("Unhandled exception");
	} else {
		list_for_each_entry(h, &handlers[vector - 32], list) {
			if (h->func) {
				h->func(h->priv);
			}
		}
	}

	lapic_ack();
}

void gpe_handler(struct x86_regs *regs)
{
	kprintf("General protection fault (err: %lx, %lx:%lx)\n",
	        regs->error, regs->cs, regs->rip);
	arch_show_interrupt_context(regs);
	panic("GPF");
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
	/* Write CMOS */
	x86_set_warm_reset();

	/* Set vector */
	*(unsigned short *)(first_page_va + 0x469) = (ip >> 4);
	*(unsigned short *)(first_page_va + 0x467) = ip & 0xf;
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

/** AAL Functions **/

void cpu_halt(void)
{
	asm volatile("hlt");
}

void cpu_enable_interrupt(void)
{
	asm volatile("sti");
}

void cpu_disable_interrupt(void)
{
	asm volatile("cli");
}

void cpu_restore_interrupt(unsigned long flags)
{
	asm volatile("push %0; popf" : : "g"(flags) : "memory", "cc");
}

void cpu_pause(void)
{
	asm volatile("pause");
}

unsigned long cpu_disable_interrupt_save(void)
{
	unsigned long flags;

	asm volatile("pushf; pop %0; cli" : "=r"(flags) : : "memory", "cc");

	return flags;
}

int aal_mc_register_interrupt_handler(int vector,
                                      struct aal_mc_interrupt_handler *h)
{
	if (vector < 32 || vector > 255) {
		return -EINVAL;
	}

	list_add_tail(&h->list, &handlers[vector - 32]);

	return 0;
}
int aal_mc_unregister_interrupt_handler(int vector,
                                        struct aal_mc_interrupt_handler *h)
{
	list_del(&h->list);

	return 0;
}

extern unsigned long __page_fault_handler_address;

void aal_mc_set_page_fault_handler(void (*h)(unsigned long, void *))
{
	__page_fault_handler_address = (unsigned long)h;
}

extern char trampoline_code_data[], trampoline_code_data_end[];
struct page_table *get_init_page_table(void);
unsigned long get_transit_page_table(void);

void aal_mc_boot_cpu(int cpuid, unsigned long pc)
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

	__x86_wakeup(cpuid, AP_TRAMPOLINE);

	/* XXX: Time out */
	while (!cpu_boot_status) {
		cpu_pause();
	}
}

void aal_mc_init_context(aal_mc_kernel_context_t *new_ctx,
                         void *stack_pointer, void (*next_function)(void))
{
	unsigned long *sp;

	if (!stack_pointer) {
		stack_pointer = get_x86_this_cpu_kstack();
	}

	sp = stack_pointer;
	memset(new_ctx, 0, sizeof(aal_mc_kernel_context_t));

	/* Set the return address */
	new_ctx->rsp = (unsigned long)(sp - 1);
	sp[-1] = (unsigned long)next_function;
}

extern char enter_user_mode[];
                                       
void aal_mc_init_user_process(aal_mc_kernel_context_t *ctx,
                              aal_mc_user_context_t **puctx,
                              void *stack_pointer, unsigned long new_pc,
                              unsigned long user_sp)
{
	char *sp;
	aal_mc_user_context_t *uctx;

	sp = stack_pointer;
	sp -= sizeof(aal_mc_user_context_t);
	uctx = (aal_mc_user_context_t *)sp;

	*puctx = uctx;

	memset(uctx, 0, sizeof(aal_mc_user_context_t));
	uctx->cs = USER_CS;
	uctx->rip = new_pc;
	uctx->ss = USER_DS;
	uctx->rsp = user_sp;
	uctx->rflags = RFLAGS_IF;

	aal_mc_init_context(ctx, sp, (void (*)(void))enter_user_mode);
	ctx->rsp0 = (unsigned long)stack_pointer;
}

void aal_mc_modify_user_context(aal_mc_user_context_t *uctx,
                                enum aal_mc_user_context_regtype reg,
                                unsigned long value)
{
	if (reg == AAL_UCR_STACK_POINTER) {
		uctx->rsp = value;
	} else if (reg == AAL_UCR_PROGRAM_COUNTER) {
		uctx->rip = value;
	}
}

void aal_mc_print_user_context(aal_mc_user_context_t *uctx)
{
	kprintf("CS:RIP = %04lx:%16lx\n", uctx->cs, uctx->rip);
	kprintf("%16lx %16lx %16lx %16lx\n%16lx %16lx %16lx\n",
	        uctx->rax, uctx->rbx, uctx->rcx, uctx->rdx,
	        uctx->rsi, uctx->rdi, uctx->rsp);
}

void aal_mc_set_syscall_handler(long (*handler)(int, aal_mc_user_context_t *))
{
	__x86_syscall_handler = handler;
}

void aal_mc_delay_us(int us)
{
	arch_delay(us);
}

void arch_show_interrupt_context(const void *reg)
{
	const struct x86_regs *regs = reg;
	int irqflags;

	irqflags = kprintf_lock();

	__kprintf("CS:EIP = %4lX:%16lX\n", regs->cs, regs->rip);
	__kprintf("             RAX              RBX              RCX              RDX\n");
	__kprintf("%16lX %16lX %16lX %16lX\n",
	        regs->rax, regs->rbx, regs->rcx, regs->rdx);
	__kprintf("             RSI              RDI              RSP\n");
	__kprintf("%16lX %16lX %16lX\n",
	        regs->rsi, regs->rdi, regs->rsp);
	__kprintf("              R8               R9              R10              R11\n");
	__kprintf("%16lX %16lX %16lX %16lX\n",
	        regs->r8, regs->r9, regs->r10, regs->r11);
	__kprintf("              CS               SS        \n");
	__kprintf("%16lX %16lX\n",
	        regs->cs, regs->ss);
	
	kprintf_unlock(irqflags);
}

int aal_mc_arch_set_special_register(enum aal_asr_type type,
                                     unsigned long value)
{
	/* GS modification is not permitted */
	switch (type) {
	case AAL_ASR_X86_FS:
		wrmsr(MSR_FS_BASE, value);
		return 0;
	default:
		return -EINVAL;
	}
}

int aal_mc_arch_get_special_register(enum aal_asr_type type,
                                     unsigned long *value)
{
	/* GS modification is not permitted */
	switch (type) {
	case AAL_ASR_X86_FS:
		*value = rdmsr(MSR_FS_BASE);
		return 0;
	default:
		return -EINVAL;
	}
}

int aal_mc_interrupt_cpu(int cpu, int vector)
{
	kprintf("[%d] aal_mc_interrupt_cpu: %d\n", aal_mc_get_processor_id(), cpu);

	wait_icr_idle();
	x86_issue_ipi(cpu, vector);
	return 0;
}
