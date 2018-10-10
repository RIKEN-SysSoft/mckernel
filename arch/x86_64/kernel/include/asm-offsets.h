
#ifndef HEADER_X86_COMMON_ASM_OFFSETS_H
#define HEADER_X86_COMMON_ASM_OFFSETS_H

/* checks that these offsets match the struct are done in
 * init_processors_local() with BUILD_BUG_ON()
 * Unfortunately it cannot be generated automatically (with preprocessor
 * alone) as the assembly preprocessor is quite limited
 */
#define X86_CPU_LOCAL_OFFSET_KSTACK     16
#define X86_CPU_LOCAL_OFFSET_USTACK     24

#define X86_CPU_LOCAL_OFFSET_TSS        192
#define X86_TSS_OFFSET_SP0              4
#define X86_CPU_LOCAL_OFFSET_SP0 \
		(X86_CPU_LOCAL_OFFSET_TSS + X86_TSS_OFFSET_SP0)

#define X86_CPU_LOCAL_OFFSET_PANICED    296
#define X86_CPU_LOCAL_OFFSET_PANIC_REGS 304

#endif
