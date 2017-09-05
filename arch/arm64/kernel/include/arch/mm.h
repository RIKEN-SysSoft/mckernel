/* mm.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef __HEADER_ARM64_ARCH_MM_H
#define __HEADER_ARM64_ARCH_MM_H

struct process_vm;

static inline void
flush_nfo_tlb()
{
}

static inline void
flush_nfo_tlb_mm(struct process_vm *vm)
{
}

#endif /* __HEADER_ARM64_ARCH_MM_H */
