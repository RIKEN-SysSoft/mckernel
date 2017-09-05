/* context.h COPYRIGHT FUJITSU LIMITED 2015 */
#ifndef __HEADER_ARM64_COMMON_CONTEXT_H
#define __HEADER_ARM64_COMMON_CONTEXT_H

void switch_mm(struct page_table *pgtbl);
void free_mmu_context(struct page_table *pgtbl);

#endif /*__HEADER_ARM64_COMMON_CONTEXT_H*/
