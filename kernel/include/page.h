#ifndef __HEADER_PAGE_H
#define __HEADER_PAGE_H

void *allocate_pages(int npages, enum aal_mc_ap_flag flag);
void free_pages(void *va, int npages);

#endif
