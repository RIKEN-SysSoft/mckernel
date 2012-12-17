#ifndef HEADER_X86_COMMON_IHK_IKC_H
#define HEADER_X86_COMMON_IHK_IKC_H

#include <ikc/ihk.h>

/* manycore side */
int ihk_mc_ikc_init_first(struct ihk_ikc_channel_desc *,
                          ihk_ikc_ph_t handler);

#endif

