#ifndef HEADER_X86_COMMON_AAL_IKC_H
#define HEADER_X86_COMMON_AAL_IKC_H

#include <ikc/aal.h>

/* manycore side */
int aal_mc_ikc_init_first(struct aal_ikc_channel_desc *,
                          aal_ikc_ph_t handler);

#endif

