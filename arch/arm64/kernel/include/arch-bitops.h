/* arch-bitops.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __HEADER_ARM64_COMMON_BITOPS_H
#define __HEADER_ARM64_COMMON_BITOPS_H

#ifndef INCLUDE_BITOPS_H
# error only <bitops.h> can be included directly
#endif

#ifndef __ASSEMBLY__

#include "bitops-fls.h"
#include "bitops-__ffs.h"
#include "bitops-ffz.h"
#include "bitops-set_bit.h"
#include "bitops-clear_bit.h"

#endif /*__ASSEMBLY__*/
#endif /* !__HEADER_ARM64_COMMON_BITOPS_H */

