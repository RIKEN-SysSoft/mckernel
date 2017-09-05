/* cache.S COPYRIGHT FUJITSU LIMITED 2015 */

#include <linkage.h>
#include "proc-macros.S"

/*
 *	__inval_cache_range(start, end)
 *	- start   - start address of region
 *	- end     - end address of region
 */
ENTRY(__inval_cache_range)
	/* FALLTHROUGH */

/*
 *	__dma_inv_range(start, end)
 *	- start   - virtual start address of region
 *	- end     - virtual end address of region
 */
__dma_inv_range:
	dcache_line_size x2, x3
	sub	x3, x2, #1
	tst	x1, x3				// end cache line aligned?
	bic	x1, x1, x3
	b.eq	1f
	dc	civac, x1			// clean & invalidate D / U line
1:	tst	x0, x3				// start cache line aligned?
	bic	x0, x0, x3
	b.eq	2f
	dc	civac, x0			// clean & invalidate D / U line
	b	3f
2:	dc	ivac, x0			// invalidate D / U line
3:	add	x0, x0, x2
	cmp	x0, x1
	b.lo	2b
	dsb	sy
	ret
ENDPROC(__inval_cache_range)
ENDPROC(__dma_inv_range)

