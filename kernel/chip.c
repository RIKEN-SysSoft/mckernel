/*
 * Copyright(c) 2015, 2016 Intel Corporation.
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  - Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * This file contains all of the code that is specific to the HFI chip,
 * or what we use of them.
 */

#include <hfi1/hfi.h>
#include <hfi1/chip_registers.h>
#include <hfi1/chip.h>

/*
 * index is the index into the receive array
 */
void hfi1_put_tid(struct hfi1_devdata *dd, u32 index,
		  u32 type, unsigned long pa, u16 order)
{
	u64 reg;
	void __iomem *base = (dd->rcvarray_wc ? dd->rcvarray_wc :
			      (dd->kregbase + RCV_ARRAY));

	if (!(dd->flags & HFI1_PRESENT))
		goto done;

	if (type == PT_INVALID) {
		pa = 0;
	} else if (type > PT_INVALID) {
		kprintf("unexpected receive array type %u for index %u, not handled\n",
			type, index);
		goto done;
	}

#ifdef TIDRDMA_DEBUG
	hfi1_cdbg(TID, "type %s, index 0x%x, pa 0x%lx, bsize 0x%lx",
		  pt_name(type), index, pa, (unsigned long)order);
#endif

#define RT_ADDR_SHIFT 12	/* 4KB kernel address boundary */
	reg = RCV_ARRAY_RT_WRITE_ENABLE_SMASK
		| (u64)order << RCV_ARRAY_RT_BUF_SIZE_SHIFT
		| ((pa >> RT_ADDR_SHIFT) & RCV_ARRAY_RT_ADDR_MASK)
					<< RCV_ARRAY_RT_ADDR_SHIFT;
	writeq(reg, base + (index * 8));

	if (type == PT_EAGER)
		/*
		 * Eager entries are written one-by-one so we have to push them
		 * after we write the entry.
		 */
		flush_wc();
done:
	return;
}

void hfi1_clear_tids(struct hfi1_ctxtdata *rcd)
{
	struct hfi1_devdata *dd = rcd->dd;
	u32 i;

#if 0
	/* this could be optimized */
	for (i = rcd->eager_base; i < rcd->eager_base +
		     rcd->egrbufs.alloced; i++)
		hfi1_put_tid(dd, i, PT_INVALID, 0, 0);
#endif
	for (i = rcd->expected_base;
			i < rcd->expected_base + rcd->expected_count; i++)
		hfi1_put_tid(dd, i, PT_INVALID, 0, 0);
}

