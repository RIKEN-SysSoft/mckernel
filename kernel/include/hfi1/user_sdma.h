
#ifndef _HFI1_USER_SDMA_H
#define _HFI1_USER_SDMA_H

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

#include <hfi1/ihk_hfi1_common.h>
#include <hfi1/iowait.h>
#include <string.h>
#include <hfi1/hfi1_user.h>
#include <uio.h>

#ifdef __HFI1_ORIG__

#include <linux/device.h>
#include <linux/wait.h>

#include "common.h"
#include "iowait.h"
#include "user_exp_rcv.h"

extern uint extended_psn;

#endif /* __HFI1_ORIG__ */
/*
 * Define fields in the KDETH header so we can update the header
 * template.
 */
#define KDETH_OFFSET_SHIFT        0
#define KDETH_OFFSET_MASK         0x7fff
#define KDETH_OM_SHIFT            15
#define KDETH_OM_MASK             0x1
#define KDETH_TID_SHIFT           16
#define KDETH_TID_MASK            0x3ff
#define KDETH_TIDCTRL_SHIFT       26
#define KDETH_TIDCTRL_MASK        0x3
#define KDETH_INTR_SHIFT          28
#define KDETH_INTR_MASK           0x1
#define KDETH_SH_SHIFT            29
#define KDETH_SH_MASK             0x1
#define KDETH_KVER_SHIFT          30
#define KDETH_KVER_MASK           0x3
#define KDETH_JKEY_SHIFT          0x0
#define KDETH_JKEY_MASK           0xff
#define KDETH_HCRC_UPPER_SHIFT    16
#define KDETH_HCRC_UPPER_MASK     0xff
#define KDETH_HCRC_LOWER_SHIFT    24
#define KDETH_HCRC_LOWER_MASK     0xff

#define AHG_KDETH_INTR_SHIFT 12
#define AHG_KDETH_SH_SHIFT   13
#define AHG_KDETH_ARRAY_SIZE  9

#define KDETH_GET(val, field)						\
	(((le32_to_cpu((val))) >> KDETH_##field##_SHIFT) & KDETH_##field##_MASK)
#define KDETH_SET(dw, field, val) do {					\
		u32 dwval = le32_to_cpu(dw);				\
		dwval &= ~(KDETH_##field##_MASK << KDETH_##field##_SHIFT); \
		dwval |= (((val) & KDETH_##field##_MASK) << \
			  KDETH_##field##_SHIFT);			\
		dw = cpu_to_le32(dwval);				\
	} while (0)
#define KDETH_RESET(dw, field, val) ({ dw = 0; KDETH_SET(dw, field, val); })

/* KDETH OM multipliers and switch over point */
#define KDETH_OM_SMALL     4
#define KDETH_OM_SMALL_SHIFT     2
#define KDETH_OM_LARGE     64
#define KDETH_OM_LARGE_SHIFT     6
#define KDETH_OM_MAX_SIZE  (1 << ((KDETH_OM_LARGE / KDETH_OM_SMALL) + 1))

enum pkt_q_sdma_state {
	SDMA_PKT_Q_ACTIVE,
	SDMA_PKT_Q_DEFERRED,
};

#include <hfi1/hfi1_generated_hfi1_user_sdma_pkt_q.h>

struct hfi1_user_sdma_comp_q {
	u16 nentries;
	struct hfi1_sdma_comp_entry *comps;
};

int hfi1_user_sdma_process_request(void *private_data, struct iovec *iovec,
				   unsigned long dim, unsigned long *count);
#ifdef __HFI1_ORIG__

int hfi1_user_sdma_alloc_queues(struct hfi1_ctxtdata *, struct file *);
int hfi1_user_sdma_free_queues(struct hfi1_filedata *);
int hfi1_user_sdma_process_request(struct file *, struct iovec *, unsigned long,
				   unsigned long *);

#endif /* __HFI1_ORIG__ */
#endif /* _HFI1_SDMA_H */
