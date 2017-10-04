#ifndef _HFI1_KERNEL_H
#define _HFI1_KERNEL_H
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

#include <hfi1/user_sdma.h>

#ifdef __HFI1_ORIG__

#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/completion.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>
#include <rdma/ib_hdrs.h>
#include <linux/rhashtable.h>
#include <rdma/rdma_vt.h>

#include "chip_registers.h"
#include "common.h"
#include "opfn.h"
#include "verbs.h"
#include "pio.h"
#include "chip.h"
#include "mad.h"
#include "qsfp.h"
#include "platform.h"
#include "affinity.h"

/* bumped 1 from s/w major version of TrueScale */
#define HFI1_CHIP_VERS_MAJ 3U

/* don't care about this except printing */
#define HFI1_CHIP_VERS_MIN 0U

/* The Organization Unique Identifier (Mfg code), and its position in GUID */
#define HFI1_OUI 0x001175
#define HFI1_OUI_LSB 40

#define DROP_PACKET_OFF		0
#define DROP_PACKET_ON		1

#endif /* __HFI1_ORIG__ */

extern unsigned long hfi1_cap_mask;

#define HFI1_CAP_KGET_MASK(mask, cap) ((mask) & HFI1_CAP_##cap)
#define HFI1_CAP_UGET_MASK(mask, cap) \
	(((mask) >> HFI1_CAP_USER_SHIFT) & HFI1_CAP_##cap)
#define HFI1_CAP_KGET(cap) (HFI1_CAP_KGET_MASK(hfi1_cap_mask, cap))
#define HFI1_CAP_UGET(cap) (HFI1_CAP_UGET_MASK(hfi1_cap_mask, cap))
#define HFI1_CAP_IS_KSET(cap) (!!HFI1_CAP_KGET(cap))
#define HFI1_CAP_IS_USET(cap) (!!HFI1_CAP_UGET(cap))
#define HFI1_MISC_GET() ((hfi1_cap_mask >> HFI1_CAP_MISC_SHIFT) & \
			HFI1_CAP_MISC_MASK)
/* Offline Disabled Reason is 4-bits */
#define HFI1_ODR_MASK(rsn) ((rsn) & OPA_PI_MASK_OFFLINE_REASON)

/*
 * Control context is always 0 and handles the error packets.
 * It also handles the VL15 and multicast packets.
 */
#define HFI1_CTRL_CTXT    0

/*
 * Driver context will store software counters for each of the events
 * associated with these status registers
 */
#define NUM_CCE_ERR_STATUS_COUNTERS 41
#define NUM_RCV_ERR_STATUS_COUNTERS 64
#define NUM_MISC_ERR_STATUS_COUNTERS 13
#define NUM_SEND_PIO_ERR_STATUS_COUNTERS 36
#define NUM_SEND_DMA_ERR_STATUS_COUNTERS 4
#define NUM_SEND_EGRESS_ERR_STATUS_COUNTERS 64
#define NUM_SEND_ERR_STATUS_COUNTERS 3
#define NUM_SEND_CTXT_ERR_STATUS_COUNTERS 5
#define NUM_SEND_DMA_ENG_ERR_STATUS_COUNTERS 24

struct exp_tid_set {
	struct list_head list;
	u32 count;
};

/*
 * Get/Set IB link-level config parameters for f_get/set_ib_cfg()
 * Mostly for MADs that set or query link parameters, also ipath
 * config interfaces
 */
#define HFI1_IB_CFG_LIDLMC 0 /* LID (LS16b) and Mask (MS16b) */
#define HFI1_IB_CFG_LWID_DG_ENB 1 /* allowed Link-width downgrade */
#define HFI1_IB_CFG_LWID_ENB 2 /* allowed Link-width */
#define HFI1_IB_CFG_LWID 3 /* currently active Link-width */
#define HFI1_IB_CFG_SPD_ENB 4 /* allowed Link speeds */
#define HFI1_IB_CFG_SPD 5 /* current Link spd */
#define HFI1_IB_CFG_RXPOL_ENB 6 /* Auto-RX-polarity enable */
#define HFI1_IB_CFG_LREV_ENB 7 /* Auto-Lane-reversal enable */
#define HFI1_IB_CFG_LINKLATENCY 8 /* Link Latency (IB1.2 only) */
#define HFI1_IB_CFG_HRTBT 9 /* IB heartbeat off/enable/auto; DDR/QDR only */
#define HFI1_IB_CFG_OP_VLS 10 /* operational VLs */
#define HFI1_IB_CFG_VL_HIGH_CAP 11 /* num of VL high priority weights */
#define HFI1_IB_CFG_VL_LOW_CAP 12 /* num of VL low priority weights */
#define HFI1_IB_CFG_OVERRUN_THRESH 13 /* IB overrun threshold */
#define HFI1_IB_CFG_PHYERR_THRESH 14 /* IB PHY error threshold */
#define HFI1_IB_CFG_LINKDEFAULT 15 /* IB link default (sleep/poll) */
#define HFI1_IB_CFG_PKEYS 16 /* update partition keys */
#define HFI1_IB_CFG_MTU 17 /* update MTU in IBC */
#define HFI1_IB_CFG_VL_HIGH_LIMIT 19
#define HFI1_IB_CFG_PMA_TICKS 20 /* PMA sample tick resolution */
#define HFI1_IB_CFG_PORT 21 /* switch port we are connected to */

/*
 * HFI or Host Link States
 *
 * These describe the states the driver thinks the logical and physical
 * states are in.  Used as an argument to set_link_state().  Implemented
 * as bits for easy multi-state checking.  The actual state can only be
 * one.
 */
#define __HLS_UP_INIT_BP	0
#define __HLS_UP_ARMED_BP	1
#define __HLS_UP_ACTIVE_BP	2
#define __HLS_DN_DOWNDEF_BP	3	/* link down default */
#define __HLS_DN_POLL_BP	4
#define __HLS_DN_DISABLE_BP	5
#define __HLS_DN_OFFLINE_BP	6
#define __HLS_VERIFY_CAP_BP	7
#define __HLS_GOING_UP_BP	8
#define __HLS_GOING_OFFLINE_BP  9
#define __HLS_LINK_COOLDOWN_BP 10

#define HLS_UP_INIT	  BIT(__HLS_UP_INIT_BP)
#define HLS_UP_ARMED	  BIT(__HLS_UP_ARMED_BP)
#define HLS_UP_ACTIVE	  BIT(__HLS_UP_ACTIVE_BP)
#define HLS_DN_DOWNDEF	  BIT(__HLS_DN_DOWNDEF_BP) /* link down default */
#define HLS_DN_POLL	  BIT(__HLS_DN_POLL_BP)
#define HLS_DN_DISABLE	  BIT(__HLS_DN_DISABLE_BP)
#define HLS_DN_OFFLINE	  BIT(__HLS_DN_OFFLINE_BP)
#define HLS_VERIFY_CAP	  BIT(__HLS_VERIFY_CAP_BP)
#define HLS_GOING_UP	  BIT(__HLS_GOING_UP_BP)
#define HLS_GOING_OFFLINE BIT(__HLS_GOING_OFFLINE_BP)
#define HLS_LINK_COOLDOWN BIT(__HLS_LINK_COOLDOWN_BP)

#define HLS_UP (HLS_UP_INIT | HLS_UP_ARMED | HLS_UP_ACTIVE)
#define HLS_DOWN ~(HLS_UP)

/* use this MTU size if none other is given */
#define HFI1_DEFAULT_ACTIVE_MTU 10240
/* use this MTU size as the default maximum */
#define HFI1_DEFAULT_MAX_MTU 10240
/* default partition key */
#define DEFAULT_PKEY 0xffff

/*
 * Possible fabric manager config parameters for fm_{get,set}_table()
 */
#define FM_TBL_VL_HIGH_ARB		1 /* Get/set VL high prio weights */
#define FM_TBL_VL_LOW_ARB		2 /* Get/set VL low prio weights */
#define FM_TBL_BUFFER_CONTROL		3 /* Get/set Buffer Control */
#define FM_TBL_SC2VLNT			4 /* Get/set SC->VLnt */
#define FM_TBL_VL_PREEMPT_ELEMS		5 /* Get (no set) VL preempt elems */
#define FM_TBL_VL_PREEMPT_MATRIX	6 /* Get (no set) VL preempt matrix */

/*
 * Possible "operations" for f_rcvctrl(ppd, op, ctxt)
 * these are bits so they can be combined, e.g.
 * HFI1_RCVCTRL_INTRAVAIL_ENB | HFI1_RCVCTRL_CTXT_ENB
 */
#define HFI1_RCVCTRL_TAILUPD_ENB 0x01
#define HFI1_RCVCTRL_TAILUPD_DIS 0x02
#define HFI1_RCVCTRL_CTXT_ENB 0x04
#define HFI1_RCVCTRL_CTXT_DIS 0x08
#define HFI1_RCVCTRL_INTRAVAIL_ENB 0x10
#define HFI1_RCVCTRL_INTRAVAIL_DIS 0x20
#define HFI1_RCVCTRL_PKEY_ENB 0x40  /* Note, default is enabled */
#define HFI1_RCVCTRL_PKEY_DIS 0x80
#define HFI1_RCVCTRL_TIDFLOW_ENB 0x0400
#define HFI1_RCVCTRL_TIDFLOW_DIS 0x0800
#define HFI1_RCVCTRL_ONE_PKT_EGR_ENB 0x1000
#define HFI1_RCVCTRL_ONE_PKT_EGR_DIS 0x2000
#define HFI1_RCVCTRL_NO_RHQ_DROP_ENB 0x4000
#define HFI1_RCVCTRL_NO_RHQ_DROP_DIS 0x8000
#define HFI1_RCVCTRL_NO_EGR_DROP_ENB 0x10000
#define HFI1_RCVCTRL_NO_EGR_DROP_DIS 0x20000

/* partition enforcement flags */
#define HFI1_PART_ENFORCE_IN	0x1
#define HFI1_PART_ENFORCE_OUT	0x2

/* how often we check for synthetic counter wrap around */
#define SYNTH_CNT_TIME 2

/* Counter flags */
#define CNTR_NORMAL		0x0 /* Normal counters, just read register */
#define CNTR_SYNTH		0x1 /* Synthetic counters, saturate at all 1s */
#define CNTR_DISABLED		0x2 /* Disable this counter */
#define CNTR_32BIT		0x4 /* Simulate 64 bits for this counter */
#define CNTR_VL			0x8 /* Per VL counter */
#define CNTR_SDMA              0x10
#define CNTR_INVALID_VL		-1  /* Specifies invalid VL */
#define CNTR_MODE_W		0x0
#define CNTR_MODE_R		0x1

/* VLs Supported/Operational */
#define HFI1_MIN_VLS_SUPPORTED 1
#define HFI1_MAX_VLS_SUPPORTED 8

#define HFI1_GUIDS_PER_PORT  5
#define HFI1_PORT_GUID_INDEX 0

static inline void incr_cntr64(u64 *cntr)
{
	if (*cntr < (u64)-1LL)
		(*cntr)++;
}

static inline void incr_cntr32(u32 *cntr)
{
	if (*cntr < (u32)-1LL)
		(*cntr)++;
}

#define MAX_NAME_SIZE 64

struct rcv_array_data {
	u8 group_size;
	u16 ngroups;
	u16 nctxt_extra;
};

/* 16 to directly index */
#define PER_VL_SEND_CONTEXTS 16

#ifndef __HFI1_ORIG__

#define BOARD_VERS_MAX 96 /* how long the version string can be */
#define SERIAL_MAX 16 /* length of the serial number */

#endif /* !__HFI1_ORIG__ */

/* 8051 firmware version helper */
#define dc8051_ver(a, b) ((a) << 8 | (b))

/* f_put_tid types */
#define PT_EXPECTED 0
#define PT_EAGER    1
#define PT_INVALID  2

#ifdef __HFI1_ORIG__

struct mmu_rb_node;
struct mmu_rb_handler;

#endif /* __HFI1_ORIG__ */

struct tid_rb_node;

/* Original size on linux is 96 bytes */
/* Private data for file operations */

struct hfi1_filedata {
	struct hfi1_devdata *dd;
	struct hfi1_ctxtdata *uctxt;
	struct hfi1_user_sdma_comp_q *cq;
	struct hfi1_user_sdma_pkt_q *pq;
	u16 subctxt;
	/* for cpu affinity; -1 if none */
	int rec_cpu_num;
	u32 tid_n_pinned;
	void *handler; //struct mmu_rb_handler *handler;
	struct tid_rb_node **entry_to_rb;
	spinlock_t tid_lock; /* protect tid_[limit,used] counters */
	u32 tid_limit;
	u32 tid_used;
	u32 *invalid_tids;
	u32 invalid_tid_idx;
	/* protect invalid_tids array and invalid_tid_idx */
	spinlock_t invalid_lock;
	void *mm; //struct mm_struct *mm;
};

int hfi1_map_device_addresses(struct hfi1_filedata *fd);

#ifdef __HFI1_ORIG__

extern struct list_head hfi1_dev_list;
extern spinlock_t hfi1_devs_lock;
struct hfi1_devdata *hfi1_lookup(int unit);
extern u32 hfi1_cpulist_count;
extern unsigned long *hfi1_cpulist;

extern unsigned int snoop_drop_send;
extern unsigned int snoop_force_capture;
int hfi1_init(struct hfi1_devdata *, int);
int hfi1_count_units(int *npresentp, int *nupp);
int hfi1_count_active_units(void);

int hfi1_diag_add(struct hfi1_devdata *);
void hfi1_diag_remove(struct hfi1_devdata *);
void handle_linkup_change(struct hfi1_devdata *dd, u32 linkup);

void handle_user_interrupt(struct hfi1_ctxtdata *rcd);

int hfi1_create_rcvhdrq(struct hfi1_devdata *, struct hfi1_ctxtdata *);
int hfi1_setup_eagerbufs(struct hfi1_ctxtdata *);
int hfi1_create_ctxts(struct hfi1_devdata *dd);
struct hfi1_ctxtdata *hfi1_create_ctxtdata(struct hfi1_pportdata *, u32, int);
int hfi1_init_pportdata(struct pci_dev *, struct hfi1_pportdata *,
			struct hfi1_devdata *, u8, u8);
void hfi1_free_ctxtdata(struct hfi1_devdata *, struct hfi1_ctxtdata *);

int handle_receive_interrupt(struct hfi1_ctxtdata *, int);
int handle_receive_interrupt_nodma_rtail(struct hfi1_ctxtdata *, int);
int handle_receive_interrupt_dma_rtail(struct hfi1_ctxtdata *, int);
void set_all_slowpath(struct hfi1_devdata *dd);

extern const struct pci_device_id hfi1_pci_tbl[];

/* receive packet handler dispositions */
#define RCV_PKT_OK      0x0 /* keep going */
#define RCV_PKT_LIMIT   0x1 /* stop, hit limit, start thread */
#define RCV_PKT_DONE    0x2 /* stop, no more packets detected */

/* calculate the current RHF address */
static inline __le32 *get_rhf_addr(struct hfi1_ctxtdata *rcd)
{
	return (__le32 *)rcd->rcvhdrq + rcd->head + rcd->dd->rhf_offset;
}

int hfi1_reset_device(int);

/* return the driver's idea of the logical OPA port state */
static inline u32 driver_lstate(struct hfi1_pportdata *ppd)
{
	/*
	 * The driver does some processing from the time the logical
	 * link state is at INIT to the time the SM can be notified
	 * as such. Return IB_PORT_DOWN until the software state
	 * is ready.
	 */
	if (ppd->lstate == IB_PORT_INIT && !(ppd->host_link_state & HLS_UP))
		return IB_PORT_DOWN;
	else
		return ppd->lstate;
}

void receive_interrupt_work(struct work_struct *work);

/* extract service channel from header and rhf */
static inline int hdr2sc(struct ib_header *hdr, u64 rhf)
{
	return ((be16_to_cpu(hdr->lrh[0]) >> 12) & 0xf) |
	       ((!!(rhf_dc_info(rhf))) << 4);
}

#define HFI1_JKEY_WIDTH       16
#define HFI1_JKEY_MASK        (BIT(16) - 1)
#define HFI1_ADMIN_JKEY_RANGE 32

/*
 * J_KEYs are split and allocated in the following groups:
 *   0 - 31    - users with administrator privileges
 *  32 - 63    - kernel protocols using KDETH packets
 *  64 - 65535 - all other users using KDETH packets
 */
static inline u16 generate_jkey(kuid_t uid)
{
	u16 jkey = from_kuid(current_user_ns(), uid) & HFI1_JKEY_MASK;

	if (capable(CAP_SYS_ADMIN))
		jkey &= HFI1_ADMIN_JKEY_RANGE - 1;
	else if (jkey < 64)
		jkey |= BIT(HFI1_JKEY_WIDTH - 1);

	return jkey;
}

/*
 * active_egress_rate
 *
 * returns the active egress rate in units of [10^6 bits/sec]
 */
static inline u32 active_egress_rate(struct hfi1_pportdata *ppd)
{
	u16 link_speed = ppd->link_speed_active;
	u16 link_width = ppd->link_width_active;
	u32 egress_rate;

	if (link_speed == OPA_LINK_SPEED_25G)
		egress_rate = 25000;
	else /* assume OPA_LINK_SPEED_12_5G */
		egress_rate = 12500;

	switch (link_width) {
	case OPA_LINK_WIDTH_4X:
		egress_rate *= 4;
		break;
	case OPA_LINK_WIDTH_3X:
		egress_rate *= 3;
		break;
	case OPA_LINK_WIDTH_2X:
		egress_rate *= 2;
		break;
	default:
		/* assume IB_WIDTH_1X */
		break;
	}

	return egress_rate;
}

/*
 * egress_cycles
 *
 * Returns the number of 'fabric clock cycles' to egress a packet
 * of length 'len' bytes, at 'rate' Mbit/s. Since the fabric clock
 * rate is (approximately) 805 MHz, the units of the returned value
 * are (1/805 MHz).
 */
static inline u32 egress_cycles(u32 len, u32 rate)
{
	u32 cycles;

	/*
	 * cycles is:
	 *
	 *          (length) [bits] / (rate) [bits/sec]
	 *  ---------------------------------------------------
	 *  fabric_clock_period == 1 /(805 * 10^6) [cycles/sec]
	 */

	cycles = len * 8; /* bits */
	cycles *= 805;
	cycles /= rate;

	return cycles;
}

void set_link_ipg(struct hfi1_pportdata *ppd);
void process_becn(struct hfi1_pportdata *ppd, u8 sl,  u16 rlid, u32 lqpn,
		  u32 rqpn, u8 svc_type);
void return_cnp(struct hfi1_ibport *ibp, struct rvt_qp *qp, u32 remote_qpn,
		u32 pkey, u32 slid, u32 dlid, u8 sc5,
		const struct ib_grh *old_grh);
#define PKEY_CHECK_INVALID -1
int egress_pkey_check(struct hfi1_pportdata *ppd, __be16 *lrh, __be32 *bth,
		      u8 sc5, int8_t s_pkey_index);

#define PACKET_EGRESS_TIMEOUT 350
static inline void pause_for_credit_return(struct hfi1_devdata *dd)
{
	/* Pause at least 1us, to ensure chip returns all credits */
	u32 usec = cclock_to_ns(dd, PACKET_EGRESS_TIMEOUT) / 1000;

	udelay(usec ? usec : 1);
}

#define PKEY_MEMBER_MASK 0x8000
#define PKEY_LOW_15_MASK 0x7fff

/*
 * ingress_pkey_matches_entry - return 1 if the pkey matches ent (ent
 * being an entry from the ingress partition key table), return 0
 * otherwise. Use the matching criteria for ingress partition keys
 * specified in the OPAv1 spec., section 9.10.14.
 */
static inline int ingress_pkey_matches_entry(u16 pkey, u16 ent)
{
	u16 mkey = pkey & PKEY_LOW_15_MASK;
	u16 ment = ent & PKEY_LOW_15_MASK;

	if (mkey == ment) {
		/*
		 * If pkey[15] is clear (limited partition member),
		 * is bit 15 in the corresponding table element
		 * clear (limited member)?
		 */
		if (!(pkey & PKEY_MEMBER_MASK))
			return !!(ent & PKEY_MEMBER_MASK);
		return 1;
	}
	return 0;
}

/*
 * ingress_pkey_table_search - search the entire pkey table for
 * an entry which matches 'pkey'. return 0 if a match is found,
 * and 1 otherwise.
 */
static int ingress_pkey_table_search(struct hfi1_pportdata *ppd, u16 pkey)
{
	int i;

	for (i = 0; i < MAX_PKEY_VALUES; i++) {
		if (ingress_pkey_matches_entry(pkey, ppd->pkeys[i]))
			return 0;
	}
	return 1;
}

/*
 * ingress_pkey_table_fail - record a failure of ingress pkey validation,
 * i.e., increment port_rcv_constraint_errors for the port, and record
 * the 'error info' for this failure.
 */
static void ingress_pkey_table_fail(struct hfi1_pportdata *ppd, u16 pkey,
				    u16 slid)
{
	struct hfi1_devdata *dd = ppd->dd;

	incr_cntr64(&ppd->port_rcv_constraint_errors);
	if (!(dd->err_info_rcv_constraint.status & OPA_EI_STATUS_SMASK)) {
		dd->err_info_rcv_constraint.status |= OPA_EI_STATUS_SMASK;
		dd->err_info_rcv_constraint.slid = slid;
		dd->err_info_rcv_constraint.pkey = pkey;
	}
}

/*
 * ingress_pkey_check - Return 0 if the ingress pkey is valid, return 1
 * otherwise. Use the criteria in the OPAv1 spec, section 9.10.14. idx
 * is a hint as to the best place in the partition key table to begin
 * searching. This function should not be called on the data path because
 * of performance reasons. On datapath pkey check is expected to be done
 * by HW and rcv_pkey_check function should be called instead.
 */
static inline int ingress_pkey_check(struct hfi1_pportdata *ppd, u16 pkey,
				     u8 sc5, u8 idx, u16 slid)
{
	if (!(ppd->part_enforce & HFI1_PART_ENFORCE_IN))
		return 0;

	/* If SC15, pkey[0:14] must be 0x7fff */
	if ((sc5 == 0xf) && ((pkey & PKEY_LOW_15_MASK) != PKEY_LOW_15_MASK))
		goto bad;

	/* Is the pkey = 0x0, or 0x8000? */
	if ((pkey & PKEY_LOW_15_MASK) == 0)
		goto bad;

	/* The most likely matching pkey has index 'idx' */
	if (ingress_pkey_matches_entry(pkey, ppd->pkeys[idx]))
		return 0;

	/* no match - try the whole table */
	if (!ingress_pkey_table_search(ppd, pkey))
		return 0;

bad:
	ingress_pkey_table_fail(ppd, pkey, slid);
	return 1;
}

/*
 * rcv_pkey_check - Return 0 if the ingress pkey is valid, return 1
 * otherwise. It only ensures pkey is vlid for QP0. This function
 * should be called on the data path instead of ingress_pkey_check
 * as on data path, pkey check is done by HW (except for QP0).
 */
static inline int rcv_pkey_check(struct hfi1_pportdata *ppd, u16 pkey,
				 u8 sc5, u16 slid)
{
	if (!(ppd->part_enforce & HFI1_PART_ENFORCE_IN))
		return 0;

	/* If SC15, pkey[0:14] must be 0x7fff */
	if ((sc5 == 0xf) && ((pkey & PKEY_LOW_15_MASK) != PKEY_LOW_15_MASK))
		goto bad;

	return 0;
bad:
	ingress_pkey_table_fail(ppd, pkey, slid);
	return 1;
}

/* MTU handling */

/* MTU enumeration, 256-4k match IB */
#define OPA_MTU_0     0
#define OPA_MTU_256   1
#define OPA_MTU_512   2
#define OPA_MTU_1024  3
#define OPA_MTU_2048  4
#define OPA_MTU_4096  5

u32 lrh_max_header_bytes(struct hfi1_devdata *dd);
int mtu_to_enum(u32 mtu, int default_if_bad);
u16 enum_to_mtu(int);
static inline int valid_ib_mtu(unsigned int mtu)
{
	return mtu == 256 || mtu == 512 ||
		mtu == 1024 || mtu == 2048 ||
		mtu == 4096;
}

static inline int valid_opa_max_mtu(unsigned int mtu)
{
	return mtu >= 2048 &&
		(valid_ib_mtu(mtu) || mtu == 8192 || mtu == 10240);
}

int set_mtu(struct hfi1_pportdata *);

int hfi1_set_lid(struct hfi1_pportdata *, u32, u8);
void hfi1_disable_after_error(struct hfi1_devdata *);
int hfi1_set_uevent_bits(struct hfi1_pportdata *, const int);
int hfi1_rcvbuf_validate(u32, u8, u16 *);

int fm_get_table(struct hfi1_pportdata *, int, void *);
int fm_set_table(struct hfi1_pportdata *, int, void *);

void set_up_vl15(struct hfi1_devdata *dd, u8 vau, u16 vl15buf);
void reset_link_credits(struct hfi1_devdata *dd);
void assign_remote_cm_au_table(struct hfi1_devdata *dd, u8 vcu);

int snoop_recv_handler(struct hfi1_packet *packet);
int snoop_send_dma_handler(struct rvt_qp *qp, struct hfi1_pkt_state *ps,
			   u64 pbc);
int snoop_send_pio_handler(struct rvt_qp *qp, struct hfi1_pkt_state *ps,
			   u64 pbc);
void snoop_inline_pio_send(struct hfi1_devdata *dd, struct pio_buf *pbuf,
			   u64 pbc, const void *from, size_t count);
int set_buffer_control(struct hfi1_pportdata *ppd, struct buffer_control *bc);

static inline struct hfi1_devdata *dd_from_ppd(struct hfi1_pportdata *ppd)
{
	return ppd->dd;
}

static inline struct hfi1_devdata *dd_from_dev(struct hfi1_ibdev *dev)
{
	return container_of(dev, struct hfi1_devdata, verbs_dev);
}

static inline struct hfi1_devdata *dd_from_ibdev(struct ib_device *ibdev)
{
	return dd_from_dev(to_idev(ibdev));
}

static inline struct hfi1_pportdata *ppd_from_ibp(struct hfi1_ibport *ibp)
{
	return container_of(ibp, struct hfi1_pportdata, ibport_data);
}

static inline struct hfi1_ibdev *dev_from_rdi(struct rvt_dev_info *rdi)
{
	return container_of(rdi, struct hfi1_ibdev, rdi);
}

static inline struct hfi1_ibport *to_iport(struct ib_device *ibdev, u8 port)
{
	struct hfi1_devdata *dd = dd_from_ibdev(ibdev);
	unsigned pidx = port - 1; /* IB number port from 1, hdw from 0 */

	WARN_ON(pidx >= dd->num_pports);
	return &dd->pport[pidx].ibport_data;
}

static inline struct hfi1_ibport *rcd_to_iport(struct hfi1_ctxtdata *rcd)
{
	return &rcd->ppd->ibport_data;
}

void hfi1_process_ecn_slowpath(struct rvt_qp *qp, struct hfi1_packet *pkt,
			       bool do_cnp);
static inline bool process_ecn(struct rvt_qp *qp, struct hfi1_packet *pkt,
			       bool do_cnp)
{
	struct ib_other_headers *ohdr = pkt->ohdr;
	u32 bth1;

	bth1 = be32_to_cpu(ohdr->bth[1]);
	if (unlikely(bth1 & (HFI1_BECN_SMASK | HFI1_FECN_SMASK))) {
		hfi1_process_ecn_slowpath(qp, pkt, do_cnp);
		return !!(bth1 & HFI1_FECN_SMASK);
	}
	return false;
}

/*
 * Return the indexed PKEY from the port PKEY table.
 */
static inline u16 hfi1_get_pkey(struct hfi1_ibport *ibp, unsigned index)
{
	struct hfi1_pportdata *ppd = ppd_from_ibp(ibp);
	u16 ret;

	if (index >= ARRAY_SIZE(ppd->pkeys))
		ret = 0;
	else
		ret = ppd->pkeys[index];

	return ret;
}

/*
 * Return the indexed GUID from the port GUIDs table.
 */
static inline __be64 get_sguid(struct hfi1_ibport *ibp, unsigned int index)
{
	struct hfi1_pportdata *ppd = ppd_from_ibp(ibp);

	WARN_ON(index >= HFI1_GUIDS_PER_PORT);
	return cpu_to_be64(ppd->guids[index]);
}

/*
 * Called by readers of cc_state only, must call under rcu_read_lock().
 */
static inline struct cc_state *get_cc_state(struct hfi1_pportdata *ppd)
{
	return rcu_dereference(ppd->cc_state);
}

/*
 * Called by writers of cc_state only,  must call under cc_state_lock.
 */
static inline
struct cc_state *get_cc_state_protected(struct hfi1_pportdata *ppd)
{
	return rcu_dereference_protected(ppd->cc_state,
					 lockdep_is_held(&ppd->cc_state_lock));
}

#endif /* __HFI1_ORIG__ */

/*
 * values for dd->flags (_device_ related flags)
 */
#define HFI1_INITTED           0x1    /* chip and driver up and initted */
#define HFI1_PRESENT           0x2    /* chip accesses can be done */
#define HFI1_FROZEN            0x4    /* chip in SPC freeze */
#define HFI1_HAS_SDMA_TIMEOUT  0x8
#define HFI1_HAS_SEND_DMA      0x10   /* Supports Send DMA */
#define HFI1_FORCED_FREEZE     0x80   /* driver forced freeze mode */

#ifdef __HFI1_ORIG__
/* IB dword length mask in PBC (lower 11 bits); same for all chips */
#define HFI1_PBC_LENGTH_MASK                     ((1 << 11) - 1)

/* ctxt_flag bit offsets */
		/* context has been setup */
#define HFI1_CTXT_SETUP_DONE 1
		/* waiting for a packet to arrive */
#define HFI1_CTXT_WAITING_RCV   2
		/* master has not finished initializing */
#define HFI1_CTXT_MASTER_UNINIT 4
		/* waiting for an urgent packet to arrive */
#define HFI1_CTXT_WAITING_URG 5

/* free up any allocated data at closes */
struct hfi1_devdata *hfi1_init_dd(struct pci_dev *,
				  const struct pci_device_id *);
void hfi1_free_devdata(struct hfi1_devdata *);
struct hfi1_devdata *hfi1_alloc_devdata(struct pci_dev *pdev, size_t extra);

/* LED beaconing functions */
void hfi1_start_led_override(struct hfi1_pportdata *ppd, unsigned int timeon,
			     unsigned int timeoff);
void shutdown_led_override(struct hfi1_pportdata *ppd);

#define HFI1_CREDIT_RETURN_RATE (100)

/*
 * The number of words for the KDETH protocol field.  If this is
 * larger then the actual field used, then part of the payload
 * will be in the header.
 *
 * Optimally, we want this sized so that a typical case will
 * use full cache lines.  The typical local KDETH header would
 * be:
 *
 *	Bytes	Field
 *	  8	LRH
 *	 12	BHT
 *	 ??	KDETH
 *	  8	RHF
 *	---
 *	 28 + KDETH
 *
 * For a 64-byte cache line, KDETH would need to be 36 bytes or 9 DWORDS
 */
#define DEFAULT_RCVHDRSIZE 9

/*
 * Maximal header byte count:
 *
 *	Bytes	Field
 *	  8	LRH
 *	 40	GRH (optional)
 *	 12	BTH
 *	 ??	KDETH
 *	  8	RHF
 *	---
 *	 68 + KDETH
 *
 * We also want to maintain a cache line alignment to assist DMA'ing
 * of the header bytes.  Round up to a good size.
 */
#define DEFAULT_RCVHDR_ENTSIZE 32

bool hfi1_can_pin_pages(struct hfi1_devdata *dd, struct mm_struct *mm,
			u32 nlocked, u32 npages);
int hfi1_acquire_user_pages(struct mm_struct *mm, unsigned long vaddr,
			    size_t npages, bool writable, struct page **pages);
void hfi1_release_user_pages(struct mm_struct *mm, struct page **p,
			     size_t npages, bool dirty);

static inline void clear_rcvhdrtail(const struct hfi1_ctxtdata *rcd)
{
	*((u64 *)rcd->rcvhdrtail_kvaddr) = 0ULL;
}

static inline u32 get_rcvhdrtail(const struct hfi1_ctxtdata *rcd)
{
	/*
	 * volatile because it's a DMA target from the chip, routine is
	 * inlined, and don't want register caching or reordering.
	 */
	return (u32)le64_to_cpu(*rcd->rcvhdrtail_kvaddr);
}

/*
 * sysfs interface.
 */

extern const char ib_hfi1_version[];

int hfi1_device_create(struct hfi1_devdata *);
void hfi1_device_remove(struct hfi1_devdata *);

int hfi1_create_port_files(struct ib_device *ibdev, u8 port_num,
			   struct kobject *kobj);
int hfi1_verbs_register_sysfs(struct hfi1_devdata *);
void hfi1_verbs_unregister_sysfs(struct hfi1_devdata *);
/* Hook for sysfs read of QSFP */
int qsfp_dump(struct hfi1_pportdata *ppd, char *buf, int len);

int hfi1_pcie_init(struct pci_dev *, const struct pci_device_id *);
void hfi1_pcie_cleanup(struct pci_dev *);
int hfi1_pcie_ddinit(struct hfi1_devdata *, struct pci_dev *);
void hfi1_pcie_ddcleanup(struct hfi1_devdata *);
void hfi1_pcie_flr(struct hfi1_devdata *);
int pcie_speeds(struct hfi1_devdata *);
void request_msix(struct hfi1_devdata *, u32 *, struct hfi1_msix_entry *);
void hfi1_enable_intx(struct pci_dev *);
void restore_pci_variables(struct hfi1_devdata *dd);
int do_pcie_gen3_transition(struct hfi1_devdata *dd);
int parse_platform_config(struct hfi1_devdata *dd);
int get_platform_config_field(struct hfi1_devdata *dd,
			      enum platform_config_table_type_encoding
			      table_type, int table_index, int field_index,
			      u32 *data, u32 len);

const char *get_unit_name(int unit);
const char *get_card_name(struct rvt_dev_info *rdi);
struct pci_dev *get_pci_dev(struct rvt_dev_info *rdi);

#endif /* __HFI1_ORIG__ */
/*
 * Flush write combining store buffers (if present) and perform a write
 * barrier.
 */
static inline void flush_wc(void)
{
	asm volatile("sfence" : : : "memory");
}

#ifdef __HFI1_ORIG__
void handle_eflags(struct hfi1_packet *packet);
int process_receive_ib(struct hfi1_packet *packet);
int process_receive_bypass(struct hfi1_packet *packet);
int process_receive_error(struct hfi1_packet *packet);
int kdeth_process_expected(struct hfi1_packet *packet);
int kdeth_process_eager(struct hfi1_packet *packet);
int process_receive_invalid(struct hfi1_packet *packet);

extern rhf_rcv_function_ptr snoop_rhf_rcv_functions[8];

/* global module parameter variables */
extern unsigned int hfi1_max_mtu;
extern unsigned int hfi1_cu;
extern unsigned int user_credit_return_threshold;
extern int num_user_contexts;
extern unsigned long n_krcvqs;
extern uint krcvqs[];
extern int krcvqsset;
extern uint kdeth_qp;
extern uint loopback;
extern uint quick_linkup;
extern uint rcv_intr_timeout;
extern uint rcv_intr_count;
extern uint rcv_intr_dynamic;
extern ushort link_crc_mask;

extern struct mutex hfi1_mutex;

/* Number of seconds before our card status check...  */
#define STATUS_TIMEOUT 60

#define DRIVER_NAME		"hfi1"
#define HFI1_USER_MINOR_BASE     0
#define HFI1_TRACE_MINOR         127
#define HFI1_DIAGPKT_MINOR       128
#define HFI1_DIAG_MINOR_BASE     129
#define HFI1_SNOOP_CAPTURE_BASE  200
#define HFI1_NMINORS             255

#define PCI_VENDOR_ID_INTEL 0x8086
#define PCI_DEVICE_ID_INTEL0 0x24f0
#define PCI_DEVICE_ID_INTEL1 0x24f1

#define HFI1_PKT_USER_SC_INTEGRITY					    \
	(SEND_CTXT_CHECK_ENABLE_DISALLOW_NON_KDETH_PACKETS_SMASK	    \
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_KDETH_PACKETS_SMASK		\
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_BYPASS_SMASK		    \
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_GRH_SMASK)

#define HFI1_PKT_KERNEL_SC_INTEGRITY					    \
	(SEND_CTXT_CHECK_ENABLE_DISALLOW_KDETH_PACKETS_SMASK)

static inline u64 hfi1_pkt_default_send_ctxt_mask(struct hfi1_devdata *dd,
						  u16 ctxt_type)
{
	u64 base_sc_integrity;

	/*
	 * No integrity checks if HFI1_CAP_NO_INTEGRITY is set
	 * or driver is snooping
	 */
	if (HFI1_CAP_IS_KSET(NO_INTEGRITY) ||
	    (dd->hfi1_snoop.mode_flag & HFI1_PORT_SNOOP_MODE))
		return 0;

	base_sc_integrity =
	SEND_CTXT_CHECK_ENABLE_DISALLOW_BYPASS_BAD_PKT_LEN_SMASK
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_PBC_STATIC_RATE_CONTROL_SMASK
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_TOO_LONG_BYPASS_PACKETS_SMASK
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_TOO_LONG_IB_PACKETS_SMASK
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_BAD_PKT_LEN_SMASK
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_PBC_TEST_SMASK
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_TOO_SMALL_BYPASS_PACKETS_SMASK
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_TOO_SMALL_IB_PACKETS_SMASK
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_RAW_IPV6_SMASK
	| SEND_CTXT_CHECK_ENABLE_DISALLOW_RAW_SMASK
	| SEND_CTXT_CHECK_ENABLE_CHECK_BYPASS_VL_MAPPING_SMASK
	| SEND_CTXT_CHECK_ENABLE_CHECK_VL_MAPPING_SMASK
	| SEND_CTXT_CHECK_ENABLE_CHECK_OPCODE_SMASK
	| SEND_CTXT_CHECK_ENABLE_CHECK_SLID_SMASK
	| SEND_CTXT_CHECK_ENABLE_CHECK_VL_SMASK
	| SEND_CTXT_CHECK_ENABLE_CHECK_ENABLE_SMASK;

	if (ctxt_type == SC_USER)
		base_sc_integrity |= HFI1_PKT_USER_SC_INTEGRITY;
	else if (ctxt_type != SC_KERNEL)
		base_sc_integrity |= HFI1_PKT_KERNEL_SC_INTEGRITY;

	/* turn on send-side job key checks if !A0 */
	if (!is_ax(dd))
		base_sc_integrity |= SEND_CTXT_CHECK_ENABLE_CHECK_JOB_KEY_SMASK;

	return base_sc_integrity;
}

static inline u64 hfi1_pkt_base_sdma_integrity(struct hfi1_devdata *dd)
{
	u64 base_sdma_integrity;

	/* No integrity checks if HFI1_CAP_NO_INTEGRITY is set */
	if (HFI1_CAP_IS_KSET(NO_INTEGRITY))
		return 0;

	base_sdma_integrity =
	SEND_DMA_CHECK_ENABLE_DISALLOW_BYPASS_BAD_PKT_LEN_SMASK
	| SEND_DMA_CHECK_ENABLE_DISALLOW_TOO_LONG_BYPASS_PACKETS_SMASK
	| SEND_DMA_CHECK_ENABLE_DISALLOW_TOO_LONG_IB_PACKETS_SMASK
	| SEND_DMA_CHECK_ENABLE_DISALLOW_BAD_PKT_LEN_SMASK
	| SEND_DMA_CHECK_ENABLE_DISALLOW_TOO_SMALL_BYPASS_PACKETS_SMASK
	| SEND_DMA_CHECK_ENABLE_DISALLOW_TOO_SMALL_IB_PACKETS_SMASK
	| SEND_DMA_CHECK_ENABLE_DISALLOW_RAW_IPV6_SMASK
	| SEND_DMA_CHECK_ENABLE_DISALLOW_RAW_SMASK
	| SEND_DMA_CHECK_ENABLE_CHECK_BYPASS_VL_MAPPING_SMASK
	| SEND_DMA_CHECK_ENABLE_CHECK_VL_MAPPING_SMASK
	| SEND_DMA_CHECK_ENABLE_CHECK_OPCODE_SMASK
	| SEND_DMA_CHECK_ENABLE_CHECK_SLID_SMASK
	| SEND_DMA_CHECK_ENABLE_CHECK_VL_SMASK
	| SEND_DMA_CHECK_ENABLE_CHECK_ENABLE_SMASK;

	if (!HFI1_CAP_IS_KSET(STATIC_RATE_CTRL))
		base_sdma_integrity |=
		SEND_DMA_CHECK_ENABLE_DISALLOW_PBC_STATIC_RATE_CONTROL_SMASK;

	/* turn on send-side job key checks if !A0 */
	if (!is_ax(dd))
		base_sdma_integrity |=
			SEND_DMA_CHECK_ENABLE_CHECK_JOB_KEY_SMASK;

	return base_sdma_integrity;
}

/*
 * hfi1_early_err is used (only!) to print early errors before devdata is
 * allocated, or when dd->pcidev may not be valid, and at the tail end of
 * cleanup when devdata may have been freed, etc.  hfi1_dev_porterr is
 * the same as dd_dev_err, but is used when the message really needs
 * the IB port# to be definitive as to what's happening..
 */
#define hfi1_early_err(dev, fmt, ...) \
	dev_err(dev, fmt, ##__VA_ARGS__)

#define hfi1_early_info(dev, fmt, ...) \
	dev_info(dev, fmt, ##__VA_ARGS__)

#define dd_dev_emerg(dd, fmt, ...) \
	dev_emerg(&(dd)->pcidev->dev, "%s: " fmt, \
		  get_unit_name((dd)->unit), ##__VA_ARGS__)
#define dd_dev_err(dd, fmt, ...) \
	dev_err(&(dd)->pcidev->dev, "%s: " fmt, \
			get_unit_name((dd)->unit), ##__VA_ARGS__)
#define dd_dev_warn(dd, fmt, ...) \
	dev_warn(&(dd)->pcidev->dev, "%s: " fmt, \
			get_unit_name((dd)->unit), ##__VA_ARGS__)

#define dd_dev_warn_ratelimited(dd, fmt, ...) \
	dev_warn_ratelimited(&(dd)->pcidev->dev, "%s: " fmt, \
			get_unit_name((dd)->unit), ##__VA_ARGS__)

#define dd_dev_info(dd, fmt, ...) \
	dev_info(&(dd)->pcidev->dev, "%s: " fmt, \
			get_unit_name((dd)->unit), ##__VA_ARGS__)

#define dd_dev_dbg(dd, fmt, ...) \
	dev_dbg(&(dd)->pcidev->dev, "%s: " fmt, \
		get_unit_name((dd)->unit), ##__VA_ARGS__)

#define hfi1_dev_porterr(dd, port, fmt, ...) \
	dev_err(&(dd)->pcidev->dev, "%s: port %u: " fmt, \
			get_unit_name((dd)->unit), (port), ##__VA_ARGS__)

/*
 * this is used for formatting hw error messages...
 */
struct hfi1_hwerror_msgs {
	u64 mask;
	const char *msg;
	size_t sz;
};

/* in intr.c... */
void hfi1_format_hwerrors(u64 hwerrs,
			  const struct hfi1_hwerror_msgs *hwerrmsgs,
			  size_t nhwerrmsgs, char *msg, size_t lmsg);

#endif /* __HFI1_ORIG__ */
#define USER_OPCODE_CHECK_VAL 0xC0
#define USER_OPCODE_CHECK_MASK 0xC0
#define OPCODE_CHECK_VAL_DISABLED 0x0
#define OPCODE_CHECK_MASK_DISABLED 0x0
#ifdef __HFI1_ORIG__

static inline void hfi1_reset_cpu_counters(struct hfi1_devdata *dd)
{
	struct hfi1_pportdata *ppd;
	int i;

	dd->z_int_counter = get_all_cpu_total(dd->int_counter);
	dd->z_rcv_limit = get_all_cpu_total(dd->rcv_limit);
	dd->z_send_schedule = get_all_cpu_total(dd->send_schedule);

	ppd = (struct hfi1_pportdata *)(dd + 1);
	for (i = 0; i < dd->num_pports; i++, ppd++) {
		ppd->ibport_data.rvp.z_rc_acks =
			get_all_cpu_total(ppd->ibport_data.rvp.rc_acks);
		ppd->ibport_data.rvp.z_rc_qacks =
			get_all_cpu_total(ppd->ibport_data.rvp.rc_qacks);
	}
}

/* Control LED state */
static inline void setextled(struct hfi1_devdata *dd, u32 on)
{
	if (on)
		write_csr(dd, DCC_CFG_LED_CNTRL, 0x1F);
	else
		write_csr(dd, DCC_CFG_LED_CNTRL, 0x10);
}

/* return the i2c resource given the target */
static inline u32 i2c_target(u32 target)
{
	return target ? CR_I2C2 : CR_I2C1;
}

/* return the i2c chain chip resource that this HFI uses for QSFP */
static inline u32 qsfp_resource(struct hfi1_devdata *dd)
{
	return i2c_target(dd->hfi1_id);
}

/* Is this device integrated or discrete? */
static inline bool is_integrated(struct hfi1_devdata *dd)
{
	return dd->pcidev->device == PCI_DEVICE_ID_INTEL1;
}

int hfi1_tempsense_rd(struct hfi1_devdata *dd, struct hfi1_temp *temp);

#define DD_DEV_ENTRY(dd)       __string(dev, dev_name(&(dd)->pcidev->dev))
#define DD_DEV_ASSIGN(dd)      __assign_str(dev, dev_name(&(dd)->pcidev->dev))

#define packettype_name(etype) { RHF_RCV_TYPE_##etype, #etype }
#define show_packettype(etype)                  \
__print_symbolic(etype,                         \
	packettype_name(EXPECTED),              \
	packettype_name(EAGER),                 \
	packettype_name(IB),                    \
	packettype_name(ERROR),                 \
	packettype_name(BYPASS))

#define ib_opcode_name(opcode) { IB_OPCODE_##opcode, #opcode  }
#define show_ib_opcode(opcode)                             \
__print_symbolic(opcode,                                   \
	ib_opcode_name(RC_SEND_FIRST),                     \
	ib_opcode_name(RC_SEND_MIDDLE),                    \
	ib_opcode_name(RC_SEND_LAST),                      \
	ib_opcode_name(RC_SEND_LAST_WITH_IMMEDIATE),       \
	ib_opcode_name(RC_SEND_ONLY),                      \
	ib_opcode_name(RC_SEND_ONLY_WITH_IMMEDIATE),       \
	ib_opcode_name(RC_RDMA_WRITE_FIRST),               \
	ib_opcode_name(RC_RDMA_WRITE_MIDDLE),              \
	ib_opcode_name(RC_RDMA_WRITE_LAST),                \
	ib_opcode_name(RC_RDMA_WRITE_LAST_WITH_IMMEDIATE), \
	ib_opcode_name(RC_RDMA_WRITE_ONLY),                \
	ib_opcode_name(RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE), \
	ib_opcode_name(RC_RDMA_READ_REQUEST),              \
	ib_opcode_name(RC_RDMA_READ_RESPONSE_FIRST),       \
	ib_opcode_name(RC_RDMA_READ_RESPONSE_MIDDLE),      \
	ib_opcode_name(RC_RDMA_READ_RESPONSE_LAST),        \
	ib_opcode_name(RC_RDMA_READ_RESPONSE_ONLY),        \
	ib_opcode_name(RC_ACKNOWLEDGE),                    \
	ib_opcode_name(RC_ATOMIC_ACKNOWLEDGE),             \
	ib_opcode_name(RC_COMPARE_SWAP),                   \
	ib_opcode_name(RC_FETCH_ADD),                      \
	ib_opcode_name(TID_RDMA_WRITE_REQ),	           \
	ib_opcode_name(TID_RDMA_WRITE_RESP),	           \
	ib_opcode_name(TID_RDMA_WRITE_DATA),	           \
	ib_opcode_name(TID_RDMA_WRITE_DATA_LAST),          \
	ib_opcode_name(TID_RDMA_READ_REQ),	           \
	ib_opcode_name(TID_RDMA_READ_RESP),	           \
	ib_opcode_name(TID_RDMA_ACK),                      \
	ib_opcode_name(UC_SEND_FIRST),                     \
	ib_opcode_name(UC_SEND_MIDDLE),                    \
	ib_opcode_name(UC_SEND_LAST),                      \
	ib_opcode_name(UC_SEND_LAST_WITH_IMMEDIATE),       \
	ib_opcode_name(UC_SEND_ONLY),                      \
	ib_opcode_name(UC_SEND_ONLY_WITH_IMMEDIATE),       \
	ib_opcode_name(UC_RDMA_WRITE_FIRST),               \
	ib_opcode_name(UC_RDMA_WRITE_MIDDLE),              \
	ib_opcode_name(UC_RDMA_WRITE_LAST),                \
	ib_opcode_name(UC_RDMA_WRITE_LAST_WITH_IMMEDIATE), \
	ib_opcode_name(UC_RDMA_WRITE_ONLY),                \
	ib_opcode_name(UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE), \
	ib_opcode_name(UD_SEND_ONLY),                      \
	ib_opcode_name(UD_SEND_ONLY_WITH_IMMEDIATE),       \
	ib_opcode_name(CNP))

#endif /* __HFI1_ORIG__ */

/* This include is at the end of this file on purpose,
 * because it needs other structs defined here.
 * Except for static inlines that need these types.
 */
#include <hfi1/hfi1_generated_structs.h>

#define OPA_MAX_SCS                             32 // from opa_smi.h

/**
 * sc_to_vlt() reverse lookup sc to vl
 * @dd - devdata
 * @sc5 - 5 bit sc
 */
static inline u8 sc_to_vlt(struct hfi1_devdata *dd, u8 sc5)
{
	if (sc5 >= OPA_MAX_SCS)
		return (u8)(0xff);

	return *(((u8 *)dd->sc2vl) + sc5);
}

#endif                          /* _HFI1_KERNEL_H */
