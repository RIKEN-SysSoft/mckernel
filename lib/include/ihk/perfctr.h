/**
 * \file perfctr.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare type and functions to manipulate performance counters. 
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef HEADER_GENERIC_IHK_PERFCTR_H
#define HEADER_GENERIC_IHK_PERFCTR_H

#define PERFCTR_USER_MODE   0x01
#define PERFCTR_KERNEL_MODE 0x02

enum ihk_perfctr_type {
	APT_TYPE_DATA_PAGE_WALK,
	APT_TYPE_DATA_READ_MISS,
	APT_TYPE_DATA_WRITE_MISS,
    APT_TYPE_BANK_CONFLICTS,
	APT_TYPE_CODE_CACHE_MISS,
	APT_TYPE_INSTRUCTIONS_EXECUTED,
	APT_TYPE_INSTRUCTIONS_EXECUTED_V_PIPE,

	APT_TYPE_L2_READ_MISS,
	APT_TYPE_L2_CODE_READ_MISS_CACHE_FILL,
	APT_TYPE_L2_DATA_READ_MISS_CACHE_FILL,
	APT_TYPE_L2_CODE_READ_MISS_MEM_FILL,
	APT_TYPE_L2_DATA_READ_MISS_MEM_FILL,

	APT_TYPE_L1D_REQUEST,
	APT_TYPE_L1I_REQUEST,
	APT_TYPE_L1_MISS,
	APT_TYPE_LLC_MISS,
	APT_TYPE_DTLB_MISS,
	APT_TYPE_ITLB_MISS,
	APT_TYPE_STALL,
	APT_TYPE_CYCLE,

        APT_TYPE_INSTRUCTIONS,
        APT_TYPE_L1D_MISS,
        APT_TYPE_L1I_MISS,
        APT_TYPE_L2_MISS,

	PERFCTR_MAX_TYPE,
};

int ihk_mc_perfctr_init(int counter, enum ihk_perfctr_type type, int mode);
int ihk_mc_perfctr_init_raw(int counter, unsigned int code, int mode);
int ihk_mc_perfctr_start(unsigned long counter_mask);
int ihk_mc_perfctr_stop(unsigned long counter_mask);
int ihk_mc_perfctr_fixed_init(int counter, int mode);
int ihk_mc_perfctr_reset(int counter);
int ihk_mc_perfctr_set(int counter, long value);
int ihk_mc_perfctr_read_mask(unsigned long counter_mask, unsigned long *value);
unsigned long ihk_mc_perfctr_read(int counter);
unsigned long ihk_mc_perfctr_read_msr(int counter);
int ihk_mc_perfctr_alloc_counter(unsigned int *type, unsigned long *config, unsigned long pmc_status);

#endif

