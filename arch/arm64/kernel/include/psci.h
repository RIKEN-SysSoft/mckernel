/* psci.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
/* @ref.impl include/uapi/linux/psci.h */
/*
 * ARM Power State and Coordination Interface (PSCI) header
 *
 * This header holds common PSCI defines and macros shared
 * by: ARM kernel, ARM64 kernel, KVM ARM/ARM64 and user space.
 *
 * Copyright (C) 2014 Linaro Ltd.
 * Author: Anup Patel <anup.patel@linaro.org>
 */

#ifndef __HEADER_ARM64_PSCI_H
#define __HEADER_ARM64_PSCI_H

/*
 * PSCI v0.1 interface
 *
 * The PSCI v0.1 function numbers are implementation defined.
 *
 * Only PSCI return values such as: SUCCESS, NOT_SUPPORTED,
 * INVALID_PARAMS, and DENIED defined below are applicable
 * to PSCI v0.1.
 */

/* PSCI v0.2 interface */
#define PSCI_0_2_FN_BASE			0x84000000
#define PSCI_0_2_FN(n)				(PSCI_0_2_FN_BASE + (n))
#define PSCI_0_2_64BIT				0x40000000
#define PSCI_0_2_FN64_BASE			(PSCI_0_2_FN_BASE + PSCI_0_2_64BIT)
#define PSCI_0_2_FN64(n)			(PSCI_0_2_FN64_BASE + (n))

#define PSCI_0_2_FN_PSCI_VERSION		PSCI_0_2_FN(0)
#define PSCI_0_2_FN_CPU_OFF			PSCI_0_2_FN(2)
#define PSCI_0_2_FN64_CPU_ON			PSCI_0_2_FN64(3)
#define PSCI_0_2_FN64_AFFINITY_INFO		PSCI_0_2_FN64(4)

/* PSCI v0.2 power state encoding for CPU_SUSPEND function */
#define PSCI_0_2_POWER_STATE_ID_MASK		0xffff
#define PSCI_0_2_POWER_STATE_ID_SHIFT		0
#define PSCI_0_2_POWER_STATE_TYPE_SHIFT		16
#define PSCI_0_2_POWER_STATE_TYPE_MASK		\
				(0x1 << PSCI_0_2_POWER_STATE_TYPE_SHIFT)
#define PSCI_0_2_POWER_STATE_AFFL_SHIFT		24
#define PSCI_0_2_POWER_STATE_AFFL_MASK		\
				(0x3 << PSCI_0_2_POWER_STATE_AFFL_SHIFT)

/* PSCI version decoding (independent of PSCI version) */
#define PSCI_VERSION_MAJOR_SHIFT		16
#define PSCI_VERSION_MINOR_MASK			\
		((1U << PSCI_VERSION_MAJOR_SHIFT) - 1)
#define PSCI_VERSION_MAJOR_MASK			~PSCI_VERSION_MINOR_MASK
#define PSCI_VERSION_MAJOR(ver)			\
		(((ver) & PSCI_VERSION_MAJOR_MASK) >> PSCI_VERSION_MAJOR_SHIFT)
#define PSCI_VERSION_MINOR(ver)			\
		((ver) & PSCI_VERSION_MINOR_MASK)

/* PSCI return values (inclusive of all PSCI versions) */
#define PSCI_RET_SUCCESS			0
#define PSCI_RET_NOT_SUPPORTED			-1
#define PSCI_RET_INVALID_PARAMS			-2
#define PSCI_RET_DENIED				-3

int psci_init(void);
int psci_cpu_off(void);
int cpu_psci_cpu_boot(unsigned int cpu, unsigned long pc);

#endif /* __HEADER_ARM64_PSCI_H */
