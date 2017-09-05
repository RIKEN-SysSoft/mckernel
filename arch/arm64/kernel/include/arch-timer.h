/* arch-timer.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef __HEADER_ARM64_COMMON_ARCH_TIMER_H
#define __HEADER_ARM64_COMMON_ARCH_TIMER_H

/* @ref.impl include/clocksource/arm_arch_timer.h */
#define ARCH_TIMER_USR_PCT_ACCESS_EN	(1 << 0)	/* physical counter */
#define ARCH_TIMER_USR_VCT_ACCESS_EN	(1 << 1)	/* virtual counter */
#define ARCH_TIMER_VIRT_EVT_EN		(1 << 2)
#define ARCH_TIMER_EVT_TRIGGER_SHIFT	(4)
#define ARCH_TIMER_EVT_TRIGGER_MASK	(0xF << ARCH_TIMER_EVT_TRIGGER_SHIFT)
#define ARCH_TIMER_USR_VT_ACCESS_EN	(1 << 8)	/* virtual timer registers */
#define ARCH_TIMER_USR_PT_ACCESS_EN	(1 << 9)	/* physical timer registers */

#endif	/* __HEADER_ARM64_COMMON_ARCH_TIMER_H */
