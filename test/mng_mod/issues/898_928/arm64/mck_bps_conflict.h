/* mck_bps_conflict.h COPYRIGHT FUJITSU LIMITED 2018 */
#ifndef _MCK_BPS_CONFLICT_H
#define _MCK_BPS_CONFLICT_H

#define MCK_DIR "/opt/ppos"

#ifdef __aarch64__
#define ARCH "arm64"
#define TARGET "smp-arm64"
#define PART_MOD_NAME "ihk-smp-arm64.ko"
#define PART_MOD_PARAM "ihk_nr_irq=4 ihk_start_irq=60"
#define TARGET "smp-arm64"
#elif defined(__x86_64__)
#define ARCH "x86_64"
#define TARGET "smp-x86"
#define PART_MOD_NAME "ihk-smp-x86_64.ko"
#define PART_MOD_PARAM "ihk_start_irq=240 ihk_ikc_irq_core=0"
#define TARGET "smp-x86"
#else
#error "Non-compliant architecture."
#endif

#endif /* _MCK_BPS_CONFLICT_H */
