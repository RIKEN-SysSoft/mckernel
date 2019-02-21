/* prctl.h COPYRIGHT FUJITSU LIMITED 2017-2019 */
#ifndef __HEADER_ARM64_COMMON_PRCTL_H
#define __HEADER_ARM64_COMMON_PRCTL_H

#define PR_SET_THP_DISABLE 41
#define PR_GET_THP_DISABLE 42

/* arm64 Scalable Vector Extension controls */
/* Flag values must be kept in sync with ptrace NT_ARM_SVE interface */
#define PR_SVE_SET_VL		50		/* set task vector length */
# define PR_SVE_SET_VL_ONEXEC	(1 << 18)	/* defer effect until exec */
#define PR_SVE_GET_VL		51		/* get task vector length */
/* Bits common to PR_SVE_SET_VL and PR_SVE_GET_VL */
# define PR_SVE_VL_LEN_MASK	0xffff
# define PR_SVE_VL_INHERIT	(1 << 17)	/* inherit across exec */

#endif /* !__HEADER_ARM64_COMMON_PRCTL_H */
