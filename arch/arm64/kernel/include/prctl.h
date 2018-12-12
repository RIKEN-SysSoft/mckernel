/* prctl.h COPYRIGHT FUJITSU LIMITED 2017 */
#ifndef __HEADER_ARM64_COMMON_PRCTL_H
#define __HEADER_ARM64_COMMON_PRCTL_H

#define PR_SET_THP_DISABLE 41
#define PR_GET_THP_DISABLE 42

/* arm64 Scalable Vector Extension controls */
#define PR_SVE_SET_VL		48			/* set task vector length */
#define PR_SVE_SET_VL_THREAD	(1 << 1)		/* set just this thread */
#define PR_SVE_SET_VL_INHERIT	(1 << 2)		/* inherit across exec */
#define PR_SVE_SET_VL_ONEXEC	(1 << 3)		/* defer effect until exec */

#define PR_SVE_GET_VL		49			/* get task vector length */
/* Decode helpers for the return value from PR_SVE_GET_VL: */
#define PR_SVE_GET_VL_LEN(ret)	((ret) & 0x3fff)	/* vector length */
#define PR_SVE_GET_VL_INHERIT	(PR_SVE_SET_VL_INHERIT << 16)
/* For conveinence, PR_SVE_SET_VL returns the result in the same encoding */

#endif /* !__HEADER_ARM64_COMMON_PRCTL_H */
