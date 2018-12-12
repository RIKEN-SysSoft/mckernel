/**
 * \file prctl.h
 *  License details are found in the file LICENSE.
 */
/*
 * HISTORY
 */

#ifndef __ARCH_PRCTL_H
#define __ARCH_PRCTL_H

#define PR_SET_THP_DISABLE 41
#define PR_GET_THP_DISABLE 42

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

#endif
