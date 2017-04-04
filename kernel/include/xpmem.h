/**
 * \file xpmem.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Structures and functions of xpmem
 */
/*
 * HISTORY
 */

#ifndef _XPMEM_H
#define _XPMEM_H

#include <ihk/context.h>

#define XPMEM_DEV_PATH  "/dev/xpmem"

#if defined(POSTK_DEBUG_ARCH_DEP_46) || defined(POSTK_DEBUG_ARCH_DEP_62)
extern int xpmem_open(int, const char*, int, ihk_mc_user_context_t *ctx);
#else /* POSTK_DEBUG_ARCH_DEP_46 || POSTK_DEBUG_ARCH_DEP_62 */
extern int xpmem_open(ihk_mc_user_context_t *ctx);
#endif /* POSTK_DEBUG_ARCH_DEP_46 || POSTK_DEBUG_ARCH_DEP_62 */

#endif /* _XPMEM_H */

