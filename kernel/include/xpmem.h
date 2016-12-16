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

extern int xpmem_open(ihk_mc_user_context_t *ctx);

#endif /* _XPMEM_H */

