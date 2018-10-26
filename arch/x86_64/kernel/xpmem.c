/* xpmem.c COPYRIGHT FUJITSU LIMITED 2017 */
/**
 * \file xpmem.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Cross Partition Memory (XPMEM) support.
 * \author Yoichi Umezawa  <yoichi.umezawa.qh@hitachi.com> \par
 * 	Copyright (C) 2016 Yoichi Umezawa
 *
 * Original Copyright follows:
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright 2010, 2014 Cray Inc. All Rights Reserved
 * Copyright 2015-2016 Los Alamos National Security, LLC. All rights reserved.
 */
/*
 * HISTORY
 */

#include <cls.h>
#include <ihk/context.h>
#include <xpmem_private.h>

int xpmem_open(const char *pathname,
		int flags, ihk_mc_user_context_t *ctx)
{
	return do_xpmem_open(__NR_open, pathname, flags, ctx);
}
