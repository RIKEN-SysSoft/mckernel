/* vdso.so.S COPYRIGHT FUJITSU LIMITED 2016 */
/* @ref.impl arch/arm64/kernel/vdso/vdso.S */
/*
 * Copyright (C) 2012 ARM Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Will Deacon <will.deacon@arm.com>
 */

#include <arch-memory.h>
#include <vdso-so-path.h>

	.section ".vdso.txet", "aw"

	.globl vdso_start, vdso_end
	.balign PAGE_SIZE
vdso_start:
	.incbin VDSO_SO_PATH
	.balign PAGE_SIZE
vdso_end:

	.previous
