/* fpsimdmacros.h COPYRIGHT FUJITSU LIMITED 2016-2017 */

.macro _check_reg nr
	.if (\nr) < 0 || (\nr) > 31
		.error "Bad register number \nr."
	.endif
.endm

.macro _check_zreg znr
	.if (\znr) < 0 || (\znr) > 31
		.error "Bad Scalable Vector Extension vector register number \znr."
	.endif
.endm

.macro _check_preg pnr
	.if (\pnr) < 0 || (\pnr) > 15
		.error "Bad Scalable Vector Extension predicate register number \pnr."
	.endif
.endm

.macro _check_num n, min, max
	.if (\n) < (\min) || (\n) > (\max)
		.error "Number \n out of range [\min,\max]"
	.endif
.endm

.macro _zstrv znt, nspb, ioff=0
	_check_zreg \znt
	_check_reg \nspb
	_check_num (\ioff), -0x100, 0xff
	.inst	0xe5804000			\
		| (\znt)			\
		| ((\nspb) << 5)		\
		| (((\ioff) & 7) << 10)		\
		| (((\ioff) & 0x1f8) << 13)
.endm

.macro _zldrv znt, nspb, ioff=0
	_check_zreg \znt
	_check_reg \nspb
	_check_num (\ioff), -0x100, 0xff
	.inst	0x85804000			\
		| (\znt)			\
		| ((\nspb) << 5)		\
		| (((\ioff) & 7) << 10)		\
		| (((\ioff) & 0x1f8) << 13)
.endm

.macro _zstrp pnt, nspb, ioff=0
	_check_preg \pnt
	_check_reg \nspb
	_check_num (\ioff), -0x100, 0xff
	.inst	0xe5800000			\
		| (\pnt)			\
		| ((\nspb) << 5)		\
		| (((\ioff) & 7) << 10)		\
		| (((\ioff) & 0x1f8) << 13)
.endm

.macro _zldrp pnt, nspb, ioff=0
	_check_preg \pnt
	_check_reg \nspb
	_check_num (\ioff), -0x100, 0xff
	.inst	0x85800000			\
		| (\pnt)			\
		| ((\nspb) << 5)		\
		| (((\ioff) & 7) << 10)		\
		| (((\ioff) & 0x1f8) << 13)
.endm

.macro _zrdvl nspd, is1
	_check_reg \nspd
	_check_num (\is1), -0x20, 0x1f
	.inst	0x04bf5000			\
		| (\nspd)			\
		| (((\is1) & 0x3f) << 5)
.endm

.macro _zrdffr pnd
	_check_preg \pnd
	.inst	0x2519f000			\
		| (\pnd)
.endm

.macro _zwrffr pnd
	_check_preg \pnd
	.inst	0x25289000			\
		| ((\pnd) << 5)
.endm

.macro for from, to, insn
	.if (\from) >= (\to)
		\insn	(\from)
		.exitm
	.endif

	for \from, ((\from) + (\to)) / 2, \insn
	for ((\from) + (\to)) / 2 + 1, \to, \insn
.endm

.macro sve_save nb, xpfpsr, ntmp
	.macro savez n
		_zstrv	\n, \nb, (\n) - 34
	.endm

	.macro savep n
		_zstrp	\n, \nb, (\n) - 16
	.endm

	for	0, 31, savez
	for	0, 15, savep
	_zrdffr	0
	_zstrp	0, \nb
	_zldrp	0, \nb, -16

	mrs	x\ntmp, fpsr
	str	w\ntmp, [\xpfpsr]
	mrs	x\ntmp, fpcr
	str	w\ntmp, [\xpfpsr, #4]

	.purgem savez
	.purgem savep
.endm

.macro sve_load nb, xpfpsr, xvqminus1 ntmp
	mrs_s	x\ntmp, SYS_ZCR_EL1
	bic	x\ntmp, x\ntmp, ZCR_EL1_LEN_MASK
	orr	x\ntmp, x\ntmp, \xvqminus1
	msr_s	SYS_ZCR_EL1, x\ntmp // self-synchronising

	.macro loadz n	
		_zldrv	\n, \nb, (\n) - 34
	.endm

	.macro loadp n
		_zldrp	\n, \nb, (\n) - 16
	.endm

	for	0, 31, loadz
	_zldrp	0, \nb
	_zwrffr	0
	for	0, 15, loadp

	ldr	w\ntmp, [\xpfpsr]
	msr	fpsr, x\ntmp
	ldr	w\ntmp, [\xpfpsr, #4]
	msr	fpcr, x\ntmp

	.purgem loadz
	.purgem loadp
.endm
