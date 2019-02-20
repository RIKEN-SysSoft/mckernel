/* sve_asm.S COPYRIGHT FUJITSU LIMITED 2016-2019 */
.globl load_z31
load_z31:
	.cpu cortex-a53+fp+simd+sve
	ldr z31, [x0]
	ret
.type load_z31, @function
.size load_z31, .-load_z31

.globl store_z31
store_z31:
	add z31.d, z31.d,#1
	str z31, [x0]
	ret
.type store_z31, @function
.size store_z31, .-store_z31

/* void sve_save_state(void *state, unsigned int *pfpsr); */
.globl sve_load_state
.align 4
sve_load_state:
	/* load z register */
	ldr	z0, [x0,#-34,mul vl]
	ldr	z1, [x0,#-33,mul vl]
	ldr	z2, [x0,#-32,mul vl]
	ldr	z3, [x0,#-31,mul vl]
	ldr	z4, [x0,#-30,mul vl]
	ldr	z5, [x0,#-29,mul vl]
	ldr	z6, [x0,#-28,mul vl]
	ldr	z7, [x0,#-27,mul vl]
	ldr	z8, [x0,#-26,mul vl]
	ldr	z9, [x0,#-25,mul vl]
	ldr	z10, [x0,#-24,mul vl]
	ldr	z11, [x0,#-23,mul vl]
	ldr	z12, [x0,#-22,mul vl]
	ldr	z13, [x0,#-21,mul vl]
	ldr	z14, [x0,#-20,mul vl]
	ldr	z15, [x0,#-19,mul vl]
	ldr	z16, [x0,#-18,mul vl]
	ldr	z17, [x0,#-17,mul vl]
	ldr	z18, [x0,#-16,mul vl]
	ldr	z19, [x0,#-15,mul vl]
	ldr	z20, [x0,#-14,mul vl]
	ldr	z21, [x0,#-13,mul vl]
	ldr	z22, [x0,#-12,mul vl]
	ldr	z23, [x0,#-11,mul vl]
	ldr	z24, [x0,#-10,mul vl]
	ldr	z25, [x0,#-9,mul vl]
	ldr	z26, [x0,#-8,mul vl]
	ldr	z27, [x0,#-7,mul vl]
	ldr	z28, [x0,#-6,mul vl]
	ldr	z29, [x0,#-5,mul vl]
	ldr	z30, [x0,#-4,mul vl]
	ldr	z31, [x0,#-3,mul vl]

	/* write ffr */
	ldr	p0, [x0]
	wrffr	p0.b

	/* load p register */
	ldr	p0, [x0,#-16,mul vl]
	ldr	p1, [x0,#-15,mul vl]
	ldr	p2, [x0,#-14,mul vl]
	ldr	p3, [x0,#-13,mul vl]
	ldr	p4, [x0,#-12,mul vl]
	ldr	p5, [x0,#-11,mul vl]
	ldr	p6, [x0,#-10,mul vl]
	ldr	p7, [x0,#-9,mul vl]
	ldr	p8, [x0,#-8,mul vl]
	ldr	p9, [x0,#-7,mul vl]
	ldr	p10, [x0,#-6,mul vl]
	ldr	p11, [x0,#-5,mul vl]
	ldr	p12, [x0,#-4,mul vl]
	ldr	p13, [x0,#-3,mul vl]
	ldr	p14, [x0,#-2,mul vl]
	ldr	p15, [x0,#-1,mul vl]

	/* write fpsr */
	ldr	w2, [x1]
	msr	fpsr, x2

	/* write fpcr */
	ldr	w2, [x1,#4]
	msr	fpcr, x2

	ret
.type sve_load_state, @function
.size sve_load_state, .-sve_load_state

/* void sve_load_state(void const *state, unsigned int const *pfpsr); */
.globl sve_save_state
.align 4
sve_save_state:
	/* store z register */
	str	z0, [x0,#-34,mul vl]
	str	z1, [x0,#-33,mul vl]
	str	z2, [x0,#-32,mul vl]
	str	z3, [x0,#-31,mul vl]
	str	z4, [x0,#-30,mul vl]
	str	z5, [x0,#-29,mul vl]
	str	z6, [x0,#-28,mul vl]
	str	z7, [x0,#-27,mul vl]
	str	z8, [x0,#-26,mul vl]
	str	z9, [x0,#-25,mul vl]
	str	z10, [x0,#-24,mul vl]
	str	z11, [x0,#-23,mul vl]
	str	z12, [x0,#-22,mul vl]
	str	z13, [x0,#-21,mul vl]
	str	z14, [x0,#-20,mul vl]
	str	z15, [x0,#-19,mul vl]
	str	z16, [x0,#-18,mul vl]
	str	z17, [x0,#-17,mul vl]
	str	z18, [x0,#-16,mul vl]
	str	z19, [x0,#-15,mul vl]
	str	z20, [x0,#-14,mul vl]
	str	z21, [x0,#-13,mul vl]
	str	z22, [x0,#-12,mul vl]
	str	z23, [x0,#-11,mul vl]
	str	z24, [x0,#-10,mul vl]
	str	z25, [x0,#-9,mul vl]
	str	z26, [x0,#-8,mul vl]
	str	z27, [x0,#-7,mul vl]
	str	z28, [x0,#-6,mul vl]
	str	z29, [x0,#-5,mul vl]
	str	z30, [x0,#-4,mul vl]
	str	z31, [x0,#-3,mul vl]

	/* store p register */
	str	p0, [x0,#-16,mul vl]
	str	p1, [x0,#-15,mul vl]
	str	p2, [x0,#-14,mul vl]
	str	p3, [x0,#-13,mul vl]
	str	p4, [x0,#-12,mul vl]
	str	p5, [x0,#-11,mul vl]
	str	p6, [x0,#-10,mul vl]
	str	p7, [x0,#-9,mul vl]
	str	p8, [x0,#-8,mul vl]
	str	p9, [x0,#-7,mul vl]
	str	p10, [x0,#-6,mul vl]
	str	p11, [x0,#-5,mul vl]
	str	p12, [x0,#-4,mul vl]
	str	p13, [x0,#-3,mul vl]
	str	p14, [x0,#-2,mul vl]
	str	p15, [x0,#-1,mul vl]

	/* read ffr */
	rdffr	p0.b
	str	p0, [x0]
	ldr	p0, [x0,#-16,mul vl]

	/* read fpsr */
	mrs	x2, fpsr
	str	w2, [x1]

	/* read fpcr */
	mrs	x2, fpcr
	str	w2, [x1,#4]

	ret
.type sve_save_state, @function
.size sve_save_state, .-sve_save_state

/* unsigned int sve_get_vl(void); */
.globl sve_get_vl
.align 4
sve_get_vl:
	rdvl	x0, #1
	ret
.type sve_get_vl, @function
.size sve_get_vl, .-sve_get_vl
