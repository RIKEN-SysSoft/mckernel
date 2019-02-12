/* sve.h COPYRIGHT FUJITSU LIMITED 2016-2019 */
#ifndef __SVE_H__
#define __SVE_H__

#include <asm/ptrace.h>
#include <asm/sigcontext.h>
#include <sys/types.h>
#include <linux/elf.h>

#define fpsimd_sve_state(vq) {		\
	__uint128_t zregs[32][vq];	\
	unsigned short pregs[16][vq];	\
	unsigned short ffr[vq];		\
}

#define user_fpsimd_sve_state(vq) {		\
	struct user_sve_header header;		\
	struct fpsimd_sve_state(vq) regs;	\
}

/* assembler */
extern void sve_save_state(void *state, unsigned int *pfpsr);
extern void sve_load_state(void const *state, unsigned int const *pfpsr);
extern unsigned int sve_get_vl(void);

/* c */
extern unsigned int gen_set_vl(const unsigned int vl);
extern int get_and_compare_vl(const unsigned long exp_arg);
extern int set_and_compare_vl(const unsigned long set_arg);
extern void gen_test_sve(void *buf, unsigned int vq);
extern void gen_test_sve_low_128(void *buf, unsigned int bf_vq, unsigned int af_vq);
extern void gen_test_fpsimd(struct user_fpsimd_state *buf, unsigned int vq);
extern void gen_test_sve_dirty(void *buf, unsigned int vq);
extern void write_sve(void *buf, unsigned int vq, unsigned int *fpscr);
extern void read_sve(void *buf, unsigned int vq, unsigned int *fpscr);
extern void show_sve(const void *buf, unsigned int vq, unsigned int *fpscr);
extern void read_and_show_sve(void *buf, unsigned int vq, unsigned int *fpscr);
extern int header_compare(const struct user_sve_header *target);
extern int sve_compare(const void *expect, const void *target, unsigned int vq);
extern int fpsimd_compare(const struct user_fpsimd_state *expect, const struct user_fpsimd_state *target, size_t n);
extern void read_fpsimd(struct user_fpsimd_state *regs);

/* arm64 Scalable Vector Extension controls */
# define PR_SVE_INVALID_FLAGS		(1 << 19)	/* invalid flag */

# define PR_SVE_GET_VL_FLAGS(ret)	((ret) & ~PR_SVE_VL_LEN_MASK)	/* sve_flags */
# define PR_SVE_GET_VL_LEN(ret)		((ret) & PR_SVE_VL_LEN_MASK)	/* vector length */

/* Definitions for user_sve_header.flags: */
#define SVE_PT_INVALID_FLAGS		(1 << 3)	/* invalid flag */

/*
 * SVE_MAX defines
 */
#define SVE_VQ_MIN	1
#define SVE_NUM_ZREGS	32
#define SVE_NUM_PREGS	16

#define VL_128_BIT	0x10 /* 16 byte */
#define VL_256_BIT	0x20 /* 32 byte */
#define VL_512_BIT	0x40 /* 64 byte */

#define VQ_128_BIT	sve_vq_from_vl(VL_128_BIT)
#define VQ_256_BIT	sve_vq_from_vl(VL_256_BIT)
#define VQ_512_BIT	sve_vq_from_vl(VL_512_BIT)

#define UNSPPORT_VL	(384 / 0x10)

#define INVALID_VL_1	(0)
#define INVALID_VL_2	(SVE_VL_MIN - 0x01)
#define INVALID_VL_3	(SVE_VL_MAX + 0x10)

#endif /* __SVE_H__ */
