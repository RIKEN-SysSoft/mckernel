#ifndef _TOF_ICC_H_
#define _TOF_ICC_H_

#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/bitops.h>
#else
#include <stdint.h>
typedef uint64_t phys_addr_t;
#endif

/* constants related to the Tofu Interconnect D */

#define TOF_ICC_NTNIS 6
#define TOF_ICC_NCQS 12
#define TOF_ICC_NBGS 48
#define TOF_ICC_NBCHS 16
#define TOF_ICC_NPORTS 10
#define TOF_ICC_NVMSIDS 16

#define TOF_ICC_RH_LEN 8
#define TOF_ICC_ECRC_LEN 4
#define TOF_ICC_FRAME_ALIGN 32
#define TOF_ICC_TLP_LEN(len) (((len) + 1) * TOF_ICC_FRAME_ALIGN)
#define TOF_ICC_TLP_PAYLOAD_MAX (TOF_ICC_TLP_LEN(61) - TOF_ICC_ECRC_LEN)
#define TOF_ICC_FRAME_LEN(len) (TOF_ICC_RH_LEN + TOF_ICC_TLP_LEN(len))
#define TOF_ICC_FRAME_LEN_MIN TOF_ICC_FRAME_LEN(2)
#define TOF_ICC_FRAME_LEN_MAX TOF_ICC_FRAME_LEN(61)
#define TOF_ICC_FRAME_BUF_SIZE_BITS 11
#define TOF_ICC_FRAME_BUF_SIZE (1 << TOF_ICC_FRAME_BUF_SIZE_BITS)
#define TOF_ICC_FRAME_BUF_ALIGN_BITS 8
#define TOF_ICC_FRAME_BUF_ALIGN (1 << TOF_ICC_FRAME_BUF_ALIGN_BITS)
#define TOF_ICC_PB_SIZE_BITS 11
#define TOF_ICC_PB_SIZE (1 << TOF_ICC_PB_SIZE_BITS)
#define TOF_ICC_PB_ALIGN_BITS 11
#define TOF_ICC_PB_ALIGN (1 << TOF_ICC_PB_ALIGN_BITS)

#define TOF_ICC_ST_ALIGN_BITS 8
#define TOF_ICC_ST_ALIGN (1 << TOF_ICC_ST_ALIGN_BITS)

#define TOF_ICC_MBT_ALIGN_BITS 8
#define TOF_ICC_MBT_ALIGN (1 << TOF_ICC_MBT_ALIGN_BITS)

#define TOF_ICC_MBPT_ALIGN_BITS 8
#define TOF_ICC_MBPT_ALIGN (1 << TOF_ICC_MBPT_ALIGN_BITS)

#define TOF_ICC_BG_BSEQ_SIZE_BITS 24
#define TOF_ICC_BG_BSEQ_SIZE (1 << TOF_ICC_BG_BSEQ_SIZE_BITS)

#define TOF_ICC_BCH_DMA_ALIGN_BITS 8
#define TOF_ICC_BCH_DMA_ALIGN (1 << TOF_ICC_BCH_DMA_ALIGN_BITS)

/* this is a CPU-specific constant, but referred in the ICC spec. */
#define TOF_ICC_CACHE_LINE_SIZE_BITS 8
#define TOF_ICC_CACHE_LINE_SIZE (1 << TOF_ICC_CACHE_LINE_SIZE_BITS)

#define TOF_ICC_TOQ_DESC_SIZE_BITS 5
#define TOF_ICC_TOQ_DESC_SIZE (1 << TOF_ICC_TOQ_DESC_SIZE_BITS)
#define TOF_ICC_TCQ_DESC_SIZE_BITS 3
#define TOF_ICC_TCQ_DESC_SIZE (1 << TOF_ICC_TCQ_DESC_SIZE_BITS)
#define TOF_ICC_TCQ_NLINE_BITS (TOF_ICC_CACHE_LINE_SIZE_BITS - TOF_ICC_TCQ_DESC_SIZE_BITS)
#define TOF_ICC_MRQ_DESC_SIZE_BITS 5
#define TOF_ICC_MRQ_DESC_SIZE (1 << TOF_ICC_MRQ_DESC_SIZE_BITS)
#define TOF_ICC_PBQ_DESC_SIZE_BITS 3
#define TOF_ICC_PBQ_DESC_SIZE (1 << TOF_ICC_PBQ_DESC_SIZE_BITS)
#define TOF_ICC_PRQ_DESC_SIZE_BITS 3
#define TOF_ICC_PRQ_DESC_SIZE (1 << TOF_ICC_PRQ_DESC_SIZE_BITS)
#define TOF_ICC_PRQ_NLINE_BITS (TOF_ICC_CACHE_LINE_SIZE_BITS - TOF_ICC_PBQ_DESC_SIZE_BITS)

#define TOF_ICC_TOQ_SIZE_NTYPES 6
#define TOF_ICC_TOQ_SIZE_BITS(size) ((size) * 2 + 11)
#define TOF_ICC_TOQ_SIZE(size) (1 << TOF_ICC_TOQ_SIZE_BITS(size))
#define TOF_ICC_TOQ_LEN(size) (TOF_ICC_TOQ_SIZE(size) * TOF_ICC_TOQ_DESC_SIZE)
#define TOF_ICC_TCQ_LEN(size) (TOF_ICC_TOQ_SIZE(size) * TOF_ICC_TCQ_DESC_SIZE)

#define TOF_ICC_MRQ_SIZE_NTYPES 6
#define TOF_ICC_MRQ_SIZE_BITS(size) ((size) * 2 + 11)
#define TOF_ICC_MRQ_SIZE(size) (1 << TOF_ICC_MRQ_SIZE_BITS(size))
#define TOF_ICC_MRQ_LEN(size) (TOF_ICC_MRQ_SIZE(size) * TOF_ICC_MRQ_DESC_SIZE)

#define TOF_ICC_PBQ_SIZE_NTYPES 6
#define TOF_ICC_PBQ_SIZE_BITS(size) ((size) * 2 + 11)
#define TOF_ICC_PBQ_SIZE(size) (1 << TOF_ICC_PBQ_SIZE_BITS(size))
#define TOF_ICC_PBQ_LEN(size) (TOF_ICC_PBQ_SIZE(size) * TOF_ICC_PBQ_DESC_SIZE)

#define TOF_ICC_PRQ_SIZE_NTYPES 6
#define TOF_ICC_PRQ_SIZE_BITS(size) ((size) * 2 + 11)
#define TOF_ICC_PRQ_SIZE(size) (1 << TOF_ICC_PRQ_SIZE_BITS(size))
#define TOF_ICC_PRQ_LEN(size) (TOF_ICC_PRQ_SIZE(size) * TOF_ICC_PRQ_DESC_SIZE)

#define TOF_ICC_STEERING_TABLE_ALIGN_BITS 8
#define TOF_ICC_STEERING_TABLE_ALIGN (1 << TOF_ICC_STEERING_TABLE_ALIGN_BITS)
#define TOF_ICC_STEERING_SIZE_BITS 4
#define TOF_ICC_STEERING_SIZE (1 << TOF_ICC_STEERING_SIZE_BITS)

#define TOF_ICC_MB_TABLE_ALIGN_BITS 8
#define TOF_ICC_MB_TABLE_ALIGN (1 << TOF_ICC_MB_TABLE_ALIGN_BITS)
#define TOF_ICC_MB_SIZE_BITS 4
#define TOF_ICC_MB_SIZE (1 << TOF_ICC_MB_SIZE_BITS)
#define TOF_ICC_MB_PS_ENCODE(bits) ((bits) % 9 == 3 ? (bits) / 9 - 1 : (bits) / 13 + 3)

#define TOF_ICC_MBPT_ALIGN_BITS 8
#define TOF_ICC_MBPT_ALIGN (1 << TOF_ICC_MBPT_ALIGN_BITS)
#define TOF_ICC_MBPT_SIZE_BITS 3
#define TOF_ICC_MBPT_SIZE (1 << TOF_ICC_MBPT_SIZE_BITS)

#define TOF_ICC_X_BITS 5
#define TOF_ICC_Y_BITS 5
#define TOF_ICC_Z_BITS 5
#define TOF_ICC_A_BITS 1
#define TOF_ICC_B_BITS 2
#define TOF_ICC_C_BITS 1
#define TOF_ICC_MAX_X_SIZE (1 << TOF_ICC_X_BITS)
#define TOF_ICC_MAX_Y_SIZE (1 << TOF_ICC_Y_BITS)
#define TOF_ICC_MAX_Z_SIZE (1 << TOF_ICC_Z_BITS)
#define TOF_ICC_A_SIZE 2
#define TOF_ICC_B_SIZE 3
#define TOF_ICC_C_SIZE 2
#define TOF_ICC_X_MASK ((1 << TOF_ICC_X_BITS) - 1)
#define TOF_ICC_Y_MASK ((1 << TOF_ICC_Y_BITS) - 1)
#define TOF_ICC_Z_MASK ((1 << TOF_ICC_Z_BITS) - 1)
#define TOF_ICC_A_MASK ((1 << TOF_ICC_A_BITS) - 1)
#define TOF_ICC_B_MASK ((1 << TOF_ICC_B_BITS) - 1)
#define TOF_ICC_C_MASK ((1 << TOF_ICC_C_BITS) - 1)
#define TOF_ICC_ABC_SIZE (TOF_ICC_A_SIZE * TOF_ICC_B_SIZE * TOF_ICC_C_SIZE)

#ifdef __KERNEL__
static inline int tof_icc_get_framelen(int len){
	len = TOF_ICC_RH_LEN + round_up(len + TOF_ICC_ECRC_LEN, TOF_ICC_FRAME_ALIGN);
	if(len < TOF_ICC_FRAME_LEN_MIN){
		len = TOF_ICC_FRAME_LEN_MIN;
	}
	return len;
}
#endif

/** Descriptors **/
/** commands and rcodes **/
enum {
	TOF_ICC_TOQ_NOP,
	TOF_ICC_TOQ_PUT,
	TOF_ICC_TOQ_WRITE_PIGGYBACK_BUFFER,
	TOF_ICC_TOQ_PUT_PIGGYBACK,
	TOF_ICC_TOQ_GET,
	TOF_ICC_TOQ_GETL,
	TOF_ICC_TOQ_ATOMIC_READ_MODIFY_WRITE = 0xe,
	TOF_ICC_TOQ_TRANSMIT_RAW_PACKET1 = 0x10,
	TOF_ICC_TOQ_TRANSMIT_RAW_PACKET2,
	TOF_ICC_TOQ_TRANSMIT_SYSTEM_PACKET1,
	TOF_ICC_TOQ_TRANSMIT_SYSTEM_PACKET2,

	TOF_ICC_TOQ_NCOMMANDS,
};

enum {
	TOF_ICC_MRQ_ATOMIC_READ_MODIFY_WRITE_HALFWAY_NOTICE = 0x1,
	TOF_ICC_MRQ_ATOMIC_READ_MODIFY_WRITE_NOTICE,
	TOF_ICC_MRQ_ATOMIC_READ_MODIFY_WRITE_REMOTE_ERROR,
	TOF_ICC_MRQ_PUT_HALFWAY_NOTICE,
	TOF_ICC_MRQ_PUT_LAST_HALFWAY_NOTICE,
	TOF_ICC_MRQ_GET_HALFWAY_NOTICE,
	TOF_ICC_MRQ_GET_LAST_HALFWAY_NOTICE,
	TOF_ICC_MRQ_PUT_NOTICE,
	TOF_ICC_MRQ_PUT_LAST_NOTICE,
	TOF_ICC_MRQ_GET_NOTICE,
	TOF_ICC_MRQ_GET_LAST_NOTICE,
	TOF_ICC_MRQ_PUT_REMOTE_ERROR,
	TOF_ICC_MRQ_PUT_LAST_REMOTE_ERROR,
	TOF_ICC_MRQ_GET_REMOTE_ERROR,
	TOF_ICC_MRQ_GET_LAST_REMOTE_ERROR,

	TOF_ICC_MRQ_NCOMMANDS,
};

enum {
	TOF_ICC_PRQ_UNKNOWN_TLP,
	TOF_ICC_PRQ_SYSTEM_TLP,
	TOF_ICC_PRQ_ADDRESS_RANGE_EXCEPTION = 0x6,
	TOF_ICC_PRQ_CQ_EXCEPTION = 0x8,
	TOF_ICC_PRQ_ILLEGAL_TLP_FLAGS,
	TOF_ICC_PRQ_ILLEGAL_TLP_LENGTH,
	TOF_ICC_PRQ_CQ_ERROR = 0xc,
};

/** structures **/
struct tof_icc_steering_entry {
	uint64_t res1:6;
	uint64_t readonly:1;
	uint64_t enable:1;
	uint64_t mbva:32;
	uint64_t res2:8;
	uint64_t mbid:16;
	uint64_t length;  /* for optimization */
};

struct tof_icc_mb_entry {
	uint64_t ps:2;
	uint64_t res1:5;
	uint64_t enable:1;
	uint64_t ipa:32;
	uint64_t res2:24;
	uint64_t npage;  /* for optimization */
};

struct tof_icc_mbpt_entry {
	uint64_t res1:7;
	uint64_t enable:1;
	uint64_t res2:4;
	uint64_t ipa:28;
	uint64_t res3:24;
};

struct tof_icc_cq_stag_offset {
	uint64_t offset:40;
	uint64_t stag:18;
	uint64_t cqid:6;
};

struct tof_icc_toq_common_header1 {
	uint8_t interrupt:1;
	uint8_t res1:4;
	uint8_t source_type:2;
	uint8_t flip:1;
	uint8_t command;
	union {
		uint8_t mtu;
		struct {
			uint8_t res:4;
			uint8_t op:4;
		} armw;
	} mtuop;
	uint8_t sps:4;
	uint8_t pa:1;
	uint8_t pb:2;
	uint8_t pc:1;
	uint8_t rx;
	uint8_t ry;
	uint8_t rz;
	uint8_t ra:1;
	uint8_t rb:2;
	uint8_t rc:1;
	uint8_t res3:1;
	uint8_t ri:3;
};

struct tof_icc_toq_common_header2 {
	uint8_t gap;
	uint8_t s:1;
	uint8_t r:1;
	uint8_t q:1;
	uint8_t p:1;
	uint8_t res1:1;
	uint8_t j:1;
	uint8_t res2:2;
	uint16_t edata;
	union{
		struct {
			uint32_t length:24;
			uint32_t res:8;
		} normal;
		struct {
			uint32_t length:6;
			uint32_t res:26;
		} piggyback;
	} len;
};

struct tof_icc_toq_descriptor {
	struct tof_icc_toq_common_header1 head1;
	uint64_t res[3];
};

struct tof_icc_toq_nop {
	struct tof_icc_toq_common_header1 head1;
	uint64_t res[3];
};

struct tof_icc_toq_put {
	struct tof_icc_toq_common_header1 head1;
	struct tof_icc_toq_common_header2 head2;
	struct tof_icc_cq_stag_offset remote;
	struct tof_icc_cq_stag_offset local;
};

struct tof_icc_toq_write_piggyback_buffer {
	struct tof_icc_toq_common_header1 head1;
	uint64_t data[3];
};

struct tof_icc_toq_put_piggyback {
	struct tof_icc_toq_common_header1 head1;
	struct tof_icc_toq_common_header2 head2;
	struct tof_icc_cq_stag_offset remote;
	uint64_t data;
};

struct tof_icc_toq_get {
	struct tof_icc_toq_common_header1 head1;
	struct tof_icc_toq_common_header2 head2;
	struct tof_icc_cq_stag_offset remote;
	struct tof_icc_cq_stag_offset local;
};

struct tof_icc_toq_atomic_read_modify_write {
	struct tof_icc_toq_common_header1 head1;
	struct tof_icc_toq_common_header2 head2;
	struct tof_icc_cq_stag_offset remote;
	uint64_t data;
};

struct tof_icc_toq_transmit_raw_packet1 {
	struct tof_icc_toq_common_header1 head1;
	uint8_t gap;
	uint8_t res4[3];
	uint32_t length:12;
	uint32_t res5:20;
	uint64_t res6;
	uint64_t pa:48;  /* for optimization */
	uint64_t res7:16;
};

struct tof_icc_toq_transmit_raw_packet2 {
	uint8_t interrupt:1;
	uint8_t res1:4;
	uint8_t source_type:2;
	uint8_t flip:1;
	uint8_t command;
	uint8_t res2:7;
	uint8_t e:1;
	uint8_t res3[4];
	uint8_t port:5;
	uint8_t res4:1;
	uint8_t vc:2;
	uint8_t gap;
	uint8_t res5[3];
	uint32_t length:12;
	uint32_t res6:20;
	uint64_t res7;
	uint64_t pa:48;  /* for optimization */
	uint64_t res8:16;
};

struct tof_icc_toq_transmit_system_packet {
	struct tof_icc_toq_common_header1 head1;  /* rx, ry, rz should be rdx, rdy, rdz */
	uint8_t gap;
	uint8_t res4[3];
	uint32_t length:12;
	uint32_t res5:20;
	uint64_t res6;
	uint64_t pa:48;  /* for optimization */
	uint64_t res7:16;
};

struct tof_icc_tcq_descriptor {
	uint8_t res1:5;
	uint8_t counter_unmatch:1;
	uint8_t res2:1;
	uint8_t flip:1;
	uint8_t rcode;
	uint8_t res3[2];
	union{
		struct {
			uint32_t length:24;
			uint32_t res:8;
		} normal;
		struct {
			uint32_t length:6;
			uint32_t res:26;
		} piggyback;
	} len;
};

struct tof_icc_mrq_common_header1 {
	uint8_t res1:7;
	uint8_t flip:1;
	uint8_t id;
	uint8_t rcode;
	uint8_t res2:4;
	uint8_t pa:1;
	uint8_t pb:2;
	uint8_t pc:1;
	uint8_t x;
	uint8_t y;
	uint8_t z;
	uint8_t a:1;
	uint8_t b:2;
	uint8_t c:1;
	uint8_t res3:1;
	uint8_t i:3;
};

struct tof_icc_mrq_common_header2 {
	uint8_t res1;
	uint8_t res2:4;
	uint8_t initial:1;
	uint8_t res3:3;
	uint16_t edata;
	union {
		struct {
			uint32_t length:11;
			uint32_t res:21;
		} normal;
		struct {
			uint32_t op:4;
			uint32_t res:28;
		} armw;
	} lenop;
};

struct tof_icc_mrq_atomic_read_modify_write_halfway_notice {
	struct tof_icc_mrq_common_header1 head1;
	struct tof_icc_mrq_common_header2 head2;
	struct tof_icc_cq_stag_offset local;
	struct tof_icc_cq_stag_offset remote;
};

struct tof_icc_mrq_descriptor {
	struct tof_icc_mrq_common_header1 head1;
	struct tof_icc_mrq_common_header2 head2;
	struct tof_icc_cq_stag_offset cso1;
	struct tof_icc_cq_stag_offset cso2;
};

struct tof_icc_pbq_descriptor {
	uint64_t res1:7;
	uint64_t f:1;
	uint64_t res2:3;
	uint64_t pa:29;
	uint64_t res3:24;
};

struct tof_icc_prq_descriptor {
	uint64_t rcode:7;
	uint64_t f:1;
	uint64_t res1:3;
	uint64_t pa:29;
	uint64_t res2:8;
	uint64_t w:1;
	uint64_t res3:5;
	uint64_t l:1;
	uint64_t e:1;
	uint64_t res4:8;
};


/** Registers **/
/* useful packed structures */
struct tof_icc_reg_subnet {
	uint64_t lz:6;
	uint64_t sz:6;
	uint64_t nz:6;
	uint64_t ly:6;
	uint64_t sy:6;
	uint64_t ny:6;
	uint64_t lx:6;
	uint64_t sx:6;
	uint64_t nx:6;
	uint64_t res:10;
};

struct tof_icc_reg_bg_address {
	uint32_t bgid:6;
	uint32_t tni:3;
	uint32_t c:1;
	uint32_t b:2;
	uint32_t a:1;
	uint32_t z:5;
	uint32_t y:5;
	uint32_t x:5;
	uint32_t pc:1;
	uint32_t pb:2;
	uint32_t pa:1;
};

/* relative offset of interrupt controller registers */
#define TOF_ICC_IRQREG_IRR 0x0
#define TOF_ICC_IRQREG_IMR 0x8
#define TOF_ICC_IRQREG_IRC 0x10
#define TOF_ICC_IRQREG_IMC 0x18
#define TOF_ICC_IRQREG_ICL 0x20

/* TOFU REGISTERS */
#define  tof_icc_reg_pa 0x40000000

/* CQ */
#define TOF_ICC_REG_CQ_PA(tni, cqid) (tof_icc_reg_pa + 0 + (tni) * 0x1000000 + (cqid) * 0x10000)
#define TOF_ICC_REG_CQ_TOQ_DIRECT_DESCRIPTOR 0x0
#define TOF_ICC_REG_CQ_TOQ_FETCH_START 0x40
#define TOF_ICC_REG_CQ_MRQ_FULL_POINTER 0x48
#define TOF_ICC_REG_CQ_TOQ_PIGGYBACK_BUFFER0 0x50
#define TOF_ICC_REG_CQ_TOQ_PIGGYBACK_BUFFER1 0x58
#define TOF_ICC_REG_CQ_TOQ_PIGGYBACK_BUFFER2 0x60
#define TOF_ICC_REG_CQ_TCQ_NUM_NOTICE 0x68
#define TOF_ICC_REG_CQ_MRQ_NUM_NOTICE 0x70
#define TOF_ICC_REG_CQ_TX_PAYLOAD_BYTE 0x78
#define TOF_ICC_REG_CQ_RX_PAYLOAD_BYTE 0x80
#define TOF_ICC_REG_CQ_DUMP_START 0x0
#define TOF_ICC_REG_CQ_DUMP_END 0x88

/* BCH */
#define TOF_ICC_REG_BCH_PA(tni, bgid) (tof_icc_reg_pa + 0x0000e00000 + (tni) * 0x1000000 + (bgid) * 0x10000)
#define TOF_ICC_REG_BCH_IDATA 0x800
#define TOF_ICC_REG_BCH_READY 0x840
#define TOF_ICC_REG_BCH_READY_STATE BIT(63)
#define TOF_ICC_REG_BCH_IGNORED_SIGNAL_COUNT 0x848
#define TOF_ICC_REG_BCH_DUMP_START 0x800
#define TOF_ICC_REG_BCH_DUMP_END 0x850

/* CQS */
#define TOF_ICC_REG_CQS_PA(tni, cqid) (tof_icc_reg_pa + 0x0000400000 + (tni) * 0x1000000 + (cqid) * 0x10000)
#define TOF_ICC_REG_CQS_STATUS 0x0
#define TOF_ICC_REG_CQS_STATUS_DESCRIPTOR_PROCESS_STOP BIT(63)
#define TOF_ICC_REG_CQS_STATUS_DESCRIPTOR_FETCH_STOP BIT(62)
#define TOF_ICC_REG_CQS_STATUS_BLANK_ENTRY_FLIP_BIT BIT(61)
#define TOF_ICC_REG_CQS_STATUS_CACHE_FLUSH_BUSY BIT(60)
#define TOF_ICC_REG_CQS_STATUS_CQ_ENABLE BIT(59)
#define TOF_ICC_REG_CQS_STATUS_SESSION_DEAD BIT(58)
#define TOF_ICC_REG_CQS_STATUS_SESSION_OFFSET_OVERFLOW BIT(57)
#define TOF_ICC_REG_CQS_STATUS_SESSION_OFFSET GENMASK(56, 32)
#define TOF_ICC_REG_CQS_STATUS_NEXT_DESCRIPTOR_OFFSET GENMASK(29, 5)
#define TOF_ICC_REG_CQS_ENABLE 0x8
#define TOF_ICC_REG_CQS_CACHE_FLUSH 0x10
#define TOF_ICC_REG_CQS_FETCH_STOP 0x18
#define TOF_ICC_REG_CQS_MODE 0x20
#define TOF_ICC_REG_CQS_MODE_SYSTEM BIT(63)
#define TOF_ICC_REG_CQS_MODE_TRP2_ENABLE BIT(62)
#define TOF_ICC_REG_CQS_MODE_TRP1_ENABLE BIT(61)
#define TOF_ICC_REG_CQS_MODE_SESSION BIT(60)
#define TOF_ICC_REG_CQS_MODE_SUBNET_NX GENMASK(53, 48)
#define TOF_ICC_REG_CQS_MODE_SUBNET_SX GENMASK(47, 42)
#define TOF_ICC_REG_CQS_MODE_SUBNET_LX GENMASK(41, 36)
#define TOF_ICC_REG_CQS_MODE_SUBNET_NY GENMASK(35, 30)
#define TOF_ICC_REG_CQS_MODE_SUBNET_SY GENMASK(29, 24)
#define TOF_ICC_REG_CQS_MODE_SUBNET_LY GENMASK(23, 18)
#define TOF_ICC_REG_CQS_MODE_SUBNET_NZ GENMASK(17, 12)
#define TOF_ICC_REG_CQS_MODE_SUBNET_SZ GENMASK(11, 6)
#define TOF_ICC_REG_CQS_MODE_SUBNET_LZ GENMASK(5, 0)
#define TOF_ICC_REG_CQS_GPID 0x28
#define TOF_ICC_REG_CQS_TOQ_IPA 0x30
#define TOF_ICC_REG_CQS_TOQ_SIZE 0x38
#define TOF_ICC_REG_CQS_TCQ_IPA 0x40
#define TOF_ICC_REG_CQS_TCQ_IPA_CACHE_INJECTION BIT(63)
#define TOF_ICC_REG_CQS_MRQ_IPA 0x48
#define TOF_ICC_REG_CQS_MRQ_IPA_CACHE_INJECTION BIT(63)
#define TOF_ICC_REG_CQS_MRQ_SIZE 0x50
#define TOF_ICC_REG_CQS_MRQ_MASK 0x58
#define TOF_ICC_REG_CQS_TCQ_DESCRIPTOR_COALESCING_TIMER 0x60
#define TOF_ICC_REG_CQS_MRQ_DESCRIPTOR_COALESCING_TIMER 0x68
#define TOF_ICC_REG_CQS_MRQ_INTERRUPT_COALESCING_TIMER 0x70
#define TOF_ICC_REG_CQS_MRQ_INTERRUPT_COALESCING_COUNT 0x78
#define TOF_ICC_REG_CQS_TOQ_DIRECT_SOURCE_COUNT 0x80
#define TOF_ICC_REG_CQS_TOQ_DIRECT_DESCRIPTOR_COUNT 0x88
#define TOF_ICC_REG_CQS_MEMORY_BLOCK_TABLE_ENABLE 0x90
#define TOF_ICC_REG_CQS_MEMORY_BLOCK_TABLE_IPA 0x98
#define TOF_ICC_REG_CQS_MEMORY_BLOCK_TABLE_SIZE 0xa0
#define TOF_ICC_REG_CQS_STEERING_TABLE_ENABLE 0xa8
#define TOF_ICC_REG_CQS_STEERING_TABLE_IPA 0xb0
#define TOF_ICC_REG_CQS_STEERING_TABLE_SIZE 0xb8
#define TOF_ICC_REG_CQS_MRQ_INTERRUPT_MASK 0xc0
#define TOF_ICC_REG_CQS_IRR 0xc8
#define TOF_ICC_REG_CQS_IMR 0xd0
#define TOF_ICC_REG_CQS_IRC 0xd8
#define TOF_ICC_REG_CQS_IMC 0xe0
#define TOF_ICC_REG_CQS_ICL 0xe8
#define TOF_ICC_REG_CQS_DUMP_START 0x0
#define TOF_ICC_REG_CQS_DUMP_END 0xf0

/* BGS */
#define TOF_ICC_REG_BGS_PA(tni, bgid) (tof_icc_reg_pa + 0x0000800000 + (tni) * 0x1000000 + (bgid) * 0x10000)
#define TOF_ICC_REG_BGS_ENABLE 0x0
#define TOF_ICC_REG_BGS_IRR 0x8
#define TOF_ICC_REG_BGS_IMR 0x10
#define TOF_ICC_REG_BGS_IRC 0x18
#define TOF_ICC_REG_BGS_IMC 0x20
#define TOF_ICC_REG_BGS_ICL 0x28
#define TOF_ICC_REG_BGS_STATE 0x30
#define TOF_ICC_REG_BGS_STATE_ENABLE BIT(0)
#define TOF_ICC_REG_BGS_EXCEPTION_INFO_GPID_UNMATCH 0x38
#define TOF_ICC_REG_BGS_EXCEPTION_INFO_GPID_UNMATCH_BG_ADDRESS GENMASK(27, 0)
#define TOF_ICC_REG_BGS_EXCEPTION_INFO_ADDRESS_UNMATCH 0x40
#define TOF_ICC_REG_BGS_EXCEPTION_INFO_ADDRESS_UNMATCH_BG_ADDRESS GENMASK(27, 0)
#define TOF_ICC_REG_BGS_SIGNAL_A 0x48
#define TOF_ICC_REG_BGS_SIGNAL_A_SIG_RECV BIT(63)
#define TOF_ICC_REG_BGS_SIGNAL_A_TLP_RECV BIT(62)
#define TOF_ICC_REG_BGS_SIGNAL_A_SIG_SEND BIT(61)
#define TOF_ICC_REG_BGS_SIGNAL_A_OP_TYPE GENMASK(3, 0)
#define TOF_ICC_REG_BGS_SIGNAL_B 0x50
#define TOF_ICC_REG_BGS_SIGNAL_B_SIG_RECV BIT(63)
#define TOF_ICC_REG_BGS_SIGNAL_B_TLP_RECV BIT(62)
#define TOF_ICC_REG_BGS_SIGNAL_B_SIG_SEND BIT(61)
#define TOF_ICC_REG_BGS_SIGNAL_B_OP_TYPE GENMASK(3, 0)
#define TOF_ICC_REG_BGS_SIGNAL_MASK 0x58
#define TOF_ICC_REG_BGS_SIGNAL_MASK_SIG_RECV BIT(63)
#define TOF_ICC_REG_BGS_SIGNAL_MASK_TLP_RECV BIT(62)
#define TOF_ICC_REG_BGS_SIGNAL_MASK_SIG_SEND BIT(61)
#define TOF_ICC_REG_BGS_SIGNAL_MASK_TLP_SEND BIT(60)
#define TOF_ICC_REG_BGS_LOCAL_LINK 0x60
#define TOF_ICC_REG_BGS_LOCAL_LINK_BGID_RECV GENMASK(37, 32)
#define TOF_ICC_REG_BGS_LOCAL_LINK_BGID_SEND GENMASK(5, 0)
#define TOF_ICC_REG_BGS_REMOTE_LINK 0x68
#define TOF_ICC_REG_BGS_REMOTE_LINK_BG_ADDRESS_RECV GENMASK(59, 32)
#define TOF_ICC_REG_BGS_REMOTE_LINK_BG_ADDRESS_SEND GENMASK(31, 0)
#define TOF_ICC_REG_BGS_SUBNET_SIZE 0x70
#define TOF_ICC_REG_BGS_GPID_BSEQ 0x78
#define TOF_ICC_REG_BGS_DATA_A0 0x108
#define TOF_ICC_REG_BGS_DATA_AE 0x178
#define TOF_ICC_REG_BGS_DATA_B0 0x188
#define TOF_ICC_REG_BGS_DATA_BE 0x1f8
#define TOF_ICC_REG_BGS_BCH_MASK 0x800
#define TOF_ICC_REG_BGS_BCH_MASK_MASK BIT(63)
#define TOF_ICC_REG_BGS_BCH_MASK_STATUS 0x808
#define TOF_ICC_REG_BGS_BCH_MASK_STATUS_RUN BIT(63)
#define TOF_ICC_REG_BGS_BCH_NOTICE_IPA 0x810
#define TOF_ICC_REG_BGS_DUMP_START 0x0
#define TOF_ICC_REG_BGS_DUMP_END 0x818

/* TNI */
#define TOF_ICC_REG_TNI_PA(tni) (tof_icc_reg_pa + 0x0000c00000 + (tni) * 0x1000000)
#define TOF_ICC_REG_TNI_IRR 0x8
#define TOF_ICC_REG_TNI_IMR 0x10
#define TOF_ICC_REG_TNI_IRC 0x18
#define TOF_ICC_REG_TNI_IMC 0x20
#define TOF_ICC_REG_TNI_ICL 0x28
#define TOF_ICC_REG_TNI_STATE 0x30
#define TOF_ICC_REG_TNI_STATE_MASK GENMASK(1, 0)
#define TOF_ICC_REG_TNI_STATE_DISABLE 0
#define TOF_ICC_REG_TNI_STATE_NORMAL 2
#define TOF_ICC_REG_TNI_STATE_ERROR 3
#define TOF_ICC_REG_TNI_ENABLE 0x38
#define TOF_ICC_REG_TNI_CQ_PRESENT 0x40
#define TOF_ICC_REG_TNI_EXCEPTION_INFO_INACTIVE_BG 0x48
#define TOF_ICC_REG_TNI_EXCEPTION_INFO_INACTIVE_BG_DEST_BG GENMASK(37, 32)
#define TOF_ICC_REG_TNI_EXCEPTION_INFO_INACTIVE_BG_SOURCE_BG_ADDRESS GENMASK(27, 0)
#define TOF_ICC_REG_TNI_PRQ_FULL_POINTER 0x100
#define TOF_ICC_REG_TNI_PBQ_PA 0x108
#define TOF_ICC_REG_TNI_PBQ_SIZE 0x110
#define TOF_ICC_REG_TNI_PRQ_PA 0x118
#define TOF_ICC_REG_TNI_PRQ_PA_CACHE_INJECTION BIT(63)
#define TOF_ICC_REG_TNI_PRQ_SIZE 0x120
#define TOF_ICC_REG_TNI_PRQ_MASK 0x128
#define TOF_ICC_REG_TNI_PRQ_ENTRY_COALESCING_TIMER 0x130
#define TOF_ICC_REG_TNI_PRQ_INTERRUPT_COALESCING_TIMER 0x138
#define TOF_ICC_REG_TNI_PRQ_INTERRUPT_COALESCING_COUNT 0x140
#define TOF_ICC_REG_TNI_SEND_COUNT 0x148
#define TOF_ICC_REG_TNI_NO_SEND_COUNT 0x150
#define TOF_ICC_REG_TNI_BLOCK_SEND_COUNT 0x158
#define TOF_ICC_REG_TNI_RECEIVE_COUNT 0x160
#define TOF_ICC_REG_TNI_NO_RECEIVE_COUNT 0x168
#define TOF_ICC_REG_TNI_NUM_SEND_TLP 0x170
#define TOF_ICC_REG_TNI_BYTE_SEND_TLP 0x178
#define TOF_ICC_REG_TNI_NUM_SEND_SYSTEM_TLP 0x180
#define TOF_ICC_REG_TNI_NUM_RECEIVE_TLP 0x188
#define TOF_ICC_REG_TNI_BYTE_RECEIVE_TLP 0x190
#define TOF_ICC_REG_TNI_NUM_RECEIVE_NULLIFIED_TLP 0x198
#define TOF_ICC_REG_TNI_RX_NUM_UNKNOWN_TLP 0x1a0
#define TOF_ICC_REG_TNI_RX_NUM_SYSTEM_TLP 0x1a8
#define TOF_ICC_REG_TNI_RX_NUM_EXCEPTION_TLP 0x1b0
#define TOF_ICC_REG_TNI_RX_NUM_DISCARD_UNKNOWN_TLP 0x1b8
#define TOF_ICC_REG_TNI_RX_NUM_DISCARD_SYSTEM_TLP 0x1c0
#define TOF_ICC_REG_TNI_RX_NUM_DISCARD_EXCEPTION_TLP 0x1c8
#define TOF_ICC_REG_TNI_DUMP_START 0x8
#define TOF_ICC_REG_TNI_DUMP_END 0x1d0

/* Port */
#define TOF_ICC_REG_PORT_PA(port) (tof_icc_reg_pa + 0x0006000000 + (port) * 0x1000)
#define TOF_ICC_REG_PORT_TX_VC0_ZERO_CREDIT_COUNT 0x0
#define TOF_ICC_REG_PORT_TX_VC1_ZERO_CREDIT_COUNT 0x8
#define TOF_ICC_REG_PORT_TX_VC2_ZERO_CREDIT_COUNT 0x10
#define TOF_ICC_REG_PORT_TX_VC3_ZERO_CREDIT_COUNT 0x18
#define TOF_ICC_REG_PORT_FREE_RUN_COUNT 0x80
#define TOF_ICC_REG_PORT_NUM_SEND_DLLP 0xc0
#define TOF_ICC_REG_PORT_NUM_SEND_TLP 0xc8
#define TOF_ICC_REG_PORT_BYTE_SEND_TLP 0xd0
#define TOF_ICC_REG_PORT_NUM_SEND_SYSTEM_TLP 0xd8
#define TOF_ICC_REG_PORT_NUM_SEND_NULLIFIED_TLP 0xe0
#define TOF_ICC_REG_PORT_NUM_TX_DISCARD_SYSTEM_TLP 0xe8
#define TOF_ICC_REG_PORT_NUM_TX_DISCARD_NORMAL_TLP 0xf0
#define TOF_ICC_REG_PORT_NUM_TX_FILTERED_NORMAL_TLP 0xf8
#define TOF_ICC_REG_PORT_NUM_VIRTUAL_CUT_THROUGH_TLP 0x100
#define TOF_ICC_REG_PORT_NUM_GENERATE_NULLIFIED_TLP 0x108
#define TOF_ICC_REG_PORT_NUM_RECEIVE_DLLP 0x110
#define TOF_ICC_REG_PORT_NUM_RECEIVE_TLP 0x118
#define TOF_ICC_REG_PORT_BYTE_RECEIVE_TLP 0x120
#define TOF_ICC_REG_PORT_NUM_RECEIVE_SYSTEM_TLP 0x128
#define TOF_ICC_REG_PORT_NUM_RECEIVE_NULLIFIED_TLP 0x130
#define TOF_ICC_REG_PORT_NUM_RX_DISCARD_SYSTEM_TLP 0x138
#define TOF_ICC_REG_PORT_NUM_RX_DISCARD_NORMAL_TLP 0x140
#define TOF_ICC_REG_PORT_NUM_RX_FILTERED_NORMAL_TLP 0x158
#define TOF_ICC_REG_PORT_NUM_RX_DISCARD_NULLIFIED_TLP 0x160
#define TOF_ICC_REG_PORT_FRAME_LCRC_ERROR_COUNT 0x170
#define TOF_ICC_REG_PORT_TX_RETRY_BUFFER_CE_COUNT 0x180
#define TOF_ICC_REG_PORT_RX_VC_BUFFER_CE_COUNT 0x188
#define TOF_ICC_REG_PORT_XB_CE_COUNT 0x190
#define TOF_ICC_REG_PORT_ACK_NACK_TIME_OUT_COUNT 0x198
#define TOF_ICC_REG_PORT_SLICE0_FCS_ERROR_COUNT 0x1a0
#define TOF_ICC_REG_PORT_SLICE1_FCS_ERROR_COUNT 0x1a8
#define TOF_ICC_REG_PORT_DUMP_START 0x0
#define TOF_ICC_REG_PORT_DUMP_END 0x1b0

/* XB */
#define TOF_ICC_REG_XB_PA (tof_icc_reg_pa + 0x000600f000)
#define TOF_ICC_REG_XB_STQ_ENABLE 0x0
#define TOF_ICC_REG_XB_STQ_UPDATE_INTERVAL 0x8
#define TOF_ICC_REG_XB_STQ_PA 0x10
#define TOF_ICC_REG_XB_STQ_SIZE 0x18
#define TOF_ICC_REG_XB_STQ_NEXT_OFFSET 0x20
#define TOF_ICC_REG_XB_DUMP_START 0x0
#define TOF_ICC_REG_XB_DUMP_END 0x28

#define TOF_ICC_XB_TC_DATA_CYCLE_COUNT(tni) ((tni) * 0x10 + 0x0)
#define TOF_ICC_XB_TC_WAIT_CYCLE_COUNT(tni) ((tni) * 0x10 + 0x8)
#define TOF_ICC_XB_TD_DATA_CYCLE_COUNT(tnr) ((tnr) * 0x10 + 0x60)
#define TOF_ICC_XB_TD_WAIT_CYCLE_COUNT(tnr) ((tnr) * 0x10 + 0x68)

/* Tofu */
#define TOF_ICC_REG_TOFU_PA (tof_icc_reg_pa + 0x0007000000)
#define TOF_ICC_REG_TOFU_NODE_ADDRESS 0x0
#define TOF_ICC_REG_TOFU_NODE_ADDRESS_X GENMASK(22, 18)
#define TOF_ICC_REG_TOFU_NODE_ADDRESS_Y GENMASK(17, 13)
#define TOF_ICC_REG_TOFU_NODE_ADDRESS_Z GENMASK(12, 8)
#define TOF_ICC_REG_TOFU_NODE_ADDRESS_A BIT(7)
#define TOF_ICC_REG_TOFU_NODE_ADDRESS_B GENMASK(6, 5)
#define TOF_ICC_REG_TOFU_NODE_ADDRESS_C BIT(4)
#define TOF_ICC_REG_TOFU_PORT_SETTING 0x8
#define TOF_ICC_REG_TOFU_TD_TLP_FILTER(tnr) ((tnr) * 0x10 + 0x10)
#define TOF_ICC_REG_TOFU_TD_SETTINGS(tnr) ((tnr) * 0x10 + 0x18)
#define TOF_ICC_REG_TOFU_TNR_MSI_BASE 0xc0
#define TOF_ICC_REG_TOFU_TNR_IRR 0xc8
#define TOF_ICC_REG_TOFU_TNR_IMR 0xd0
#define TOF_ICC_REG_TOFU_TNR_IRC 0xd8
#define TOF_ICC_REG_TOFU_TNR_IMC 0xe0
#define TOF_ICC_REG_TOFU_TNR_ICL 0xe8
#define TOF_ICC_REG_TOFU_TNI_VMS(tni, vmsid) ((tni) * 0x100 + (vmsid) * 0x8 + 0x100)
#define TOF_ICC_REG_TOFU_TNI_VMS_CQ00(tni) ((tni) * 0x100 + 0x180)
#define TOF_ICC_REG_TOFU_TNI_VMS_BG00(tni) ((tni) * 0x100 + 0x1a0)
#define TOF_ICC_REG_TOFU_TNI_VMS_BG16(tni) ((tni) * 0x100 + 0x1a8)
#define TOF_ICC_REG_TOFU_TNI_VMS_BG32(tni) ((tni) * 0x100 + 0x1b0)
#define TOF_ICC_REG_TOFU_TNI_MSI_BASE(tni) ((tni) * 0x100 + 0x1c0)
#define TOF_ICC_REG_TOFU_DUMP_START 0x0
#define TOF_ICC_REG_TOFU_DUMP_END 0x6c8

/** Interrupts **/
#define TOF_ICC_IRQ_CQS_TOQ_READ_EXCEPTION BIT(0)
#define TOF_ICC_IRQ_CQS_TOQ_DIRECT_DESCRIPTOR_EXCEPTION BIT(1)
#define TOF_ICC_IRQ_CQS_TOQ_MARKED_UE BIT(2)
#define TOF_ICC_IRQ_CQS_TCQ_WRITE_EXCEPTION BIT(3)
#define TOF_ICC_IRQ_CQS_TOQ_SOURCE_TYPE_EXCEPTION BIT(4)
#define TOF_ICC_IRQ_CQS_TCQ_WRITE_ACKNOWLEDGE BIT(5)
#define TOF_ICC_IRQ_CQS_MRQ_WRITE_ACKNOWLEDGE BIT(7)
#define TOF_ICC_IRQ_CQS_MRQ_WRITE_EXCEPTION BIT(8)
#define TOF_ICC_IRQ_CQS_MRQ_OVERFLOW BIT(9)
#define TOF_ICC_IRQ_CQS_STEERING_READ_EXCEPTION BIT(36)
#define TOF_ICC_IRQ_CQS_MB_READ_EXCEPTION BIT(38)
#define TOF_ICC_IRQ_CQS_PAYLOAD_READ_EXCEPTION BIT(39)
#define TOF_ICC_IRQ_CQS_PAYLOAD_WRITE_EXCEPTION BIT(40)

#define TOF_ICC_IRQ_BGS_NODE_ADDRESS_UNMATCH BIT(0)
#define TOF_ICC_IRQ_BGS_BG_RECV_ADDRESS_EXCEPTION BIT(1)
#define TOF_ICC_IRQ_BGS_BG_SEND_ADDRESS_EXCEPTION BIT(2)
#define TOF_ICC_IRQ_BGS_GPID_UNMATCH BIT(3)
#define TOF_ICC_IRQ_BGS_BSEQ_UNMATCH BIT(4)
#define TOF_ICC_IRQ_BGS_SIGNAL_STATE_ERROR BIT(5)
#define TOF_ICC_IRQ_BGS_SYNCHRONIZATION_ACKNOWLEDGE BIT(24)
#define TOF_ICC_IRQ_BGS_ERROR_SYNCHRONIZATION_ACKNOWLEDGE BIT(25)
#define TOF_ICC_IRQ_BGS_DMA_COMPLETION_EXCEPTION BIT(26)

#define TOF_ICC_IRQ_TNI_PBQ_READ_EXCEPTION BIT(0)
#define TOF_ICC_IRQ_TNI_PBQ_MARKED_UE BIT(1)
#define TOF_ICC_IRQ_TNI_PBQ_UNDERFLOW BIT(2)
#define TOF_ICC_IRQ_TNI_PRQ_PACKET_DISCARD BIT(3)
#define TOF_ICC_IRQ_TNI_PRQ_WRITE_ACKNOWLEDGE BIT(4)
#define TOF_ICC_IRQ_TNI_PRQ_WRITE_EXCEPTION BIT(5)
#define TOF_ICC_IRQ_TNI_PRQ_OVERFLOW BIT(6)
#define TOF_ICC_IRQ_TNI_INACTIVE_BG BIT(16)
#define TOF_ICC_IRQ_TNI_STAGE2_TRANSLATION_FAULT BIT(32)

#define TOF_ICC_IRQ_TNR_TNR0_RX_FILTER_OUT BIT(0)
#define TOF_ICC_IRQ_TNR_TNR0_TX_FILTER_OUT BIT(1)
#define TOF_ICC_IRQ_TNR_TNR0_PORT_ERROR BIT(2)
#define TOF_ICC_IRQ_TNR_TNR0_DATELINE_ERROR BIT(3)
#define TOF_ICC_IRQ_TNR_TNR0_ROUTING_ERROR BIT(4)
#define TOF_ICC_IRQ_TNR_TNR1_RX_FILTER_OUT BIT(6)
#define TOF_ICC_IRQ_TNR_TNR1_TX_FILTER_OUT BIT(7)
#define TOF_ICC_IRQ_TNR_TNR1_PORT_ERROR BIT(8)
#define TOF_ICC_IRQ_TNR_TNR1_DATELINE_ERROR BIT(9)
#define TOF_ICC_IRQ_TNR_TNR1_ROUTING_ERROR BIT(10)
#define TOF_ICC_IRQ_TNR_TNR2_RX_FILTER_OUT BIT(12)
#define TOF_ICC_IRQ_TNR_TNR2_TX_FILTER_OUT BIT(13)
#define TOF_ICC_IRQ_TNR_TNR2_PORT_ERROR BIT(14)
#define TOF_ICC_IRQ_TNR_TNR2_DATELINE_ERROR BIT(15)
#define TOF_ICC_IRQ_TNR_TNR2_ROUTING_ERROR BIT(16)
#define TOF_ICC_IRQ_TNR_TNR3_RX_FILTER_OUT BIT(18)
#define TOF_ICC_IRQ_TNR_TNR3_TX_FILTER_OUT BIT(19)
#define TOF_ICC_IRQ_TNR_TNR3_PORT_ERROR BIT(20)
#define TOF_ICC_IRQ_TNR_TNR3_DATELINE_ERROR BIT(21)
#define TOF_ICC_IRQ_TNR_TNR3_ROUTING_ERROR BIT(22)
#define TOF_ICC_IRQ_TNR_TNR4_RX_FILTER_OUT BIT(24)
#define TOF_ICC_IRQ_TNR_TNR4_TX_FILTER_OUT BIT(25)
#define TOF_ICC_IRQ_TNR_TNR4_PORT_ERROR BIT(26)
#define TOF_ICC_IRQ_TNR_TNR4_DATELINE_ERROR BIT(27)
#define TOF_ICC_IRQ_TNR_TNR4_ROUTING_ERROR BIT(28)
#define TOF_ICC_IRQ_TNR_TNR5_RX_FILTER_OUT BIT(30)
#define TOF_ICC_IRQ_TNR_TNR5_TX_FILTER_OUT BIT(31)
#define TOF_ICC_IRQ_TNR_TNR5_PORT_ERROR BIT(32)
#define TOF_ICC_IRQ_TNR_TNR5_DATELINE_ERROR BIT(33)
#define TOF_ICC_IRQ_TNR_TNR5_ROUTING_ERROR BIT(34)
#define TOF_ICC_IRQ_TNR_TNR6_RX_FILTER_OUT BIT(36)
#define TOF_ICC_IRQ_TNR_TNR6_TX_FILTER_OUT BIT(37)
#define TOF_ICC_IRQ_TNR_TNR6_PORT_ERROR BIT(38)
#define TOF_ICC_IRQ_TNR_TNR6_DATELINE_ERROR BIT(39)
#define TOF_ICC_IRQ_TNR_TNR6_ROUTING_ERROR BIT(40)
#define TOF_ICC_IRQ_TNR_TNR7_RX_FILTER_OUT BIT(42)
#define TOF_ICC_IRQ_TNR_TNR7_TX_FILTER_OUT BIT(43)
#define TOF_ICC_IRQ_TNR_TNR7_PORT_ERROR BIT(44)
#define TOF_ICC_IRQ_TNR_TNR7_DATELINE_ERROR BIT(45)
#define TOF_ICC_IRQ_TNR_TNR7_ROUTING_ERROR BIT(46)
#define TOF_ICC_IRQ_TNR_TNR8_RX_FILTER_OUT BIT(48)
#define TOF_ICC_IRQ_TNR_TNR8_TX_FILTER_OUT BIT(49)
#define TOF_ICC_IRQ_TNR_TNR8_PORT_ERROR BIT(50)
#define TOF_ICC_IRQ_TNR_TNR8_DATELINE_ERROR BIT(51)
#define TOF_ICC_IRQ_TNR_TNR8_ROUTING_ERROR BIT(52)
#define TOF_ICC_IRQ_TNR_TNR9_RX_FILTER_OUT BIT(54)
#define TOF_ICC_IRQ_TNR_TNR9_TX_FILTER_OUT BIT(55)
#define TOF_ICC_IRQ_TNR_TNR9_PORT_ERROR BIT(56)
#define TOF_ICC_IRQ_TNR_TNR9_DATELINE_ERROR BIT(57)
#define TOF_ICC_IRQ_TNR_TNR9_ROUTING_ERROR BIT(58)

#endif

/* vim: set noet ts=8 sw=8 sts=0 tw=0 : */

