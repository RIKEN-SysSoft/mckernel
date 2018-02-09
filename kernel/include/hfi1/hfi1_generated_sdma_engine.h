struct sdma_engine {
	union {
		char whole_struct[1472];
		struct {
			char padding0[0];
			struct hfi1_devdata *dd;
		};
		struct {
			char padding1[16];
			void *tail_csr;
		};
		struct {
			char padding2[72];
			struct hw_sdma_desc *descq;
		};
		struct {
			char padding3[80];
			unsigned int descq_full_count;
		};
		struct {
			char padding4[88];
			struct sdma_txreq **tx_ring;
		};
		struct {
			char padding5[104];
			u32 sdma_mask;
		};
		struct {
			char padding6[112];
			struct sdma_state state;
		};
		struct {
			char padding7[180];
			u8 sdma_shift;
		};
		struct {
			char padding8[181];
			u8 this_idx;
		};
		struct {
			char padding9[256];
			spinlock_t tail_lock;
		};
		struct {
			char padding10[260];
			u32 descq_tail;
		};
		struct {
			char padding11[264];
			long unsigned int ahg_bits;
		};
		struct {
			char padding12[272];
			u16 desc_avail;
		};
		struct {
			char padding13[274];
			u16 tx_tail;
		};
		struct {
			char padding14[276];
			u16 descq_cnt;
		};
		struct {
			char padding15[320];
			seqlock_t head_lock;
		};
		struct {
			char padding16[328];
			u32 descq_head;
		};
		struct {
			char padding17[704];
			spinlock_t flushlist_lock;
		};
		struct {
			char padding18[712];
			struct list_head flushlist;
		};
	};
};
