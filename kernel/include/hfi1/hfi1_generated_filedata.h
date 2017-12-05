struct hfi1_filedata {
	union {
		char whole_struct[104];
		struct {
			char padding0[0];
			struct hfi1_devdata *dd;
		};
		struct {
			char padding1[8];
			struct hfi1_ctxtdata *uctxt;
		};
		struct {
			char padding2[16];
			struct hfi1_user_sdma_comp_q *cq;
		};
		struct {
			char padding3[24];
			struct hfi1_user_sdma_pkt_q *pq;
		};
		struct {
			char padding4[32];
			u16 subctxt;
		};
		struct {
			char padding5[56];
			struct tid_rb_node **entry_to_rb;
		};
		struct {
			char padding6[64];
			spinlock_t tid_lock;
		};
		struct {
			char padding7[72];
			u32 tid_used;
		};
		struct {
			char padding8[80];
			u32 *invalid_tids;
		};
		struct {
			char padding9[88];
			u32 invalid_tid_idx;
		};
		struct {
			char padding10[92];
			spinlock_t invalid_lock;
		};
	};
};
