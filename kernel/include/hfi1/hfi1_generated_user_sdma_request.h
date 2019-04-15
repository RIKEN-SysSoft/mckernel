struct user_sdma_request {
	union {
		char whole_struct[768];
		struct {
			char padding0[0];
			struct hfi1_pkt_header hdr;
		};
		struct {
			char padding1[64];
			struct hfi1_user_sdma_pkt_q *pq;
		};
		struct {
			char padding2[72];
			struct hfi1_user_sdma_comp_q *cq;
		};
		struct {
			char padding3[80];
			struct sdma_engine *sde;
		};
		struct {
			char padding4[88];
			struct sdma_req_info info;
		};
		struct {
			char padding5[96];
			u32 *tids;
		};
		struct {
			char padding6[104];
			u32 data_len;
		};
		struct {
			char padding7[108];
			u16 n_tids;
		};
		struct {
			char padding8[110];
			u8 data_iovs;
		};
		struct {
			char padding9[111];
			s8 ahg_idx;
		};
		struct {
			char padding10[128];
			u64 seqcomp;
		};
		struct {
			char padding11[136];
			u64 seqsubmitted;
		};
		struct {
			char padding12[192];
			struct list_head txps;
		};
		struct {
			char padding13[208];
			u64 seqnum;
		};
		struct {
			char padding14[216];
			u32 tidoffset;
		};
		struct {
			char padding15[220];
			u32 koffset;
		};
		struct {
			char padding16[224];
			u32 sent;
		};
		struct {
			char padding17[228];
			u16 tididx;
		};
		struct {
			char padding18[230];
			u8 iov_idx;
		};
		struct {
			char padding19[231];
			u8 has_error;
		};
		struct {
			char padding20[232];
			struct user_sdma_iovec iovs[8];
		};
	};
};
