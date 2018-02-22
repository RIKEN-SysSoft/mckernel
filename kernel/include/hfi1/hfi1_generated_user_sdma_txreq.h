struct user_sdma_txreq {
	union {
		char whole_struct[264];
		struct {
			char padding0[0];
			struct hfi1_pkt_header hdr;
		};
		struct {
			char padding1[64];
			struct sdma_txreq txreq;
		};
		struct {
			char padding2[224];
			struct list_head list;
		};
		struct {
			char padding3[240];
			struct user_sdma_request *req;
		};
		struct {
			char padding4[248];
			u16 flags;
		};
		struct {
			char padding5[252];
			unsigned int busycount;
		};
		struct {
			char padding6[256];
			u64 seqnum;
		};
	};
};
