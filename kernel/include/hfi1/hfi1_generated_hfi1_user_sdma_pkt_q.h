struct hfi1_user_sdma_pkt_q {
	union {
		char whole_struct[352];
		struct {
			char padding0[4];
			u16 n_max_reqs;
		};
		struct {
			char padding1[8];
			atomic_t n_reqs;
		};
		struct {
			char padding2[16];
			struct hfi1_devdata *dd;
		};
		struct {
			char padding3[32];
			struct user_sdma_request *reqs;
		};
		struct {
			char padding4[40];
			long unsigned int *req_in_use;
		};
		struct {
			char padding5[288];
			enum pkt_q_sdma_state state;
		};
	};
};
