struct hfi1_pportdata {
	union {
		struct {
			char padding0[1907];
			u8 vls_operational;
		};
	};
};
struct hfi1_ctxtdata {
	union {
		struct {
			char padding0[144];
			unsigned int ctxt;
		};
		struct {
			char padding1[172];
			u32 rcv_array_groups;
		};
		struct {
			char padding2[176];
			u32 eager_base;
		};
		struct {
			char padding3[180];
			u32 expected_count;
		};
		struct {
			char padding4[184];
			u32 expected_base;
		};
		struct {
			char padding5[192];
			struct exp_tid_set tid_group_list;
		};
		struct {
			char padding6[216];
			struct exp_tid_set tid_used_list;
		};
		struct {
			char padding7[240];
			struct exp_tid_set tid_full_list;
		};
		struct {
			char padding8[432];
			struct hfi1_devdata *dd;
		};
	};
};
struct hfi1_devdata {
	union {
		struct {
			char padding0[2984];
			u8 *kregbase1;
		};
		struct {
			char padding1[2992];
			resource_size_t physaddr;
		};
		struct {
			char padding2[3320];
			u64 default_desc1;
		};
		struct {
			char padding3[3352];
			dma_addr_t sdma_pad_phys;
		};
		struct {
			char padding4[3376];
			struct sdma_engine *per_sdma;
		};
		struct {
			char padding5[3384];
			struct sdma_vl_map *sdma_map;
		};
		struct {
			char padding6[3432];
			void *piobase;
		};
		struct {
			char padding7[3440];
			void *rcvarray_wc;
		};
		struct {
			char padding8[3688];
			u32 chip_rcv_array_count;
		};
		struct {
			char padding9[6872];
			struct hfi1_pportdata *pport;
		};
		struct {
			char padding10[6896];
			u16 flags;
		};
		struct {
			char padding11[6920];
			u64 sc2vl[4];
		};
	};
};
