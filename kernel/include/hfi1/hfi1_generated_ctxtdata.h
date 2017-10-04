struct hfi1_ctxtdata {
	union {
		char whole_struct[1456];
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
