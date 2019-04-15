struct hfi1_ctxtdata {
	union {
		char whole_struct[1160];
		struct {
			char padding0[144];
			u16 ctxt;
		};
		struct {
			char padding1[168];
			u32 rcv_array_groups;
		};
		struct {
			char padding2[172];
			u32 eager_base;
		};
		struct {
			char padding3[176];
			u32 expected_count;
		};
		struct {
			char padding4[180];
			u32 expected_base;
		};
		struct {
			char padding5[184];
			struct exp_tid_set tid_group_list;
		};
		struct {
			char padding6[208];
			struct exp_tid_set tid_used_list;
		};
		struct {
			char padding7[232];
			struct exp_tid_set tid_full_list;
		};
		struct {
			char padding8[392];
			struct hfi1_devdata *dd;
		};
	};
};
