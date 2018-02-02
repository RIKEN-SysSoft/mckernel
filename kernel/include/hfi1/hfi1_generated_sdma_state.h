struct sdma_state {
	union {
		char whole_struct[64];
		struct {
			char padding0[40];
			enum sdma_states current_state;
		};
		struct {
			char padding1[48];
			unsigned int go_s99_running;
		};
		struct {
			char padding2[52];
			enum sdma_states previous_state;
		};
	};
};
