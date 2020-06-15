			struct {
				struct tof_utofu_trans_list *mru;
				struct tof_trans_table *table;
				int mruhead;
				ihk_spinlock_t mru_lock;
			} trans;
