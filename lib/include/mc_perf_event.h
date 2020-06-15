/* mc_perf_event.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef MC_PERF_EVENT_H
#define MC_PERF_EVENT_H

#include <list.h>
#include <march.h>
#include <ihk/atomic.h>

struct perf_event_attr;

/**
 * IOC Macro start
 */
#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8

#ifndef _IOC_SIZEBITS
# define _IOC_SIZEBITS  14
#endif

#ifndef _IOC_DIRBITS
# define _IOC_DIRBITS   2
#endif

#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT+_IOC_SIZEBITS)

#ifndef _IOC_NONE
# define _IOC_NONE      0U
#endif

#ifndef _IOC_WRITE
# define _IOC_WRITE     1U
#endif

#ifndef _IOC_READ
# define _IOC_READ      2U
#endif

#define _IOC(dir,type,nr,size) \
        (((dir)  << _IOC_DIRSHIFT) | \
         ((type) << _IOC_TYPESHIFT) | \
         ((nr)   << _IOC_NRSHIFT) | \
         ((size) << _IOC_SIZESHIFT))

#ifndef _IOC_TYPECHECK
#define _IOC_TYPECHECK(t) (sizeof(t))
#endif

/* used to create numbers */
#define _IO(type,nr)            _IOC(_IOC_NONE,(type),(nr),0)
#define _IOR(type,nr,size)      _IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOW(type,nr,size)      _IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOWR(type,nr,size)     _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOR_BAD(type,nr,size)  _IOC(_IOC_READ,(type),(nr),sizeof(size))
#define _IOW_BAD(type,nr,size)  _IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#define _IOWR_BAD(type,nr,size) _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))
/**
 * IOC Macro end
 */

#define PERF_EVENT_IOC_ENABLE           _IO ('$', 0)
#define PERF_EVENT_IOC_DISABLE          _IO ('$', 1)
#define PERF_EVENT_IOC_REFRESH          _IO ('$', 2)
#define PERF_EVENT_IOC_RESET            _IO ('$', 3)

enum perf_type_id {
        PERF_TYPE_HARDWARE                      = 0,
        PERF_TYPE_SOFTWARE                      = 1,
        PERF_TYPE_TRACEPOINT                    = 2,
        PERF_TYPE_HW_CACHE                      = 3,
        PERF_TYPE_RAW                           = 4,
        PERF_TYPE_BREAKPOINT                    = 5,

        PERF_TYPE_MAX,                          /* non-ABI */
};

enum perf_event_read_format {
        PERF_FORMAT_TOTAL_TIME_ENABLED          = 1U << 0,
        PERF_FORMAT_TOTAL_TIME_RUNNING          = 1U << 1,
        PERF_FORMAT_ID                          = 1U << 2,
        PERF_FORMAT_GROUP                       = 1U << 3,

        PERF_FORMAT_MAX = 1U << 4,              /* non-ABI */
};

enum perf_hw_id {
        /*
         * Common hardware events, generalized by the kernel:
         */
        PERF_COUNT_HW_CPU_CYCLES                = 0,
        PERF_COUNT_HW_INSTRUCTIONS              = 1,
        PERF_COUNT_HW_CACHE_REFERENCES          = 2,
        PERF_COUNT_HW_CACHE_MISSES              = 3,
        PERF_COUNT_HW_BRANCH_INSTRUCTIONS       = 4,
        PERF_COUNT_HW_BRANCH_MISSES             = 5,
        PERF_COUNT_HW_BUS_CYCLES                = 6,
        PERF_COUNT_HW_STALLED_CYCLES_FRONTEND   = 7,
        PERF_COUNT_HW_STALLED_CYCLES_BACKEND    = 8,
        PERF_COUNT_HW_REF_CPU_CYCLES            = 9,

        PERF_COUNT_HW_MAX,                      /* non-ABI */
};

/*
 * Generalized hardware cache events:
 *
 *       { L1-D, L1-I, LLC, ITLB, DTLB, BPU, NODE } x
 *       { read, write, prefetch } x
 *       { accesses, misses }
 */
enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D         = 0,
	PERF_COUNT_HW_CACHE_L1I         = 1,
	PERF_COUNT_HW_CACHE_LL          = 2,
	PERF_COUNT_HW_CACHE_DTLB        = 3,
	PERF_COUNT_HW_CACHE_ITLB        = 4,
	PERF_COUNT_HW_CACHE_BPU         = 5,
	PERF_COUNT_HW_CACHE_NODE        = 6,

	PERF_COUNT_HW_CACHE_MAX,        /* non-ABI */
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ     = 0,
	PERF_COUNT_HW_CACHE_OP_WRITE        = 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH     = 2,

	PERF_COUNT_HW_CACHE_OP_MAX,     /* non-ABI */
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS   = 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS     = 1,

	PERF_COUNT_HW_CACHE_RESULT_MAX,     /* non-ABI */
};

/*
 * Hardware event_id to monitor via a performance monitoring event:
 */
struct perf_event_attr {

	/*
	 * Major type: hardware/software/tracepoint/etc.
 	 */
	unsigned int			type;

	/*
	 * Size of the attr structure, for fwd/bwd compat.
 	 */
	unsigned int			size;

	/*
	 * Type specific configuration information.
 	 */
	unsigned long			config;

	union {
		unsigned long		sample_period;
		unsigned long		sample_freq;
	};

	unsigned long			sample_type;
	unsigned long			read_format;

	unsigned long		disabled       :  1, /* off by default        */
				inherit	       :  1, /* children inherit it   */
				pinned	       :  1, /* must always be on PMU */
				exclusive      :  1, /* only group on PMU     */
				exclude_user   :  1, /* don't count user      */
				exclude_kernel :  1, /* ditto kernel          */
				exclude_hv     :  1, /* ditto hypervisor      */
				exclude_idle   :  1, /* don't count when idle */
				mmap           :  1, /* include mmap data     */
				comm	       :  1, /* include comm data     */
				freq           :  1, /* use freq, not period  */
				inherit_stat   :  1, /* per task counts       */
				enable_on_exec :  1, /* next exec enables     */
				task           :  1, /* trace fork/exit       */
				watermark      :  1, /* wakeup_watermark      */
				/*
				 * precise_ip:
  				 *
 				 *  0 - SAMPLE_IP can have arbitrary skid
 				 *  1 - SAMPLE_IP must have constant skid
 				 *  2 - SAMPLE_IP requested to have 0 skid
 				 *  3 - SAMPLE_IP must have 0 skid
				 *
				 *  See also PERF_RECORD_MISC_EXACT_IP
				 */
				precise_ip     :  2, /* skid constraint       */
				mmap_data      :  1, /* non-exec mmap data    */
				sample_id_all  :  1, /* sample_type all events */

				exclude_host   :  1, /* don't count in host   */
				exclude_guest  :  1, /* don't count in guest  */

				exclude_callchain_kernel : 1, /* exclude kernel callchains */
				exclude_callchain_user   : 1, /* exclude user callchains */
				mmap2          :  1, /* include mmap with inode data     */

#ifdef __GENKSYMS__
				__reserved_1   : 40;
#else
				comm_exec      :  1, /* flag comm events that are due to an exec */
				__reserved_1   : 39;
#endif

	union {
		unsigned int		wakeup_events;	  /* wakeup every n events */
		unsigned int		wakeup_watermark; /* bytes before wakeup   */
	};

	unsigned int			bp_type;
	union {
		unsigned long		bp_addr;
		unsigned long		config1; /* extension of config */
	};
	union {
		unsigned long		bp_len;
		unsigned long		config2; /* extension of config1 */
	};
	unsigned long	branch_sample_type; /* enum perf_branch_sample_type */

	/*
	 * Defines set of user regs to dump on samples.
 	 * See asm/perf_regs.h for details.
 	 */
	unsigned long	sample_regs_user;

	/*
	 * Defines size of the user stack to dump on samples.
 	 */
	unsigned int	sample_stack_user;

	/* Align to unsigned long. */
	unsigned int	__reserved_2;
	/*
	 * Defines set of regs to dump for each sample
 	 * state captured on:
 	 *  - precise = 0: PMU interrupt
 	 *  - precise > 0: sampled instruction
	 *
 	 * See asm/perf_regs.h for details.
	 */
#ifndef __GENKSYMS__
	unsigned long	sample_regs_intr;
#endif
};

struct hw_perf_event_extra {
	unsigned long config;
	unsigned int reg;
	int idx;
};

struct hw_perf_event {
	/*
	 * The last observed hardware counter value, updated with a
	 * local64_cmpxchg() such that pmu::read() can be called nested.
	 */
	ihk_atomic64_t			prev_count;

	/*
	 * The period to start the next sample with.
	 */
	uint64_t			sample_period;

	/*
	 * The period we started this sample with.
	 */
	uint64_t			last_period;

	/*
	 * However much is left of the current period; note that this is
	 * a full 64bit value and allows for generation of periods longer
	 * than hardware might allow.
	 */
	ihk_atomic64_t			period_left;
};

/**
 * enum perf_event_state - the states of an event:
 */
enum perf_event_state {
	PERF_EVENT_STATE_INACTIVE   =  0,
	PERF_EVENT_STATE_ACTIVE     =  1,
};

struct mc_perf_event {
	struct perf_event_attr		attr;
	struct hw_perf_event_extra extra_reg;
	unsigned long		hw_config;
	unsigned long		hw_config_ext;
	enum perf_event_state		state;
	int 				cpu_id;
	int 				counter_id;	// counter_id
	ihk_atomic64_t			count;		// counter_value
	unsigned long			child_count_total;	// child_counter_value
	unsigned long 			pmc_status;
	unsigned long			sample_freq;

	struct mc_perf_event		*parent;
	struct mc_perf_event 		*group_leader;
	struct list_head		sibling_list;
	int 				nr_siblings;
	int				pid;
	struct list_head		group_entry;
	int				use_invariant_tsc;
	long long			base_user_tsc;
	long long			stopped_user_tsc;
	long long			user_accum_count;
	long long			base_system_tsc;
	long long			stopped_system_tsc;
	long long			system_accum_count;
	struct hw_perf_event		hw;
};

struct perf_event_mmap_page {
	unsigned int version;		// version number of this structure
	unsigned int compat_version;	// lowest version this is compat with
	unsigned int lock;		// seqlock for synchronization
	unsigned int index;		// hardware event identifier
	long	offset;			// add to hardware event value
	unsigned long time_enabled;	// time evet active
	unsigned long time_running;	// time event on cpu
	union {
		unsigned long   capabilities;
		struct {
			unsigned long   cap_bit0          : 1, // Always 0, deprecated
		                cap_bit0_is_deprecated    : 1, // Always 1, signals that bit 0 is zero
				cap_user_rdpmc            : 1, // The RDPMC instruction can be used to read counts
				cap_user_time             : 1, // The time_* fields are used
				cap_user_time_zero        : 1, // The time_zero field is used
				cap_____res               : 59;
		};
	};
	unsigned short pmc_width;
	unsigned short time_shift;
	unsigned int time_mult;
	unsigned long time_offset;
	unsigned long time_zero;
	unsigned int size;

	unsigned char __reserved[118*8+4];
	unsigned long data_head;
	unsigned long data_tail;
};

#endif

