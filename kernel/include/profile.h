#ifndef __PROCESS_PROFILE_H_
#define __PROCESS_PROFILE_H_

/* Uncomment this to enable profiling */
#define PROFILE_ENABLE

#ifdef PROFILE_ENABLE
#define PROFILE_SYSCALL_MAX                          300
#define PROFILE_OFFLOAD_MAX   (PROFILE_SYSCALL_MAX << 1)
#define PROFILE_EVENT_MIN            PROFILE_OFFLOAD_MAX
#define __NR_profile                                 701

#define PROF_JOB                       0x40000000
#define PROF_PROC                      0x80000000
#define PROF_CLEAR                           0x01
#define PROF_ON                              0x02
#define PROF_OFF                             0x04
#define PROF_PRINT                           0x08

struct profile_event {
	uint32_t cnt;
	uint64_t tsc;
};

/*
 * The layout of profile events is as follows:
 * [0,PROFILE_SYSCALL_MAX) - syscalls
 * [PROFILE_SYSCALL_MAX,PROFILE_OFFLOAD_MAX) - syscall offloads
 * [PROFILE_OFFLOAD_MAX,PROFILE_EVENT_MAX) - general events
 *
 * XXX: Make sure to fill in prof_event_names in profile.c
 * for each added profiled event.
 */
enum profile_event_type {
	PROFILE_tlb_invalidate = PROFILE_EVENT_MIN,
	PROFILE_page_fault,
	PROFILE_page_fault_anon_clr,
	PROFILE_page_fault_file,
	PROFILE_page_fault_dev_file,
	PROFILE_page_fault_file_clr,
	PROFILE_mpol_alloc_missed,
	PROFILE_mmap_anon_contig_phys,
	PROFILE_mmap_anon_no_contig_phys,
	PROFILE_mmap_regular_file,
	PROFILE_mmap_device_file,
	PROFILE_EVENT_MAX	/* Should be the last event type */
};

struct thread;
struct process;

enum profile_event_type profile_syscall2offload(enum profile_event_type sc);
void profile_event_add(enum profile_event_type type, uint64_t tsc);
void profile_print_thread_stats(struct thread *thread);
void profile_print_proc_stats(struct process *proc);
void profile_print_job_stats(struct process *proc);
void profile_accumulate_events(struct thread *thread, struct process *proc);
int profile_accumulate_and_print_job_events(struct process *proc);
int profile_alloc_events(struct thread *thread);
void profile_dealloc_thread_events(struct thread *thread);
void profile_dealloc_proc_events(struct process *proc);
#endif // PROFILE_ENABLE



#endif // __PROCESS_PROFILE_H_
