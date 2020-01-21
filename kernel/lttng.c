#include <lttng.h>
#include <kmsg.h>
#include <registers.h>
#include <cls.h>
#include <ihk/cpu.h>
#include <kmalloc.h>


#define LTTNG_TRACE_BUFFER_SIZE (1024*1024*64)
#define LTTNG_TRACE_BUFFER_PAGES \
	((LTTNG_TRACE_BUFFER_SIZE + 4095) >> PAGE_SHIFT)

static const char *metadata = "/* CTF 1.8 */\n"
	"\n"
	"typealias integer { size = 8; align = 8; signed = false; }  := uint8_t;\n"
	"typealias integer { size = 16; align = 8; signed = false; } := uint16_t;\n"
	"typealias integer { size = 32; align = 8; signed = false; } := uint32_t;\n"
	"typealias integer { size = 64; align = 8; signed = false; } := uint64_t;\n"
	"typealias integer { size = 64; align = 8; signed = false; } := unsigned long;\n"
	"typealias integer { size = 5; align = 1; signed = false; }  := uint5_t;\n"
	"typealias integer { size = 27; align = 1; signed = false; } := uint27_t;\n"
	"\n"
	"trace {\n"
	"	major = 1;\n"
	"	minor = 8;\n"
	"	byte_order = le;\n"
	"	packet.header := struct {\n"
	"		uint32_t magic;\n"
	"		uint32_t stream_id;\n"
	"	};\n"
	"};\n"
	"\n"
	"env {\n"
	"	domain = \"kernel\";\n"
	"	tracer_name = \"lttng-modules\";\n"
	"	tracer_major = 2;\n"
	"	tracer_minor = 11;\n"
	"	tracer_patchlevel = 0;\n"
	"};\n"
	"\n"
	"clock {\n"
	"	name = \"monotonic\";\n"
	"	description = \"Monotonic Clock\";\n"
	"	freq = 1000000000; /* Frequency, in Hz */\n"
	"	/* clock value offset from Epoch is: offset * (1/freq) */\n"
	"	offset = 1578378831114078890;\n"
	"};\n"
	"\n"
	"typealias integer {\n"
	"	size = 64;\n"
	"	align = 8;\n"
	"	signed = false;\n"
	"	map = clock.monotonic.value;\n"
	"} := uint64_clock_monotonic_t;\n"
	"\n"
	"stream {\n"
	"	id = 0;\n"
	"	packet.context := struct {\n"
	"		uint32_t cpu_id;\n"
	"	};\n"
	"	event.header := struct {\n"
	"		uint32_t id;\n"
	"		uint64_clock_monotonic_t timestamp;\n"
	"	};\n"
	"};\n"
	"\n"
	"event {\n"
	"	name = \"sched_switch\";\n"
	"	id = 0;\n"
	"	stream_id = 0;\n"
	"	fields := struct {\n"
	"		integer { size = 8; align = 8; signed = 0; encoding = UTF8; base = 10; } _prev_comm[16];\n"
	"		integer { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _prev_tid;\n"
	"		integer { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _prev_prio;\n"
	"		integer { size = 64; align = 8; signed = 1; encoding = none; base = 10; } _prev_state;\n"
	"		integer { size = 8; align = 8; signed = 0; encoding = UTF8; base = 10; } _next_comm[16];\n"
	"		integer { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _next_tid;\n"
	"		integer { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _next_prio;\n"
	"	};\n"
	"};\n"
	"\n"
	"event {\n"
	"	name = \"syscall_entry_futex\";\n"
	"	id = 188;\n"
	"	stream_id = 0;\n"
	"	fields := struct {\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _uaddr;\n"
	"		integer { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _op;\n"
	"		integer { size = 32; align = 8; signed = 0; encoding = none; base = 10; } _val;\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _utime;\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _uaddr2;\n"
	"		integer { size = 32; align = 8; signed = 0; encoding = none; base = 10; } _val3;\n"
	"	};\n"
	"};\n"
	"\n"
	"event {\n"
	"	name = \"syscall_exit_futex\";\n"
	"	id = 477;\n"
	"	stream_id = 0;\n"
	"	fields := struct {\n"
	"		integer { size = 64; align = 8; signed = 1; encoding = none; base = 10; } _ret;\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _uaddr;\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _uaddr2;\n"
	"	};\n"
	"};\n"
	"\n"
	"event {\n"
	"	name = \"syscall_entry_mmap\";\n"
	"	id = 13;\n"
	"	stream_id = 0;\n"
	"	fields := struct {\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 16; } _addr;\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _len;\n"
	"		integer { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _prot;\n"
	"		integer { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _flags;\n"
	"		integer { size = 32; align = 8; signed = 1; encoding = none; base = 10; } _fd;\n"
	"		integer { size = 64; align = 8; signed = 1; encoding = none; base = 10; } _offset;\n"
	"	};\n"
	"};\n"
	"\n"
	"event {\n"
	"	name = \"syscall_exit_mmap\";\n"
	"	id = 302;\n"
	"	stream_id = 0;\n"
	"	fields := struct {\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 16; } _ret;\n"
	"	};\n"
	"};\n"
	"\n"
	"event {\n"
	"	name = \"syscall_entry_mprotect\";\n"
	"	id = 14;\n"
	"	stream_id = 0;\n"
	"	fields := struct {\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _start;\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _len;\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _prot;\n"
	"	};\n"
	"};\n"
	"\n"
	"event {\n"
	"	name = \"syscall_exit_mprotect\";\n"
	"	id = 303;\n"
	"	stream_id = 0;\n"
	"	fields := struct {\n"
	"		integer { size = 64; align = 8; signed = 1; encoding = none; base = 10; } _ret;\n"
	"	};\n"
	"};\n"
	"\n"
	"event {\n"
	"	name = \"syscall_entry_munmap\";\n"
	"	id = 15;\n"
	"	stream_id = 0;\n"
	"	fields := struct {\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _addr;\n"
	"		integer { size = 64; align = 8; signed = 0; encoding = none; base = 10; } _len;\n"
	"	};\n"
	"};\n"
	"\n"
	"event {\n"
	"	name = \"syscall_exit_munmap\";\n"
	"	id = 304;\n"
	"	stream_id = 0;\n"
	"	fields := struct {\n"
	"		integer { size = 64; align = 8; signed = 1; encoding = none; base = 10; } _ret;\n"
	"	};\n"
	"};\n";

struct __attribute__((__packed__)) event_header {
	uint32_t id;
	uint64_t timestamp;
};


static int mk_packet_header(char *buf, size_t *len, const size_t bs)
{
	struct __attribute__((__packed__)) packet_header {
		uint32_t magic;
		uint32_t stream_id;
	};

	const int pks = sizeof(struct packet_header);
	struct packet_header *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct packet_header *) &buf[*len];
	*pk = (struct packet_header) {
		.magic = 0xc1fc1fc1,
		.stream_id = 0
	};

	*len += pks;

	return 0;
}

static int mk_packet_context(char *buf, size_t *len, const size_t bs,
		      uint32_t cpu_id)
{
	struct __attribute__((__packed__)) packet_context {
		uint32_t cpu_id;
	};

	const int pks = sizeof(struct packet_context);
	struct packet_context *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct packet_context *) &buf[*len];
	*pk = (struct packet_context) {
		.cpu_id = cpu_id,
	};

	*len += pks;

	return 0;
}

static int mk_event_header(struct event_header *pk, uint32_t id)
{
	*pk = (struct event_header) {
		.id = id,
		.timestamp = rdtsc()
	};

	return 0;
}

static int alloc_lttng_trace_buffer(struct lttng_trace *lt)
{
	int p2align = PAGE_P2ALIGN;

	lt->size = LTTNG_TRACE_BUFFER_SIZE;
	lt->len = 0;

	kprintf("lttng: allocating buffer\n");
	lt->buffer = ihk_mc_alloc_aligned_pages(LTTNG_TRACE_BUFFER_PAGES,
						p2align, IHK_MC_AP_NOWAIT);
	if (!lt->buffer) {
		kprintf("Error: Cannot allocate lttng buffer\n");
		return -ENOMEM;
	}
	kprintf("lttng: memsetting buffer\n");
	memset((void *)lt->buffer, 0, lt->size);

	return 0;
}

void lttng_init(void)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	alloc_lttng_trace_buffer(lt);
}

int lttng_trace_core_dump(void)
{
	int ret;
	struct lttng_trace *lt;

	lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer || lt->fd < 0 || !lt->len)
		return 0;

	kprintf("LTTng flushing %lu/%lu bytes\n", lt->len, lt->size);
	ret = forward_write(lt->fd, lt->user_map, lt->len);
	if (ret) {
		kprintf("%s: error: writing LTTng buffer ret = %d\n",
			__func__, ret);
		return 1;
	}

	if (lt->lost)
		kprintf("WARNING: LTTng lost event count: %lu\n", lt->lost);

	lt->len = 0;
	lt->lost = 0;

	return 0;
}

static void lttng_trace_write_headers(struct lttng_trace *lt, int cpu_id)
{
	lt->len = 0;
	mk_packet_header(lt->buffer, &lt->len, lt->size);
	mk_packet_context(lt->buffer, &lt->len, lt->size, (uint32_t) cpu_id);
}

// Initialize the LTTng trace directory for this run. This function must be
// called before any applicaiton thread has started running because it sets up
// per-cpu variables for all involved cpus.
void lttng_trace_prepare_directory(void)
{
	unsigned long long *krn_fn_buf = 0, *usr_fn_buf = 0;
	int p2align = PAGE_P2ALIGN;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct lttng_trace *lt;
	int off;
	ihk_mc_user_context_t ctx1, ctx2;
	int fd, md_fd;
	char *exec = "mcexec";
	int error;
	int ret;
	int i;

	if (!proc->lttng)
		return;

	kprintf("allocating LTTng filename buffer\n");
	krn_fn_buf = ihk_mc_alloc_aligned_pages(1, p2align, IHK_MC_AP_NOWAIT);
	if (krn_fn_buf == 0) {
		kprintf("%s: error: Cannot allocate filename LTTng buffer\n",
			__func__);
		return;
	}

	kprintf("maping to user\n");
	usr_fn_buf = map_pages_to_user(krn_fn_buf, 1, VR_REMOTE);
	if (usr_fn_buf == NULL) {
		kprintf("%s: error: mapping LTTng buffer\n", __func__);
		goto free_fn_buf;
	}

	if (proc->saved_cmdline) {
		exec = strrchr(proc->saved_cmdline, '/');
		if (exec) {
			/* Point after '/' */
			++exec;
		} else {
			exec = proc->saved_cmdline;
		}
	}

	// create trace directories
	kprintf("writing to kernel buffer\n");
	off = snprintf((char *) krn_fn_buf, PATH_MAX, "lttng-%s-%lu",
		       exec, rdtsc());
	ihk_mc_syscall_arg0(&ctx1) = (intptr_t)usr_fn_buf;
	ihk_mc_syscall_arg1(&ctx1) = 00777;
	kprintf("trying to create <trace>/ LTTng directory: %s\n", krn_fn_buf);
	ret = syscall_generic_forwarding(__NR_mkdir, &ctx1);
	if (ret < 0) {
		kprintf("%s: error: cannot create lttng directory: %d",
			__func__, ret);
		goto unmap_fn_usrbuf;
	}

	kprintf("writing to kernel buffer\n");
	off += snprintf((char *) krn_fn_buf + off, PATH_MAX - off, "/kernel");
	ihk_mc_syscall_arg0(&ctx1) = (intptr_t)usr_fn_buf;
	ihk_mc_syscall_arg1(&ctx1) = 00777;
	kprintf("trying to create <trace>/kernel LTTng directory: %s\n",
		krn_fn_buf);
	ret = syscall_generic_forwarding(__NR_mkdir, &ctx1);
	if (ret < 0) {
		kprintf("%s: error: cannot create lttng directory: %d",
			__func__, ret);
		goto unmap_fn_usrbuf;
	}

	// TODO: move me to some more appropriate place
#define O_RDWR		00000002
#define O_CREAT		00000100
#define O_TRUNC		00001000

	// map all per cpu buffers to user-space
	for (i = 0; i < num_processors; i++) {
		lt = &get_cpu_local_var(i)->lttng_trace;
		// map per cpu file to user-space
		kprintf("mapping %d LTTng buffer pages at %p to user space\n",
			LTTNG_TRACE_BUFFER_PAGES, lt->buffer);
		lt->user_map = map_pages_to_user(lt->buffer,
						 LTTNG_TRACE_BUFFER_PAGES,
						 VR_REMOTE);
		if (lt->user_map == NULL) {
			kprintf("%s: error: mapping LTTng buffer\n", __func__);
			// TODO add code to unmap regions, for some reason it
			// was crashing when attempting to unmap
			goto unmap_fn_usrbuf;
		}
	}

	// write metadata file
	snprintf((char *) krn_fn_buf + off, PATH_MAX - off, "/metadata");
	ihk_mc_syscall_arg0(&ctx1) = (intptr_t)usr_fn_buf;
	ihk_mc_syscall_arg1(&ctx1) = O_RDWR | O_CREAT | O_TRUNC;
	ihk_mc_syscall_arg2(&ctx1) = 00600;
	kprintf("trying to open the file: %s\n", krn_fn_buf);
	md_fd = syscall_generic_forwarding(__NR_open, &ctx1);
	if (md_fd < 0) {
		kprintf("%s: error: can't open metadata file: %s, md_fd = %d",
			__func__, krn_fn_buf, md_fd);
		goto unmap_fn_usrbuf;
	}
	lt = &cpu_local_var(lttng_trace);
	strncpy(lt->buffer, metadata, strlen(metadata));
	ret = forward_write(md_fd, lt->user_map, strlen(metadata));
	if (ret) {
		kprintf("%s: error: writing LTTng metadata\n", __func__);
		goto close_metadata_fd;
	}

	// we want to open the per core trace file at the beginning of the
	// execution to support buffer flushes while the application is running.
	error = 0;
	for (i = 0; i < num_processors; i++) {
		lt = &get_cpu_local_var(i)->lttng_trace;

		// open per-cpu output file
		snprintf((char *) krn_fn_buf + off, PATH_MAX - off,
			 "/channel_%d", i);
		ihk_mc_syscall_arg0(&ctx1) = (intptr_t)usr_fn_buf;
		ihk_mc_syscall_arg1(&ctx1) = O_RDWR | O_CREAT | O_TRUNC;
		ihk_mc_syscall_arg2(&ctx1) = 00600;
		kprintf("trying to open the file: %s\n", krn_fn_buf);
		fd = syscall_generic_forwarding(__NR_open, &ctx1);
		if (fd < 0) {
			kprintf("%s: error: can't open LTTng out file: %s, fd = %d",
				__func__, krn_fn_buf, fd);

			error = 1;
			break;
		}
		lt->fd = fd;

		// write LTTng per core file headers
		lttng_trace_write_headers(lt, i);

		// reset lost events count
		lt->lost = 0;
	}

	// close fd's on error
	if (error) {
		i--;
		for (; i >= 0; i--) {
			lt = &get_cpu_local_var(i)->lttng_trace;
			kprintf("closing the file!\n");
			ihk_mc_syscall_arg0(&ctx2) = lt->fd;
			ret = syscall_generic_forwarding(__NR_close, &ctx2);
			if (ret < 0) {
				kprintf("%s: error: Can't close LTTng out file. fd = %d",
					__func__, ret);
			}
			lt->fd = -1;
		}
	}

close_metadata_fd:
	kprintf("closing the metadata file!\n");
	ihk_mc_syscall_arg0(&ctx2) = md_fd;
	ret = syscall_generic_forwarding(__NR_close, &ctx2);
	if (ret < 0) {
		kprintf("%s: error: can't close LTTng metadata. fd = %d",
			__func__, ret);
	}

unmap_fn_usrbuf:
	kprintf("unmap filename kernel buffer\n");
	if (do_munmap((void *)usr_fn_buf, 4096, 0))
		kprintf("%s:error: unmaping PEBS user buffer\n", __func__);

free_fn_buf:
	kprintf("free filename user buffer\n");
	ihk_mc_free_pages(krn_fn_buf, 1);
}

static size_t mk_sched_switch(char *buf, size_t *len, const size_t bs,
		       unsigned char *prev_comm,
		       int32_t prev_tid, int32_t prev_prio, int64_t prev_state,
		       unsigned char *next_comm,
		       int32_t next_tid, int32_t next_prio)
{
	struct __attribute__((__packed__)) sched_switch {
		struct event_header event_header;
		unsigned char prev_comm[16];
		int32_t prev_tid;
		int32_t prev_prio;
		int64_t prev_state;
		unsigned char next_comm[16];
		int32_t next_tid;
		int32_t next_prio;
	};

	const uint32_t id = 0;
	const int pks = sizeof(struct sched_switch);
	struct sched_switch *pk;
	int i;

	if (*len + pks >= bs)
		return 1;

	pk = (struct sched_switch *) &buf[*len];

	*pk = (struct sched_switch) {
		.prev_tid   = prev_tid,
		.prev_prio  = prev_prio,
		.prev_state = prev_state,
		.next_tid   = next_tid,
		.next_prio  = next_prio
	};

	mk_event_header(&pk->event_header, id);

	// prev_comm
	for (i = 0; i < sizeof(pk->prev_comm) && prev_comm[i]; i++)
		pk->prev_comm[i] = prev_comm[i];
	for (; i < sizeof(pk->prev_comm); i++)
		pk->prev_comm[i] = '\0';
	// next_comm
	for (i = 0; i < sizeof(pk->next_comm) && next_comm[i]; i++)
		pk->next_comm[i] = next_comm[i];
	for ( ; i < sizeof(pk->next_comm); i++)
		pk->next_comm[i] = '\0';

	*len += pks;

	return 0;
}

static size_t mk_entry_futex(char *buf, size_t *len, const size_t bs,
			     uint64_t uaddr, int32_t op, uint32_t val,
			     uint64_t utime, uint64_t uaddr2, uint32_t val3)
{
	struct __attribute__((__packed__)) entry_futex {
		struct event_header event_header;
		uint64_t uaddr;
		int32_t op;
		uint32_t val;
		uint64_t utime;
		uint64_t uaddr2;
		uint32_t val3;
	};

	const uint32_t id = 188;
	const int pks = sizeof(struct entry_futex);
	struct entry_futex *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct entry_futex *) &buf[*len];

	*pk = (struct entry_futex) {
		.uaddr   = uaddr,
		.op      = op,
		.val     = val,
		.utime   = utime,
		.uaddr2  = uaddr2,
		.val3    = val3,
	};

	mk_event_header(&pk->event_header, id);

	*len += pks;

	return 0;
}

static size_t mk_exit_futex(char *buf, size_t *len, const size_t bs,
			    int64_t ret, uint64_t uaddr, uint64_t uaddr2)
{
	struct __attribute__((__packed__)) exit_futex {
		struct event_header event_header;
		int64_t  ret;
		uint64_t uaddr;
		uint64_t uaddr2;
	};

	const uint32_t id = 477;
	const int pks = sizeof(struct exit_futex);
	struct exit_futex *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct exit_futex *) &buf[*len];

	*pk = (struct exit_futex) {
		.ret    = ret,
		.uaddr  = uaddr,
		.uaddr2 = uaddr2,
	};

	mk_event_header(&pk->event_header, id);

	*len += pks;

	return 0;
}

static size_t mk_entry_mmap(char *buf, size_t *len, const size_t bs,
			    uint64_t addr, uint64_t len0, int32_t prot,
			    int32_t flags, int32_t fd, int64_t offset)
{
	struct __attribute__((__packed__)) entry_mmap {
		struct event_header event_header;
		uint64_t addr;
		uint64_t len;
		int32_t  prot;
		int32_t  flags;
		int32_t  fd;
		int64_t  offset;
	};

	const uint32_t id = 13;
	const int pks = sizeof(struct entry_mmap);
	struct entry_mmap *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct entry_mmap *) &buf[*len];

	*pk = (struct entry_mmap) {
		.addr   = addr,
		.len    = len0,
		.prot   = prot,
		.flags  = flags,
		.fd     = fd,
		.offset = offset,
	};

	mk_event_header(&pk->event_header, id);

	*len += pks;

	return 0;
}

static size_t mk_exit_mmap(char *buf, size_t *len, const size_t bs,
			   uint64_t ret)
{
	struct __attribute__((__packed__)) exit_mmap {
		struct event_header event_header;
		uint64_t ret;
	};

	const uint32_t id = 302;
	const int pks = sizeof(struct exit_mmap);
	struct exit_mmap *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct exit_mmap *) &buf[*len];

	*pk = (struct exit_mmap) {
		.ret   = ret,
	};

	mk_event_header(&pk->event_header, id);

	*len += pks;

	return 0;
}

static size_t mk_entry_munmap(char *buf, size_t *len, const size_t bs,
			      uint64_t addr, uint64_t len0)
{
	struct __attribute__((__packed__)) entry_munmap {
		struct event_header event_header;
		uint64_t addr;
		uint64_t len;
	};

	const uint32_t id = 15;
	const int pks = sizeof(struct entry_munmap);
	struct entry_munmap *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct entry_munmap *) &buf[*len];

	*pk = (struct entry_munmap) {
		.addr   = addr,
		.len    = len0,
	};

	mk_event_header(&pk->event_header, id);

	*len += pks;

	return 0;
}

static size_t mk_exit_munmap(char *buf, size_t *len, const size_t bs,
			     int64_t ret)
{
	struct __attribute__((__packed__)) exit_munmap {
		struct event_header event_header;
		int64_t ret;
	};

	const uint32_t id = 304;
	const int pks = sizeof(struct exit_munmap);
	struct exit_munmap *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct exit_munmap *) &buf[*len];

	*pk = (struct exit_munmap) {
		.ret = ret,
	};

	mk_event_header(&pk->event_header, id);

	*len += pks;

	return 0;
}

static size_t mk_entry_mprotect(char *buf, size_t *len, const size_t bs,
				uint64_t start, uint64_t len0, uint64_t prot)
{
	struct __attribute__((__packed__)) entry_mprotect {
		struct event_header event_header;
		uint64_t start;
		uint64_t len;
		uint64_t prot;
	};

	const uint32_t id = 14;
	const int pks = sizeof(struct entry_mprotect);
	struct entry_mprotect *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct entry_mprotect *) &buf[*len];

	*pk = (struct entry_mprotect) {
		.start  = start,
		.len    = len0,
		.prot   = prot,
	};

	mk_event_header(&pk->event_header, id);

	*len += pks;

	return 0;
}

static size_t mk_exit_mprotect(char *buf, size_t *len, const size_t bs,
			       int64_t ret)
{
	struct __attribute__((__packed__)) exit_mprotect {
		struct event_header event_header;
		int64_t ret;
	};

	const uint32_t id = 303;
	const int pks = sizeof(struct exit_mprotect);
	struct exit_mprotect *pk;

	if (*len + pks >= bs)
		return 1;

	pk = (struct exit_mprotect *) &buf[*len];

	*pk = (struct exit_mprotect) {
		.ret = ret,
	};

	mk_event_header(&pk->event_header, id);

	*len += pks;

	return 0;
}






void trace_entry_futex(uint64_t uaddr, int32_t op, uint32_t val,
		       uint64_t utime, uint64_t uaddr2, uint32_t val3)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer)
		return;

	if (mk_entry_futex(lt->buffer, &lt->len, lt->size,
			   uaddr, op, val, utime, uaddr2, val3))
		lt->lost++;
}

void trace_exit_futex(int64_t ret, uint64_t uaddr, uint64_t uaddr2)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer)
		return;

	if (mk_exit_futex(lt->buffer, &lt->len, lt->size,
			  ret, uaddr, uaddr2))
		lt->lost++;
}

void trace_entry_mmap(uint64_t addr, uint64_t len, int32_t prot,
		      int32_t flags, int32_t fd, int64_t offset)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer)
		return;

	if (mk_entry_mmap(lt->buffer, &lt->len, lt->size,
			  addr, len, prot, flags, fd, offset))
		lt->lost++;
}

void trace_exit_mmap(uint64_t ret)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer)
		return;

	if (mk_exit_mmap(lt->buffer, &lt->len, lt->size,
			 ret))
		lt->lost++;
}

void trace_entry_munmap(uint64_t addr, uint64_t len)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer)
		return;

	if (mk_entry_munmap(lt->buffer, &lt->len, lt->size,
			    addr, len))
		lt->lost++;
}

void trace_exit_munmap(int64_t ret)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer)
		return;

	if (mk_exit_munmap(lt->buffer, &lt->len, lt->size,
			   ret))
		lt->lost++;
}

void trace_entry_mprotect(uint64_t start, uint64_t len, uint64_t prot)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer)
		return;

	if (mk_entry_mprotect(lt->buffer, &lt->len, lt->size,
			      start, len, prot))
		lt->lost++;
}

void trace_exit_mprotect(int64_t ret)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer)
		return;

	if (mk_exit_mprotect(lt->buffer, &lt->len, lt->size,
			     ret))
		lt->lost++;
}

void trace_sched_switch(char *prev_comm,
			int32_t prev_tid, int32_t prev_prio, int64_t prev_state,
			char *next_comm,
			int32_t next_tid, int32_t next_prio)
{
	struct lttng_trace *lt = &cpu_local_var(lttng_trace);

	if (!lt->buffer)
		return;

	prev_state = (prev_state == 1) ? 0 : prev_state;

	if (mk_sched_switch(lt->buffer, &lt->len, lt->size,
			    (unsigned char *)prev_comm, prev_tid, prev_prio,
			    prev_state,
			    (unsigned char *)next_comm, next_tid, next_prio))
		lt->lost++;
}

