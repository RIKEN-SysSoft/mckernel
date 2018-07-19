#include <cbuf.h>
#include <kmalloc.h>
#include <string.h>
#include <mman.h>
#include <syscall.h>

//#define  PERFCTR_DEBUG

#ifdef PERFCTR_DEBUG
#define	dkprintf(...)	do { kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...)	do { kprintf(__VA_ARGS__); } while (0)
#else
#define	dkprintf(...)	do { } while (0)
#define	ekprintf(...)	do { kprintf(__VA_ARGS__); } while (0)
#endif

int cbuf_init(struct cbuf **cbuf, size_t nelem)
{
	int nr_pages;
	void *pages = NULL;
	int p2align = PAGE_P2ALIGN;

	/* alloc and initialize buffer */
	*cbuf = kmalloc(sizeof(struct cbuf), IHK_MC_PG_KERNEL);
	if (!*cbuf)
		return -ENOMEM;
	nelem += 1;

	nr_pages = ((nelem * sizeof(cbuf_t)) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if ((size_t)nr_pages << PAGE_SHIFT > LARGE_PAGE_SIZE)
		p2align = LARGE_PAGE_P2ALIGN;

	pages = ihk_mc_alloc_aligned_pages(nr_pages, p2align, IHK_MC_AP_NOWAIT);
	if (pages == NULL) {
		kprintf("%s: error: allocating cbuf\n", __func__);
		return -ENOMEM;
	}

	(*cbuf)->buf = pages;
	(*cbuf)->nr_pages = nr_pages;
	(*cbuf)->head  = 0;
	(*cbuf)->tail  = 0;
	(*cbuf)->nelem = nelem;
	(*cbuf)->size  = nelem*sizeof(cbuf_t);

	return 0;
}

int cbuf_destroy(struct cbuf **cbuf)
{
	if (!(*cbuf))
		return 0;

	if ((*cbuf)->buf) {
		ihk_mc_free_pages((*cbuf)->buf, (*cbuf)->nr_pages);
	}

	kfree(*cbuf);
	*cbuf = NULL;

	return 0;
}

int cbuf_write(struct cbuf *cbuf, cbuf_t *buf, size_t len)
{
	if (!cbuf || !cbuf->buf) {
		kprintf("cbuf buffer not allocated before writing\n");
		return -1;
	}

	/* cripple user buffer if it is bigger than cbuf */
	if (len >= cbuf->nelem) {
		buf = buf + len - (cbuf->nelem-1);
		len = cbuf->nelem-1;
		cbuf->head = 0;
		cbuf->tail = 0;
	}

	/* buffer overflow */
	if (cbuf->head + len >= cbuf->nelem) {
		dkprintf(" - write: buffer overflow\n");
		size_t chunk1, chunk2;
		size_t data_lost = 0;

		chunk1 = cbuf->nelem - cbuf->head;
		chunk2 = len - chunk1;

		/* first chunk */
		memcpy(&cbuf->buf[cbuf->head], buf, chunk1*sizeof(cbuf_t));

		/* second chunk */
		memcpy(cbuf->buf, buf+chunk1, chunk2*sizeof(cbuf_t));

		/* update tail */
		if (cbuf->tail > cbuf->head) {
			data_lost = cbuf->nelem - cbuf->tail + chunk2 + 1;
		} else if (cbuf->tail <= chunk2) {
			data_lost = chunk2 - cbuf->tail + 1;
		}

		if (data_lost) {
			cbuf->tail = (chunk2+1)%cbuf->nelem;
			dkprintf("PEBS cbuf data lost: %lu records\n", data_lost);
		}

		cbuf->head = chunk2;
	/* no buffer overflow but data override */
	} else if ((cbuf->head < cbuf->tail) &&
		   (cbuf->head + len >= cbuf->tail)) {
		dkprintf(" - write: data override\n");
#ifdef PERFCTR_DEBUG
		size_t data_lost = 0;
#endif
		memcpy(&cbuf->buf[cbuf->head], buf, len*sizeof(cbuf_t));
#ifdef PERFCTR_DEBUG
		data_lost = cbuf->head+len - cbuf->tail + 1;
#endif
		cbuf->head += len;
		cbuf->tail = (cbuf->head+1)%cbuf->nelem;
		dkprintf("PEBS cbuf data lost: %lu records\n", data_lost);
	/* no buffer overflow and no data override */
	} else {
		dkprintf(" - write: normal\n");
		memcpy(&cbuf->buf[cbuf->head], buf, len*sizeof(cbuf_t));
		cbuf->head += len;
	}

	return 0;
}

int cbuf_write_one(struct cbuf *cbuf, cbuf_t val)
{
	if (!cbuf || !cbuf->buf) {
		kprintf("cbuf buffer not allocated before writing one\n");
		return 0;
	}

	cbuf->buf[cbuf->head] = val;
	cbuf->head = (cbuf->head + 1) % cbuf->nelem;

	if (cbuf->head == cbuf->tail) {
		dkprintf("PEBS cbuf data lost: 1 records\n");
		cbuf->tail = (cbuf->tail + 1)%cbuf->nelem;
	}

	return 0;
}

size_t __cbuf_read(struct cbuf *cbuf, struct cbuf_arg *args)
{
	size_t ret, err;
	size_t len;

	len = args->len;

	if (!cbuf || !cbuf->buf) {
		kprintf("cbuf buffer not allocated before reading\n");
		return 0;
	}

	if (cbuf->tail == 0 && cbuf->head == 0)
		return 0;

	if (len >= cbuf->nelem)
		len = cbuf->nelem-1;

	/* buffer overflow */
	if ((cbuf->tail + len >= cbuf->nelem) && (cbuf->tail > cbuf->head)) {
		dkprintf(" - read: overflow\n");
		size_t chunk1, chunk2;

		chunk1 = cbuf->nelem - cbuf->tail;
		chunk2 = (len-chunk1 <= cbuf->head)? len - chunk1 : cbuf->head;

		/* first chunk */
		args->src_buf = &args->base[cbuf->tail];
		args->len = chunk1*sizeof(cbuf_t);
		if ((err = args->fun(args))) {
			args->status = err;
			return 0;
		}

		/* second chunk */
		args->dst_buf += chunk1;
		args->src_buf  = args->base;
		args->len      = chunk2*sizeof(cbuf_t);
		if ((err = args->fun(args))) {
			args->status = err;
			return 0;
		}

		cbuf->tail = chunk2;
		ret = chunk1+chunk2;
	/* no buffer overflow */
	} else {
		dkprintf(" - read: no overflow\n");
		size_t chunk;
		if (cbuf->tail > cbuf->head)
			chunk = len;
		else
			chunk = (cbuf->tail + len >= cbuf->head)?
				cbuf->head - cbuf->tail : len;

		dkprintf("head: %zu tail: %zu chunk: %zu\n", cbuf->head,
		       cbuf->tail, chunk);
		args->src_buf = &args->base[cbuf->tail];
		args->len     = chunk*sizeof(cbuf_t);
		if ((err = args->fun(args))) {
			args->status = err;
			return 0;
		}
		cbuf->tail += chunk;
		ret = chunk;
	}

	/* if tail == head, buffer is empy */
	if (cbuf->tail == cbuf->head) {
		cbuf->tail = 0;
		cbuf->head = 0;
	}

	return ret;
}

void cbuf_reset(struct cbuf *cbuf)
{
	if (!cbuf || !cbuf->buf) {
		kprintf("cbuf buffer not allocated before reset\n");
	}

	cbuf->head = 0;
	cbuf->tail = 0;
}

ssize_t __copy_to_local_buf(struct cbuf_arg *args) {
	memcpy(args->dst_buf, args->src_buf, args->len);
	return 0;
}

ssize_t __copy_to_user_buf(struct cbuf_arg *args) {
	//TODO distinguish between CBUF_USERSPACE and CBUF_USERDIRECT
	return copy_to_user(args->dst_buf, args->src_buf, args->len);
}

ssize_t __copy_to_file(struct cbuf_arg *args)
{
	ihk_mc_user_context_t ctx;
	size_t written, ret, len;
	ssize_t write_ret;
	unsigned long buf;
	int fd;

	fd = args->fd;
	len = args->len;
	buf = (unsigned long) args->src_buf;

	written = 0;
	ret = 0;

	dkprintf("%s: len: %lu, written: %lu\n",
		__func__, len, written);
	do {
		ihk_mc_syscall_arg0(&ctx) = fd;
		ihk_mc_syscall_arg1(&ctx) = buf + written;
		ihk_mc_syscall_arg2(&ctx) = len - written;

		write_ret = syscall_generic_forwarding(__NR_write, &ctx);
		dkprintf("%s: to write: %lu, write_ret: %ld\n",
			__func__, len - written, write_ret);

		if (write_ret < 0) {
			ret = write_ret;
			break;
		}

		written += (size_t) write_ret;
		dkprintf("%s: len: %lu, written: %lu\n",
			__func__, len, written);

	} while (written != len);

	return ret;
}


size_t cbuf_read_into_local_buffer(struct cbuf *cbuf, cbuf_t *buf, size_t len)
{
	struct cbuf_arg cbuf_args = {
		.base = cbuf->buf,
		.dst_buf = buf,
		.len = len,
		.fun = __copy_to_local_buf,
		.status = 0,
	};

	return __cbuf_read(cbuf, &cbuf_args);
}

size_t cbuf_read_into_user_buffer(struct cbuf *cbuf, cbuf_t *buf, size_t len)
{
	struct cbuf_arg cbuf_args = {
		.base = cbuf->buf,
		.dst_buf = buf,
		.len = len,
		.fun = __copy_to_user_buf,
		.status = 0,
	};

	return __cbuf_read(cbuf, &cbuf_args);
}

size_t cbuf_read_into_file(struct cbuf *cbuf, int fd, size_t len, int *status)
{
	void *user_buf;
	struct cbuf_arg cbuf_args = {
		.fd = fd,
		.len = len,
		.fun = __copy_to_file,
		.status = 0,
	};
	size_t ret = 0;

	/* Map cbuf to user-space */
	user_buf = map_pages_to_user(cbuf->buf, cbuf->nr_pages, VR_REMOTE);
	if (user_buf == NULL) {
		kprintf("%s: error: mapping PEBS buffer", __func__);
		*status = -ENOMEM;
		goto out;
	}

	dkprintf("%s: len=%zu cbuf->size=%zu cbuf->nelem=%zu\n",
		__func__, len, cbuf->size, cbuf->nelem);

	/* Use user buffer as base address */
	cbuf_args.base = (cbuf_t *)user_buf;

	ret = __cbuf_read(cbuf, &cbuf_args);
	*status = cbuf_args.status;

	dkprintf("cbuf_read_into_file: ret=%zu, bytes=%zu, status=%d\n",
		ret, ret*sizeof(cbuf_t), *status);

	do_munmap(user_buf, cbuf->nr_pages << PAGE_SHIFT);

out:
	return ret;
}

