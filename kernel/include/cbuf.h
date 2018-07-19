/* circular buffer */

#ifndef HEADER_CBUF_H
#define HEADER_CBUF_H

#include <ihk/types.h>

#define CBUF_MCKERNEL   0x01
#define CBUF_USERSPACE  0x02
#define CBUF_USERDIRECT 0x04

typedef uint64_t cbuf_t;

struct cbuf {
	size_t head;
	size_t tail;
	size_t size;
	size_t nelem;
	cbuf_t *buf;
	int nr_pages;
};

struct cbuf_arg {
	int fd;
	cbuf_t *base;
	cbuf_t *src_buf;
	cbuf_t *dst_buf;
	size_t len;
	ssize_t (*fun)(struct cbuf_arg *arg);
	int status;
};

int cbuf_init(struct cbuf **cbuf, size_t nelem);
int cbuf_destroy(struct cbuf **cbuf);
void cbuf_reset(struct cbuf *cbuf);

int cbuf_write(struct cbuf *cbuf, cbuf_t *buf, size_t len);
int cbuf_write_one(struct cbuf *cbuf, cbuf_t buf);

size_t cbuf_read_into_local_buffer(struct cbuf *cbuf, cbuf_t *buf, size_t len);
size_t cbuf_read_into_user_buffer(struct cbuf *cbuf, cbuf_t *buf, size_t len);
size_t cbuf_read_into_file(struct cbuf *cbuf, int fd, size_t len, int *status);

#endif // HEADER_CBUF_H
