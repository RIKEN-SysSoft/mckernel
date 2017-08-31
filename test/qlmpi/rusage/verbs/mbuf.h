/*
 * mbuf.h
 *
 *  Created on: 2011/10/19
 *      Author: simin
 */

#ifndef MBUF_H_
#define MBUF_H_

enum buf_type{
	HOST_BUF_TYPE,
	PCI_BUF_TYPE
};

typedef struct buf_t{
	void *buf;
	int size;
	enum buf_type type;
} buf_t;

#define buf_free(buf_p) {if(buf_p->type) free(buf_p->buf);}
#endif /* MBUF_H_ */
