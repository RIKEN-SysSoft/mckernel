/*
 * type.h
 *
 *  Created on: 2011/10/08
 *      Author: simin
 */

#ifndef TYPE_H_
#define TYPE_H_

#include <stdio.h>

typedef unsigned long int addr_t;

enum buf_type{
	HOST_BUF_TYPE,
	PCI_BUF_TYPE
};

typedef struct buf{
	void *buf;
	int size;
	enum buf_type type;
} buf_t;

#define free_buf(buf_p) {if(buf_p->type == HOST_BUF_TYPE) free(buf_p->buf); buf_p=NULL;}


#endif /* TYPE_H_ */
