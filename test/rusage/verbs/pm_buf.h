/*
 * pm_buf.h
 *
 *  Created on: 2011/10/21
 *      Author: simin
 */

#ifndef PM_BUF_H_
#define PM_BUF_H_

struct pm_buf_ops {
	void* (*alloc_buf)(int size);
	void (*free_buf)(void *buf);
};

#endif /* PM_BUF_H_ */
