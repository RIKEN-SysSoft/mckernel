/*
 * mm_ib_test.h
 *
 *  Created on: 2011/10/14
 *      Author: simin
 */

#ifndef MM_IB_TEST_H_
#define MM_IB_TEST_H_

//#define USE_1_SERVER 1


//#define TEST_BUF_SIZE 16
#define TEST_SERVER_BUF_NUM 2

#define TEST_COMM_HOST_BASE_ADDR 0x20001
#define TEST_COMM_CORE_BASE_ADDR (0x20000 << 11)

/* MR buffer setting info */
#define TEST_HOST_MR_PAGE_NO 0
#define TEST_MR_BUF_OFFSET 0
#define TEST_MR_HOST_BUF_SIZE 4096

#define TEST_MR_HOST_BUF_ADDR (TEST_COMM_HOST_BASE_ADDR + TEST_MR_BUF_OFFSET)
#define TEST_MR_CORE_BUF_ADDR (TEST_COMM_CORE_BASE_ADDR + TEST_MR_BUF_OFFSET)

/*
#define TEST_S2_HOST_MR_PAGE_NO 1
#define TEST_S2_COMM_HOST_BASE_ADDR 0x30001
#define TEST_S2_COMM_CORE_BASE_ADDR (0x30000 << 11)
#define TEST_S2_MR_HOST_BUF_ADDR TEST_S2_COMM_HOST_BASE_ADDR + TEST_MR_BUF_OFFSET
#define TEST_S2_MR_CORE_BUF_ADDR TEST_S2_COMM_CORE_BASE_ADDR + TEST_MR_BUF_OFFSET
*/

/* CQ buffer setting info */
#define TEST_HOST_CQ_PAGE_NO 1
#define TEST_CQ_BUF_OFFSET (TEST_MR_BUF_OFFSET + TEST_MR_HOST_BUF_SIZE)
#define TEST_CQ_HOST_BUF_SIZE 4096*2 // SCQ + RCQ

#define TEST_CQ_HOST_BUF_ADDR (TEST_COMM_HOST_BASE_ADDR + TEST_CQ_BUF_OFFSET)
#define TEST_CQ_CORE_BUF_ADDR (TEST_CQ_HOST_BUF_ADDR >> 1 << 1 << 11)

/* QP buffer setting info */
#define TEST_HOST_QP_PAGE_NO 3
#define TEST_QP_BUF_OFFSET (TEST_CQ_BUF_OFFSET + TEST_CQ_HOST_BUF_SIZE)
#define TEST_QP_HOST_BUF_SIZE 4096

#define TEST_QP_HOST_BUF_ADDR (TEST_COMM_HOST_BASE_ADDR + TEST_QP_BUF_OFFSET)
#define TEST_QP_CORE_BUF_ADDR (TEST_QP_HOST_BUF_ADDR >> 1 << 1 << 11)

#endif /* MM_IB_TEST_H_ */