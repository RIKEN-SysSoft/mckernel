#ifndef MIC_MEM_H_
#define MIC_MEM_H_

#include "mtype.h"

/*#### MMIO ####*/
#define MIC_PCI_MMIO_BASE_ADDR 0xc2300000

/*## GTT ##*/
#define GTT_START_OFFSET 0x40000
#define MIC_PCI_GTT_START_ADDR (MIC_PCI_MMIO_BASE_ADDR + GTT_START_OFFSET)
#define MIC_PCI_GTT_ETT_MAX 65536
#define MIC_GTT_ETT_SIZE 4

/*## SBOX ##*/
#define SBOX_START_OFFSET 0x10000
#define MIC_PCI_SBOX_START_ADDR (MIC_PCI_MMIO_BASE_ADDR + SBOX_START_OFFSET)
#define MIC_PCI_SBOX_SIZE 0x30000
#define SBOX_SBQ_FLUSH_REG 0x0000B1A0
#define SBOX_TLB_FLUSH_REG 0x0000B1A4

/*## APERTURE ##*/
#define MIC_PCI_APERTURE_BASE_ADDR 0xb0000000
//256MB
#define MIC_PCI_APERTURE_SIZE 0x10000000
//4kB
#define MIC_PAGE_SIZE 4096

static inline addr_t _mic_map2mic(addr_t addr){
	return addr >> 1 << 1 << 11;
}

#define MIC_MAP2MIC _mic_map2mic

extern int mm_host_init();
extern int mm_host_exit();

extern addr_t mm_host_get_vaddr(int page_no, int offset);
extern addr_t mm_host_get_paddr(int page_no, int offset);

/**
 * map a page to MIC memory(set GTT[page_no])
 */
extern int mm_host_page_init(int pg_no, addr_t map_addr, int size, int flush_flg);
/**
 * read or write a initialized page
 */
extern int mm_host_page_read(int pg_no, int offset, int size, void *data);
extern int mm_host_page_write(int pg_no, int offset, int size, void *data);

extern int mm_host_dump_gtt();

/**
 * flush GTT table
 * If only set 1 page, you can call mm_host_page_init with flush_flg=1
 * If set several pages, you can call mm_host_page_init with flush_flg=0, and call mm_host_gtt_flush after all page_init
 */
extern int mm_host_gtt_flush();

#endif /* MIC_MEM_H_ */
