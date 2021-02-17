#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

#include "tof_icc.h"
#include "tof_uapi.h"

#define ST_RDWR   0x0
#define ST_RDONLY 0x1
#define ST_LPG    0x2

#define mb() asm volatile("dmb ish" ::: "memory")
static inline void BRK(void) {asm volatile ("brk #0");}
#define TOF_EXIT() (printf("ERROR:errorno=%d:line%d\n", errno, __LINE__),fflush(stdout),BRK(),exit(1))
#define TOF_NG(str, ...) printf("TOF_NG ##### line%d "str"\n", __LINE__, ##__VA_ARGS__);
#define TOF_OK(str, ...) printf("TOF_OK ##### line%d "str"\n", __LINE__, ##__VA_ARGS__);
#define MMAP(len) ({\
			void *buf;					\
			buf = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0); \
			if(buf == MAP_FAILED){TOF_EXIT();} /* printf("mmap(%d)=%p\n", len, buf); */ buf;})
#define PROGRESS() (printf("PROGRESS:%d\n", __LINE__))
#define MALLOC(len) ({\
	void *buf;				\
	buf = malloc(len);			\
	if(buf == NULL){			\
		TOF_EXIT();			\
	}					\
	buf;})

#define IOCTL(fd, id, req) ({				\
			int res;			\
			res = ioctl(fd, id, req);	\
			if(res != 0){			\
				TOF_EXIT();		\
			}				\
			res;})
#if 0
enum {
	TOF_ICC_TOQ_NOP,
	TOF_ICC_TOQ_PUT,
	TOF_ICC_TOQ_WRITE_PIGGYBACK_BUFFER,
	TOF_ICC_TOQ_PUT_PIGGYBACK,
	TOF_ICC_TOQ_GET,
	TOF_ICC_TOQ_GETL,
	TOF_ICC_TOQ_ATOMIC_READ_MODIFY_WRITE = 0xe,
	TOF_ICC_TOQ_TRANSMIT_RAW_PACKET1 = 0x10,
	TOF_ICC_TOQ_TRANSMIT_RAW_PACKET2,
	TOF_ICC_TOQ_TRANSMIT_SYSTEM_PACKET1,
	TOF_ICC_TOQ_TRANSMIT_SYSTEM_PACKET2,

	TOF_ICC_TOQ_NCOMMANDS,
};


struct tof_icc_cq_stag_offset {
	uint64_t offset:40;
	uint64_t stag:18;
	uint64_t cqid:6;
};

struct tof_icc_toq_common_header1 {
	uint8_t interrupt:1;
	uint8_t res1:4;
	uint8_t source_type:2;
	uint8_t flip:1;
	uint8_t command;
	union {
		uint8_t mtu;
		struct {
			uint8_t res:4;
			uint8_t op:4;
		} armw;
	} mtuop;
	uint8_t sps:4;
	uint8_t pa:1;
	uint8_t pb:2;
	uint8_t pc:1;
	uint8_t rx;
	uint8_t ry;
	uint8_t rz;
	uint8_t ra:1;
	uint8_t rb:2;
	uint8_t rc:1;
	uint8_t res3:1;
	uint8_t ri:3;
};

struct tof_icc_toq_common_header2 {
	uint8_t gap;
	uint8_t s:1;
	uint8_t r:1;
	uint8_t q:1;
	uint8_t p:1;
	uint8_t res1:1;
	uint8_t j:1;
	uint8_t res2:2;
	uint16_t edata;
	union{
		struct {
			uint32_t length:24;
			uint32_t res:8;
		} normal;
		struct {
			uint32_t length:6;
			uint32_t res:26;
		} piggyback;
	} len;
};

struct tof_icc_toq_put {
	struct tof_icc_toq_common_header1 head1;
	struct tof_icc_toq_common_header2 head2;
	struct tof_icc_cq_stag_offset remote;
	struct tof_icc_cq_stag_offset local;
};

struct tof_icc_toq_get {
	struct tof_icc_toq_common_header1 head1;
	struct tof_icc_toq_common_header2 head2;
	struct tof_icc_cq_stag_offset remote;
	struct tof_icc_cq_stag_offset local;
};

#endif

static inline void get_position(struct tof_addr *addr){
	int fd;
	char buf[256];
	ssize_t res;

	fd = open("/proc/tofu/position", O_RDWR);
	if(fd < 0){
		TOF_EXIT();
	}
	res = read(fd, buf, 256);
	if(res <= 0){
		TOF_EXIT();
	}
	buf[res] = '0';
	if(sscanf(buf, "%d %d %d %d %d %d", &addr->x, &addr->y, &addr->z, &addr->a, &addr->b, &addr->c) != 6){
		TOF_EXIT();
	}

	close(fd);
}

static inline uint64_t get_timestamp(void){
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}
