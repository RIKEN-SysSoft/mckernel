#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <infiniband/verbs.h>

#include <sys/mman.h> // mmap

#define BUF_SIZE (32)/*(1024)*/
#define LOOP_NUM (1000)

#define __USE_MALLOC__

static inline uint64_t rdtsc_light(void )
{
    uint64_t x;
    __asm__ __volatile__("rdtscp;" /* rdtscp don't jump over earlier instructions */
                         "shl $32, %%rdx;"
                         "or %%rdx, %%rax" :
                         "=a"(x) :
                         :    
                         "%rcx", "%rdx", "memory");
    return x;
}

/**
 * ibv_reg_mr test
 *
 */
int main(int argc, char **argv)
{
	int i, end;
	int dev_num;
	struct ibv_device **dev_list = NULL;
	struct ibv_context *ib_ctx = NULL;
	struct ibv_pd *pd = NULL;

	struct ibv_mr *mr[LOOP_NUM] = {NULL};
	int mr_flags;
	char *buf[LOOP_NUM];
	int buf_size;

	unsigned long long t1, t2, t3;

	dev_list = ibv_get_device_list(&dev_num);
	if (dev_list == NULL) {
			perror("ibv_get_device_list");
			goto exit;
	}
	if (!dev_num) {
			printf("no device are found\n");
			goto exit;
	}

	printf("dev_num = %d, dev_name = %s\n", dev_num, ibv_get_device_name(dev_list[0]));

	ib_ctx = ibv_open_device(dev_list[0]);
	if (!ib_ctx) {
			perror("ibv_open_device");
			goto exit;
	}

	pd = ibv_alloc_pd(ib_ctx);
	if(!pd){
		perror("ibv_alloc_pd");
		goto exit;
	}

	mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC;
	buf_size = BUF_SIZE;

	for (i = 0; i < LOOP_NUM; i++) {
#ifdef __USE_MALLOC__
		buf[i] = (char *)malloc(buf_size);
		if (!buf[i]) {
				perror("malloc");
				end = i + 1;
				goto exit;
		}
#else
		buf[i] = mmap(0, buf_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (buf[i] == MAP_FAILED) {
				perror("mmap");
				end = i + 1;
				goto exit;
		}
#endif
	}

	end = i;

	t1 = rdtsc_light();
	for (i = 0; i < end; i++) {
		mr[i] = ibv_reg_mr(pd, buf[i], buf_size, mr_flags);
		if (!mr[i]) {
				perror("ibv_reg_mr");
				goto exit;
		}
	}
	t2 = rdtsc_light();

exit:
	for (i = 0; i < end;i ++) {
		if (mr[i]) {
				ibv_dereg_mr(mr[i]);
		}
	}
	t3 = rdtsc_light();

    FILE* fp;
    fp = popen("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if(!fp) { printf("popen failed\n"); goto fn_fail; }
    char freq_str[256];
    int nread = fread(freq_str, sizeof(char), 256, fp);
    if(!nread) { printf("popen failed"); goto fn_fail; }
    freq_str[nread] = 0;
    long int freq = strtol(freq_str, NULL, 10) * 1000;
    printf("CPU frequency:%ld\n", freq);
    pclose(fp);

	printf("%d byte x %d\n", BUF_SIZE, end);
	printf("      reg_mr   time=%llu (%f msec)\n", t2 - t1, (t2 - t1) * (1 / (double)freq) * 1000);
	printf("    dereg_mr   time=%llu (%f msec)\n", t3 - t2, (t3 - t2) * (1 / (double)freq) * 1000);

	for (i = 0; i < end;i ++) {
#ifdef __USE_MALLOC__
		if (buf[i]) {
				free(buf[i]);
		}
#else
		if (buf[i]) {
				munmap(buf[i], buf_size);
		}
#endif
	}

	if (pd) {
			ibv_dealloc_pd(pd);
	}

	if (ib_ctx) {
			ibv_close_device(ib_ctx);
	}

	if (dev_list) {
			ibv_free_device_list(dev_list);
	}

 fn_exit:
	return 0;
 fn_fail:
    goto fn_exit;
}
