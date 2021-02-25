/* uti_perf COPYRIGHT FUJITSU LIMITED 2021 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "tof_uapi.h"
#include "tof_test.h"

extern int __libc_allocate_rtsig (int __high);

#define CTRL_MSGLEN		(64)
#define DATA_MSGLEN		(16 * 1024 * 1024 - 256)

#define MSG_CREAR_TO_GET	(0x58fca109U)
#define MSG_DONE			(0x1105bf26U)
#define MSG_BARRIER			(0x9c6108afU)
#define MSG_SEND_DELAY		(0x61fb9044U)
#define MSG_INIT			(0x065f8cbaU)

#define RECV_PATTERN	(0x00A0)
#define SEND_PATTERN	(0x0050)

/* param.mode bit */
#define MODE_SEND	(0x0000)
#define MODE_RECV	(0x0001)
#define MODE_MASK	(0x0001)

#define THR_DEFAULT	(0x0000)
#define THR_NONE	(0x0002)	/* do not create thread */
#define THR_LCUY	(0x0004)	/* lock-check-unlock-yield */
#define THR_MASK	(0x0006)

#define SEND_FIFO	(0x00000010)
#define THR_FIFO	(0x00000020)
#define DUMMY_MODE1	(0x00000040)

#define OPT_RTSIG	(0x01000000)
#define OPT_SYSCALL	(0x02000000)
#define OPT_POLL	(0x04000000)
#define OPT_CINJ	(0x08000000)

#define REMOTE()	(param.remote)
#define LOCAL()		(param.local)
#define IS_RECV()	(((param.mode) & MODE_MASK) == MODE_RECV)
#define IS_SEND()	(((param.mode) & MODE_MASK) == MODE_SEND)

struct node_info {
	int tni;
	int cq;
	int ctrl_in_stag;
	int ctrl_out_stag;
	int data_stag;
	int bar_in_stag;
	int bar_out_stag;
	char clear_pattern;
};

struct tp_param {
	int mode;
	int delay;						/* protocol delay, d1 */
	int count;						/* number of measurements of delay */
	int length;						/* data length */
	int forknum;					/* number of processes */
	int send_usleep;				/* usleep time for do_send */
	int recv_usleep;				/* usleep time for do_recv */
	int thr_prio;					/* progress thread priority */
	int ctrl_retry;					/* ctrl retry count */
	struct tof_icc_toq_put *toq;
	struct tof_icc_tcq_descriptor *tcq;
	struct tof_icc_mrq_descriptor *mrq;
	uint64_t *toq_reg;
	uint64_t toq_cnt;
	uint64_t mrq_cnt;
	uint64_t bar_cnt;
	struct tof_addr raddr;			/* remote tofu address */
	void *ctrl_in_buf;
	void *ctrl_out_buf;
	void *data_buf;
	void *bar_in_buf;
	void *bar_out_buf;

	struct node_info local;			/* constant data per node */
	struct node_info remote;
};

static int verbose = 0;
static struct tp_param param;

static volatile int recv_complete = 0;
static volatile int dummy_complete = 0;

static pthread_mutex_t mutex;
static pthread_cond_t cond;
static pthread_barrier_t bar;

/* Fill constant parameters for the test */
static int setup_tp_param (int proc)
{
	struct tof_addr laddr;
	struct node_info *recv = IS_RECV() ? &LOCAL() : &REMOTE();
	struct node_info *send = IS_SEND() ? &LOCAL() : &REMOTE();

	/* get local pos */
	/* TOF_EXIT(), if failed to get pos */
	get_position(&laddr);

	if ((laddr.x == param.raddr.x) && (laddr.a == param.raddr.a) &&
		(laddr.y == param.raddr.y) && (laddr.b == param.raddr.b) &&
		(laddr.z == param.raddr.z) && (laddr.c == param.raddr.c)) {

		/* same node, separate send/recv TNI */
		if (proc >= 11 || proc < 0) {
			return -1;		/* limit 11 process */
		}
		recv->tni = 4;
		recv->cq = proc;
		send->tni = 5;
		send->cq = proc;

	} else {
		/* internode comm, use same TNI/CQ for send/recv */
		if (proc >= 48 || proc < 0) {
			return -1;		/* limit 48 process */
		}
		send->tni = recv->tni = proc / 10 + 1;	/* 1 - 5 */
		send->cq = recv->cq = proc % 10;		/* 0 - 9 */
	}

	recv->ctrl_in_stag = recv->cq * 100 + recv->tni * 10 + 1;
	recv->ctrl_out_stag = recv->cq * 100 + recv->tni * 10 + 2;
	recv->data_stag = recv->cq * 100 + recv->tni * 10 + 3;
	recv->bar_in_stag = recv->cq * 100 + recv->tni * 10 + 4;
	recv->bar_out_stag = recv->cq * 100 + recv->tni * 10 + 5;
	recv->clear_pattern = (char)(RECV_PATTERN + proc);

	send->ctrl_in_stag = send->cq * 100 + send->tni * 10 + 1;
	send->ctrl_out_stag = send->cq * 100 + send->tni * 10 + 2;
	send->data_stag = send->cq * 100 + send->tni * 10 + 3;
	send->bar_in_stag = send->cq * 100 + send->tni * 10 + 4;
	send->bar_out_stag = send->cq * 100 + send->tni * 10 + 5;
	send->clear_pattern = (char)(SEND_PATTERN + proc);

	if (verbose) {
		printf("mode   : %s (proc=%d)\n", 
			(IS_RECV() ? "RECV" : "SEND"), proc);
		printf("local  : %d,%d,%d,%d,%d,%d tni=%d cq=%d\n", 
			laddr.x, laddr.y, laddr.z, laddr.a, laddr.b, laddr.c, 
			LOCAL().tni, LOCAL().cq);
		printf("remote : %d,%d,%d,%d,%d,%d tni=%d cq=%d\n", 
			param.raddr.x, param.raddr.y, param.raddr.z, 
			param.raddr.a, param.raddr.b, param.raddr.c, 
			REMOTE().tni, REMOTE().cq);
	}
	return 0;
}

/* create tofu device file name */
static void create_tofu_device_name (char *file, int tni, int cq)
{
	strcpy(file, "/proc/tofu/dev/tni4cq0");
	file[18] = '0' + tni;
	file[21] = '0' + cq;
}

static int alloc_stag(int cq_fd, int msglen, int stag, void *buf)
{
	struct tof_alloc_stag alst;
	int ret;

	alst.flags = 0;
	alst.stag = stag;
	alst.va = buf;
	alst.len = msglen;
	ret = ioctl(cq_fd, TOF_IOCTL_ALLOC_STAG, &alst);
	if (ret != 0) {
		perror("ioctl, TOF_IOCTL_ALLOC_STAG");
		return -1;
	}
	if (alst.offset != 0) {
		fprintf(stderr, "%s: offset != 0\n", __FUNCTION__);
		return -1;
	}
	
	if (verbose) {
		printf("va=%p len=%ld stag=%d offset=%ld\n",
			alst.va, alst.len, alst.stag, alst.offset);
	}

	return 0;
}

int caused_signal_number = -1;

void my_sig_action(int sig, siginfo_t *info, void *val){
	if(sig > 32){
		fprintf(stderr, "sig=%d si_int=0x%lx si_errno=%d si_code=%d\n",
			sig, info->si_int, info->si_errno, info->si_code);
	}
	else {
		fprintf(stderr, "sig=%d\n", sig);
	}
	fflush(stderr);
	if(caused_signal_number == -1){
		caused_signal_number = sig;
	}
	else if(caused_signal_number != sig){
		fprintf(stderr, "2 different signal were sent: oldsig=%d newsig=%d\n", caused_signal_number, sig);
		TOF_NG();
		TOF_EXIT();
	}
}

void set_rtsignal(int fd){
	int sig;
	int min, max;
	int res;
	struct sigaction sigact;

	min = SIGRTMIN;
	max = SIGRTMAX;
	sig = __libc_allocate_rtsig(1);
	if(sig < min || sig > max){
		TOF_EXIT();
	}
	res = ioctl(fd, TOF_SET_RT_SIGNAL, &sig);
	if(res){
		TOF_EXIT();
	}

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_sigaction = my_sig_action;
	sigact.sa_flags = SA_SIGINFO;
	sigemptyset(&sigact.sa_mask);
	//sigaddset(&sigact.sa_mask, sig);
	if(sigaction(sig, &sigact, NULL) != 0){
		TOF_EXIT();
	}

//	printf("setup signal\n");
}

void set_termsignal(void){
	struct sigaction sigact;
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_sigaction = my_sig_action;
	//sigact.sa_flags = SA_SIGINFO;
	sigemptyset(&sigact.sa_mask);
	//sigaddset(&sigact.sa_mask, sig);
	if(sigaction(SIGTERM, &sigact, NULL) != 0){
		TOF_EXIT();
	}
}

static void chld_handler (int sig, siginfo_t *info, void *val)
{
	dummy_complete = 1;
}

static void set_chldsignal (void)
{
	struct sigaction sigact;
	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_sigaction = chld_handler;
	sigemptyset(&sigact.sa_mask);
	if(sigaction(SIGCHLD, &sigact, NULL) != 0){
		TOF_EXIT();
	}
}

/* "0,1,2,3,4" -> {0,1,2,3,4} */
static int str2int(const char *str, int *dst, int max)
{
	int i = 0;
	char *s = (char *)str;
	char *e;

	while (*s != '\0') {
		dst[i] = (int)strtol(s, &e, 0);

		/* conversion failure */
		if (s == e)
			break;
		/* output buffer check */
		if (++i >= max)
			break;
		/* end of string */
		if (*e == '\0')
			break;
		/* get next pos */
		s = e + 1;
	}

	return i;
}

/* "0,1,2,3,4,5" -> struct tof_addr */
static int str2pos(const char *str, struct tof_addr *addr)
{
	int dst[6];

	if (str2int(str, dst, 6) == 6) {
		addr->x = dst[0];
		addr->y = dst[1];
		addr->z = dst[2];
		addr->a = dst[3];
		addr->b = dst[4];
		addr->c = dst[5];
		return 0;
	} else {
		return 1;
	}
}

/* get 10ns (100MHz) timer counter */
static inline unsigned long rdtsc_light(void)
{
	unsigned long x;
	__asm__ __volatile__("isb \n\t"
		"mrs %[output], cntvct_el0"
		: [output]"=r"(x)
		:
		: "memory");
	return x;
}

/* delay routine - begin */
#define N_INIT	100000
static double nspw = 0.0;	/* 10 ns per work */

static inline void fixed_size_work (void)
{
	__asm__ __volatile__(
		"mov x20, #0\n\t"
		"1:\t"
		"add x20, x20, #1\n\t"
		"cmp x20, #99\n\t"
		"b.le 1b\n\t"
		:
		:
		: "x20", "cc", "memory");
}

static inline void bulk_fsw (unsigned long n)
{
	int j;
	for(j = 0; j < n; j++) {
		fixed_size_work();
	}
}

static void fwq_init (void)
{
	unsigned long t1, t2;
	t1 = rdtsc_light();
	bulk_fsw(N_INIT);
	t2 = rdtsc_light();
	nspw = (double)(t2 - t1) / (double)N_INIT;
}

static void fwq (long delay_10ns)
{
	if (delay_10ns >= 0) {
		bulk_fsw(delay_10ns / nspw);
	}
}
/* delay routine - end */

static int _getcpu (void)
{
	int cpu, ret;

	ret = syscall(SYS_getcpu, &cpu, NULL, NULL);
	if (ret == -1) {
		cpu = -1;
	}

	return cpu;
}

static int onmck (void)
{
	return (syscall(732) == -1 ? 0 : 1);
}

/*
 *  tofu put/get
 */
static void tofu_putget (
	int command, int msglen, int mode, int lstag, int rstag)
{

	struct tof_icc_toq_put *toq = param.toq;
	uint64_t toq_cnt = param.toq_cnt;

	int mx , my , mz , ma , mb , mc;
	struct tof_icc_toq_put aput;
	
	int flip = ((toq_cnt >> 11) & 1)^1;
	int index = toq_cnt & 2047;

	mx = param.raddr.x;
	my = param.raddr.y;
	mz = param.raddr.z;
	ma = param.raddr.a;
	mb = param.raddr.b;
	mc = param.raddr.c;

	memset(&aput, 0, sizeof(aput));
//	aput.head1.command = TOF_ICC_TOQ_PUT;
	aput.head1.command = command;
	aput.head1.mtuop.mtu = 240;/// MAX
	aput.head1.pa = ma;
	aput.head1.pb = mb;
	aput.head1.pc = mc;
	aput.head1.rx = mx;
	aput.head1.ry = my;
	aput.head1.rz = mz;
	aput.head1.ra = ma;
	aput.head1.rb = mb;
	aput.head1.rc = mc;
	aput.head1.ri = REMOTE().tni;
	aput.head1.flip = flip ^ 1;	/* current filp */
	aput.head2.s = 1;
	if (mode & OPT_POLL) {	/* receive polling */
		aput.head2.r = 0;
		aput.head2.q = 0;
	} else {
		aput.head2.r = 0;
		aput.head2.q = 1;
	}
	if (mode & OPT_CINJ) {	/* cache injection */
		aput.head2.j = 1;
	} else {
		aput.head2.j = 0;
	}
	aput.head2.edata = toq_cnt;
	aput.head2.len.normal.length = msglen;
	aput.remote.stag = rstag;
	aput.remote.offset = 0;	/* always zero, checking alloc_stag */
	aput.remote.cqid = REMOTE().cq;
	aput.local.stag = lstag;
	aput.local.offset = 0;	/* always zero, checking alloc_stag */
	aput.local.cqid = LOCAL().cq;

	memcpy(&toq[index], &aput, sizeof(aput));
	mb();
	toq[index].head1.flip = flip;	/* write next flip */
	mb();
}

/* 
 * fetch start, 
 * wait update tcq, 
 * return rcode (0: Success)
 */
static int check_tcq (void)
{
	int rcode;
	struct tof_icc_tcq_descriptor *tcq = param.tcq;
	uint64_t *toq_reg = param.toq_reg;
	uint64_t *toq_cnt = &(param.toq_cnt);

	int flip = ((*toq_cnt >> 11) & 1)^1;
	int index = *toq_cnt & 2047;

	/* fetch start */
	do {
		toq_reg[8] = 1;
	} while (tcq[index].flip != flip);
	mb();
	(*toq_cnt)++;

	rcode = tcq[index].rcode;

	/* check tcq */
	if (rcode) {
		fprintf(stderr, "%s: rcode=%d\n", __FUNCTION__, rcode);
	}
	return rcode;
}

/*
 * wait update mrq
 * return 0: Success, othrewise unintended id
 */
static int check_mrq (int continue_id, int break_id)
{
	struct tof_icc_mrq_descriptor *mrq = param.mrq;
	uint64_t *mrq_cnt = &(param.mrq_cnt);

	int mrq_flip;
	int id;
	uint64_t index;

	while (1) {
		mrq_flip = ((*mrq_cnt >> 17) & 1)^1;
		index = *mrq_cnt & (4*1024*1024/32 - 1);

		if (mrq[index].head1.flip != mrq_flip)
			continue;
		mb();
		(*mrq_cnt)++;
		id = mrq[index].head1.id;

		if (id == continue_id)
			continue;
		if (id == break_id) {
			id = 0;
			break;
		}

		/* otherwise, unintended or error id */
		fprintf(stderr, "%s: id=%d wait=%d\n", __FUNCTION__, id, break_id);
		break;
	}

	return id;
}

static inline void clear_msg (void *buf, int sec)
{
	int *ptr = (int *)(buf) + (CTRL_MSGLEN / sizeof(int)) - 1;
	*ptr = MSG_INIT;
	*(ptr - 1) = sec;

//	printf("%s: sec=%d\n", __FUNCTION__, *(ptr - 1));
}


static int put_msg (int out_stag, int in_stag)
{
	int ret;

	tofu_putget(TOF_ICC_TOQ_PUT, CTRL_MSGLEN, (OPT_POLL | OPT_CINJ), 
		out_stag, in_stag);

	if ((ret = check_tcq()) != 0) {
		return ret;
	}

	return check_mrq(TOF_ICC_MRQ_PUT_NOTICE, TOF_ICC_MRQ_PUT_LAST_NOTICE);
}

static int put_ctrl_msg (int msg)
{
	int *ptr = (int *)(param.ctrl_out_buf) + (CTRL_MSGLEN / sizeof(int)) - 1;
	*ptr = msg;
	*(ptr - 1) += 1;

//	printf("%s: msg=%x sec=%d\n", __FUNCTION__, msg, *(ptr - 1));

	return put_msg(LOCAL().ctrl_out_stag, REMOTE().ctrl_in_stag);
}

static int get_data (void)
{
	int ret;

	/* 
	 * Unset Q flag (set OPT_POLL)
	 * Get Halfway Notice is not required
	 */
	tofu_putget(TOF_ICC_TOQ_GET, param.length, OPT_POLL, 
		LOCAL().data_stag, REMOTE().data_stag);

	if ((ret = check_tcq()) != 0) {
		return ret;
	}

	return check_mrq(TOF_ICC_MRQ_GET_NOTICE, TOF_ICC_MRQ_GET_LAST_NOTICE);
}

static int check_ctrl_msg (int msg, int clear)
{
	int ret = -1;
	int *ptr = (int *)(param.ctrl_in_buf) + (CTRL_MSGLEN / sizeof(int)) - 1;

#if 1		/* control message check */
	int val = *ptr;
	int sec = *(ptr - 1);

	if (val == msg) {
		if (clear) {
			*ptr = MSG_INIT;
//			printf("%s: req=%x, val=%x, sec=%d\n", __FUNCTION__, msg, val, sec);
		}
		ret = 0;
	} else if (val != MSG_INIT) {
		if (clear) {
			/* clear = 0, touch buffer only */
			fprintf(stderr, "%s: Unexpected control message (req=%x, val=%x, sec=%d)\n", 
				__FUNCTION__, msg, val, sec);
		}
	}
#else
	if (*ptr == msg) {
		if (clear) {
			*ptr = MSG_INIT;
		}
		ret = 0;
	}
#endif
	return ret;
}

static int put_barrier_msg (void)
{
	int *ptr = (int *)(param.bar_out_buf) + (CTRL_MSGLEN / sizeof(int)) - 1;
	*ptr = MSG_BARRIER;
	*(ptr - 1) = param.bar_cnt;

//	printf("%s: sec=%d\n", __FUNCTION__, *(ptr - 1));

	return put_msg(LOCAL().bar_out_stag, REMOTE().bar_in_stag);
}

static int check_barrier_msg (void)
{
	int *ptr = (int *)(param.bar_in_buf) + (CTRL_MSGLEN / sizeof(int)) - 1;
	int val;
	int sec;

	val = *ptr;
	mb();
	sec = *(ptr - 1);

	if (val == MSG_INIT)
		return -1;

	if (val == MSG_BARRIER && sec == param.bar_cnt) {
		*ptr = MSG_INIT;
//		printf("%s: sec=%d\n", __FUNCTION__, sec);
		return 0;
	}

	fprintf(stderr, "%s: Unexpected barrier message (val=%x, sec=%d, cnt=%d)\n", 
		__FUNCTION__, val, sec, param.bar_cnt);
	return -1;
}

static void tofu_barrier_init (void)
{
	param.bar_cnt = 0;
	clear_msg(param.bar_in_buf, param.bar_cnt);
	clear_msg(param.bar_out_buf,param.bar_cnt);
}

static int tofu_barrier_wait (void)
{
	int ret = 0;

	if (IS_SEND()) {
		(param.bar_cnt)++;
		if (ret = put_barrier_msg()) {
			fprintf(stderr, "%s: put MSG_BARRIER is failed(%d)\n", __FUNCTION__, ret);
			return ret;
		}
		(param.bar_cnt)++;
		while (check_barrier_msg()) { /*  */ }
	} else {
		(param.bar_cnt)++;
		while (check_barrier_msg()) { /*  */ }
		(param.bar_cnt)++;
		if (ret = put_barrier_msg()) {
			fprintf(stderr, "%s: put MSG_BARRIER is failed(%d)\n", __FUNCTION__, ret);
			return ret;
		}
	}

	return ret;
}


/* send mode */
static int __do_send (unsigned long *d)
{
	unsigned long t1, t2;
	int ret;

	t1 = rdtsc_light();
	ret = put_ctrl_msg(MSG_CREAR_TO_GET);
	if (ret == 0) {
		while (check_ctrl_msg(MSG_DONE, 1)) { /*  */ }
		t2 = rdtsc_light();
		*d = t2 - t1;
	} else {
		fprintf(stderr, "%s: put MSG_CREAR_TO_GET is failed (%d)\n", 
			__FUNCTION__, ret);
	}

	if (param.send_usleep)
		usleep(param.send_usleep);

	return ret;
}

static int do_send (void)
{
	unsigned long d2, tmp, min, max;
	int ret, i;

	if (verbose) {
		printf("%s: start, cpu=%d running on %s\n", 
			__FUNCTION__, _getcpu(), (onmck() ? "McKernel" : "Linux"));
	}

	if (param.mode & SEND_FIFO) {
		struct sched_param pri;
		pri.sched_priority = sched_get_priority_min(SCHED_FIFO);
		ret = sched_setscheduler(0, SCHED_FIFO, &pri);
		if (ret) {
			perror("sched_setscheduler");
		}
		if (verbose) {
			printf("%s: sched policy to sched_fifo\n", __FUNCTION__);
		}
	}

	/* Measure the reaction delay */
	min = -1UL;
	max = 0UL;
	d2 = 0UL;
	for (i = 0; i < param.count; i++) {
		/* Wait recv process */
		memset(param.data_buf, LOCAL().clear_pattern, param.length);
		tofu_barrier_wait();
		usleep(1);

		if ((ret = __do_send(&tmp))) {
			goto err_send;
		}

		d2 += tmp;
		min = (tmp < min ? tmp : min);
		max = (tmp > max ? tmp : max);

		/* print result */
		printf("%lu\n", tmp);

		/* sync receiver/sender */
		tofu_barrier_wait();
	}

	/* print summary */
	d2 /= param.count;
	printf("%s: reaction=%ld, min=%ld, max=%ld\n",
		__FUNCTION__, d2, min, max);

err_send:
	return ret;
}

/* recv mode with progress thread */
static int __do_recv (void)
{
	int ret, i;

	while (1) {
		pthread_mutex_lock(&mutex);
		for (i = 0; i < param.ctrl_retry; i++) {
			if (!(ret = check_ctrl_msg(MSG_CREAR_TO_GET, 1))) {
				break;
			}
		}
		if (!ret) {
			break;
		}
		pthread_mutex_unlock(&mutex);
		sched_yield();
	}

	if ((ret = get_data())) {
		fprintf(stderr, "%s: data_get is failed(%d)\n", __FUNCTION__, ret);
		goto err__recv;
	}
	if ((ret = put_ctrl_msg(MSG_DONE))) {
		fprintf(stderr, "%s: put MSG_DONE is failed(%d)\n", __FUNCTION__, ret);
		goto err__recv;
	}

	/* Set flags referenced by parent thread */
	recv_complete = 1;

err__recv:
	pthread_mutex_unlock(&mutex);
	return ret;
}

static int progress_func (void)
{
	int ret, i;

	for (i = 0; i < param.count; i++) {
		ret = pthread_barrier_wait(&bar);
		if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
			fprintf(stderr, "%s: pthread_barrier_wait is failed (%d)\n", 
				__FUNCTION__, ret);
		}
		if ((ret = __do_recv())) {
			break;
		}
	}

	return ret;
}

/* progress thread lock-check-unlock-yield overhead */
static int progress_only_lock_unlock (void)
{
	int ret, i, p;

	for (i = 0; i < param.count; i++) {
		ret = pthread_barrier_wait(&bar);
		if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
			fprintf(stderr, "%s: pthread_barrier_wait is failed (%d)\n", 
				__FUNCTION__, ret);
		}

		/* Check clear-to-get without buffer clear */
		while (1) {
			pthread_mutex_lock(&mutex);

			for (p = 0; p < param.ctrl_retry; p++) {
				check_ctrl_msg(MSG_CREAR_TO_GET, 0);
			}
			if (recv_complete) {	/* check flag from parent */
				recv_complete = 0;
				break;
			}
			pthread_mutex_unlock(&mutex);
			sched_yield();
		}
		pthread_mutex_unlock(&mutex);
	}

	return 0;
}

static void *progress_thread (void *arg)
{
	int ret;
	int (*func)(void) = (int (*)(void))(arg);

	if (verbose) {
		printf("%s: start, cpu=%d running on %s\n", 
			__FUNCTION__, _getcpu(), (onmck() ? "McKernel" : "Linux"));
	}

	/* set priority */
	if (param.mode & THR_FIFO) {
		struct sched_param pri;
		pri.sched_priority = sched_get_priority_min(SCHED_FIFO);
		ret = pthread_setschedparam(pthread_self(), SCHED_FIFO, &pri);
		if (ret) {
			perror("pthread_setschedparam");
		}
		if (verbose) {
			printf("%s: sched policy to sched_fifo\n", __FUNCTION__);
		}
	} else if (param.thr_prio != 0) {
		ret = setpriority(PRIO_PROCESS, 0, param.thr_prio);
		if (ret) {
			fprintf(stderr, "%s: setpriority is failed (%d)\n", 
				__FUNCTION__, ret);
		}
		if (verbose || ret) {	/* if setpriority is failed */
			errno = 0;
			ret = getpriority(PRIO_PROCESS, 0);
			printf("%s: getpriority = %d, errno = %d\n", 
				__FUNCTION__, ret, errno);
		}
	}

	if ((ret = func())) {
		fprintf(stderr, "%s: progress function is failed (%d)\n", __FUNCTION__, ret);
	}

	return NULL;
}

static int initialize_thread_resources (pthread_t *thr, int (*func)(void))
{
	pthread_attr_t attr;
	cpu_set_t cpuset;
	int ret;

	if ((ret = pthread_attr_init(&attr))) {
		fprintf(stderr, "%s: pthread_attr_init is failed (%d)\n", 
			__FUNCTION__, ret);
		goto err_res;
	}

	if (onmck()) {
		/* on McKernel */
		if (param.mode & OPT_SYSCALL) {
			ret = syscall(731, 1, NULL);
			if (verbose || ret) {
				printf("%s: on McKernel, util_indicate_clone = %d\n", 
					__FUNCTION__, ret);
			}
		}
	} else {
		/* on HostLinux, set thread affinity */
		CPU_ZERO(&cpuset);
		CPU_SET(0, &cpuset);
		CPU_SET(1, &cpuset);
		ret = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);
		if (ret) {
			fprintf(stderr, "%s: pthread_attr_setaffinity_np is failed (%d)\n", 
				__FUNCTION__, ret);
			goto err_res;
		}
	}

	if ((ret = pthread_create(thr, &attr, progress_thread, (void *)func))) {
		fprintf(stderr, "%s: pthread_create is failed (%d)\n", __FUNCTION__, ret);
	}

err_res:
	return ret;
}

static int do_recv (void)
{
	int i, p;
	int ret;
	pthread_t thr;

	if (verbose) {
		printf("%s: start, cpu=%d running on %s\n", 
			__FUNCTION__, _getcpu(), (onmck() ? "McKernel" : "Linux"));
	}

	pthread_mutex_init(&mutex, NULL);
	ret = pthread_barrier_init(&bar, NULL, 2);
	if (ret) {
		fprintf(stderr, "%s: pthread_barrier_init is failed (%d)\n", 
			__FUNCTION__, ret);
		return ret;
	}

	if ((param.mode & THR_MASK) == THR_NONE) {
		/* nothing to do */
	} else if ((param.mode & THR_MASK) == THR_LCUY) {
		/* progress thread lock-check-unlock-yield overhead */
		ret = initialize_thread_resources(&thr, progress_only_lock_unlock);
	} else {
		/* Normal mode */
		ret = initialize_thread_resources(&thr, progress_func);
	}
	if (ret) {
		return ret;
	}

	printf("%s: Measure the reaction delay, Ready\n", __FUNCTION__);

	/* Measure the reaction delay */
	for (i = 0; i < param.count; i++) {

		memset(param.data_buf, LOCAL().clear_pattern, param.length);

		if ((param.mode & THR_MASK) != THR_NONE) {
			/* sync progress thread */
			ret = pthread_barrier_wait(&bar);
			if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
				fprintf(stderr, "%s: pthread_barrier_wait is failed (%d)\n", 
					__FUNCTION__, ret);
			}
		}

		/* sync receiver/sender */
		pthread_mutex_lock(&mutex);
		tofu_barrier_wait();
		pthread_mutex_unlock(&mutex);

		/* progress thread lock-check-unlock-yield overhead */
		if ((param.mode & THR_MASK) != THR_DEFAULT) {
			if ((ret = __do_recv())) {
				goto err_recv;
			}
			tofu_barrier_wait();
			continue;	/* Measure loop continue */
		}
		/* else Normal mode */

		/* calc */
		if (param.delay) {
			fwq(param.delay);
		}

		/* wait progress thread */
		ret = -1;
		while (1) {
			pthread_mutex_lock(&mutex);

			for (p = 0; p < param.ctrl_retry; p++) {
				if (recv_complete) {
					ret = 0;
					recv_complete = 0;
					break;
				}
			}
			if (!ret) {
				break;
			}
			pthread_mutex_unlock(&mutex);
			sched_yield();
			if (param.recv_usleep) {
				usleep(param.recv_usleep);
			}
		}
		pthread_mutex_unlock(&mutex);

		tofu_barrier_wait();
	}

err_recv:
	if ((param.mode & THR_MASK) != THR_NONE) {
		pthread_join(thr, NULL);
		if (verbose) {
			printf("%s: progress thread is joined\n", __FUNCTION__);
		}
	}
	return ret;
}

/* dummy sender/receiver pair */
static int dummy_send (void)
{

	if (verbose) {
		printf("%s: start, cpu=%d running on %s\n", 
			__FUNCTION__, _getcpu(), (onmck() ? "McKernel" : "Linux"));
	}

	while (!dummy_complete) {
		usleep(10000);
	}

	if (verbose) {
		printf("%s: end, cpu=%d running on %s\n", 
			__FUNCTION__, _getcpu(), (onmck() ? "McKernel" : "Linux"));
	}

	return 0;
}

static int dummy_func (void)
{
	int i;
	int ret= -1;

	while (1) {
		pthread_mutex_lock(&mutex);
		for (i = 0; i < param.ctrl_retry; i++) {
			if (!(ret = check_ctrl_msg(MSG_CREAR_TO_GET, 1))) {
				break;
			}
			if (dummy_complete) {
				ret = 0;
				break;
			}
		}
		if (!ret) {
			break;
		}
		pthread_mutex_unlock(&mutex);
		sched_yield();
	}

	recv_complete = 1;
	pthread_mutex_unlock(&mutex);
	return 0;
}

static int dummy_func1 (void)
{
	pthread_mutex_lock(&mutex);
	if (!recv_complete) {	/* Wait main thread */
		pthread_cond_wait(&cond, &mutex);
	}
	pthread_mutex_unlock(&mutex);
	return 0;
}

static int dummy_recv (void)
{
	int i;
	int ret;
	pthread_t thr;

	if (verbose) {
		printf("%s: start, cpu=%d running on %s\n", 
			__FUNCTION__, _getcpu(), (onmck() ? "McKernel" : "Linux"));
	}

	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);

	if (param.mode & DUMMY_MODE1) {
		/* Progress thread waits for wake request from parent thread */
		if ((ret = initialize_thread_resources(&thr, dummy_func1))) {
			return ret;
		}

		while (!dummy_complete) {	/* Wait SIGCHLD handler */
			usleep(10000);
			sched_yield();	/* Todo */
		}
		pthread_mutex_lock(&mutex);
		recv_complete = 1;
		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&mutex);
	} else {
		/* else, normal mode */
		if ((ret = initialize_thread_resources(&thr, dummy_func))) {
			return ret;
		}

		ret = -1;
		while (1) {
			pthread_mutex_lock(&mutex);
			for (i = 0;i < param.ctrl_retry; i++) {
				if (recv_complete) {
					ret = 0;
					recv_complete = 0;
					break;
				}
			}
			if (!ret) {
				break;
			}
			pthread_mutex_unlock(&mutex);
			sched_yield();
		}
		pthread_mutex_unlock(&mutex);
	}

	pthread_join(thr, NULL);
	if (verbose) {
		printf("%s: progress thread is joined\n", __FUNCTION__);
	}
	return 0;
}

static int args_to_param (int argc, char *argv[])
{
	int ret;

	struct option longopts[] = {
		/* only long opt */
		{ "sendusleep", required_argument, NULL, 512},
		{ "sendfifo", no_argument, NULL, 513},
		{ "dummymode1", no_argument, NULL, 514},
		{ "thrprio", required_argument, NULL, 515},
		{ "thrfifo", no_argument, NULL, 516},
		{ "protocol", no_argument, NULL, 517},
		{ "ctrlretry", required_argument, NULL, 518},
		{ "recvusleep", required_argument, NULL, 519},
		/* forward short opt */
		{ "nortsig", no_argument, NULL, 's'},
		{ "thread", required_argument, NULL, 't'},
		{ "d1", required_argument, NULL, 'd'},
		{ 0, 0, 0, 0 }
	};

	while ((ret = getopt_long(argc, argv, "a:d:t:srcf:n:l:v", longopts, NULL)) != -1) {
		switch (ret) {
		/* only long opt */
		case 512:	/* usleep time for do_send */
			param.send_usleep = (int)strtol(optarg, NULL, 0);
			break;
		case 513:	/* apply sched_fifo policy to do_send */
			param.mode |= SEND_FIFO;
			break;
		case 514:
			param.mode |= DUMMY_MODE1;
			break;
		case 515:
			param.thr_prio = (int)strtol(optarg, NULL, 0);
			break;
		case 516:
			param.mode |= THR_FIFO;
			break;
		case 517:	/* Measure protocol delay */
			param.forknum = 1;
			param.mode |= THR_NONE;
			break;
		case 518:
			param.ctrl_retry = (int)strtol(optarg, NULL, 0);
			break;
		case 519:
			param.recv_usleep = (int)strtol(optarg, NULL, 0);
			break;
		/* forward short opt */
		case 'a':	/* tofu coordinate */
			if (str2pos(optarg, &(param.raddr))) {
				fprintf(stderr, "Failed to parse remote address");
				return -1;
			}
			break;
		case 'd':	/* protocol delay */
			param.delay = (int)strtol(optarg, NULL, 0);
			break;
		case 't':	/* thread mode */
			if (strstr(optarg, "none") != NULL) {
				param.mode |= THR_NONE;
			} else if (strstr(optarg, "lcuy") != NULL) {
				param.mode |= THR_LCUY;
			}
			break;
		case 's':	/* signal mode */
			param.mode &= ~OPT_RTSIG;
			break;
		case 'r':	/* execute mode */
			param.mode |= MODE_RECV;
			break;
		case 'c':	/* disable util_indicate_clone */
			param.mode &= ~OPT_SYSCALL;
			break;
		case 'f':	/* fork, Process Generation Count */
			param.forknum = (int)strtol(optarg, NULL, 0);
			if (param.forknum < 1) {
				return -1;
			}
			break;
		case 'n':	/* Number of measurements of reaction delay */
			param.count = (int)strtol(optarg, NULL, 0);
			break;
		case 'l':	/* data length */
			param.length = (int)strtol(optarg, NULL, 0);
			break;
		case 'v':	/* verbose mode */
			verbose = 1;
			break;
		default:
			return -1;
		}
	}
	return 0;
}


int main(int argc, char *argv[])
{
	int ret;
	int cq_fd;
	int proc = 0;
	pid_t cpid = 0;
	cpu_set_t cpuset;
	int i;

	param.forknum = 1;
	param.mode = OPT_RTSIG | OPT_SYSCALL | MODE_SEND | THR_DEFAULT | DUMMY_MODE1;
	param.delay = 0;
	param.count = 10;
	param.length = DATA_MSGLEN;
	param.send_usleep = 100000;
	param.recv_usleep = 0;
	param.thr_prio = 10;
	param.ctrl_retry = 10;

	if (args_to_param(argc, argv)) {
		goto err_fork;
	}

#if 0
	{
		struct rlimit l;
		l.rlim_cur = RLIM_INFINITY;
		l.rlim_max = RLIM_INFINITY;

		if (setrlimit(RLIMIT_CPU, &l))
			perror("RLIMIT_CPU");
		if(setrlimit(RLIMIT_NICE, &l))
			perror("RLIMIT_NICE");
		if(setrlimit(RLIMIT_RTPRIO, &l))
			perror("RLIMIT_RTPRIO");
	}
#endif

	/* fork, Multi process mode */
	for (i = 0; i < (param.forknum - 1); i++) {
		cpid = fork();
		if (cpid == -1) {
			perror("fork");
			goto err_fork;
		}
		if (cpid != 0) {
			break;		/* parent */
		}
		/* cpid = 0, fork next child */
	}
	/* set affinity */
	CPU_ZERO(&cpuset);
	if (onmck()) {
		CPU_SET(i, &cpuset);			/* 0,1,2,3 ... */
	} else {
		CPU_SET((i + 12), &cpuset);		/* 12,13,14 ... */
	}
	ret = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
	if (ret) {
		perror("sched_setaffinity");
		goto err_open;
	}

	/* override proc number */
	proc = i;

	/* setup signal */
	set_chldsignal();

	if (verbose) {
		printf("proc=%d, cpu=%d, pid=%d, cpid=%d\n", 
			proc, _getcpu(), getpid(), cpid);
	}


	/* setup test parameters */
	ret = setup_tp_param(proc);
	if (ret) {
		fprintf(stderr, "%s: setup_tp_param is failed\n", __FUNCTION__);
		goto err_open;
	}

	fwq_init();
#if 0
	{	/* fwq timer test */
		unsigned long t1, t2;
		printf("nspw = %f, result of measuring 1 us \n", nspw);
		for (i = 0; i < 10; i++) {
			t1 = rdtsc_light();
			fwq(100);
			t2 = rdtsc_light();
			printf("[%d] %ld ns\n", i, (t2 - t1) * 10);
		}
	}
#endif

	/* get cq_fd */
	{
		char file[32];
		create_tofu_device_name(file, LOCAL().tni, LOCAL().cq);

		if (verbose) {
			printf("open %s\n", file);
		}
		cq_fd = open(file, O_RDWR|O_CLOEXEC);
		if (cq_fd < 0) {
			perror("open");
			goto err_open;
		}
	}

	/* setup signal handler */
	if (param.mode & OPT_RTSIG) {
		set_rtsignal(cq_fd);
	} else {
		set_termsignal();
	}

	/* memory mapping toq_reg */
	param.toq_reg = mmap(NULL, 4096, PROT_READ|PROT_WRITE, 
		MAP_SHARED, cq_fd, TOF_MMAP_CQ_REGISTER);
	if (param.toq_reg == MAP_FAILED) {
		perror("mmap");
		goto err_mmap;
	}

	/* init cq */
	{
		struct tof_init_cq req;

		req.version = TOF_UAPI_VERSION;
		req.session_mode = 0;
		req.toq_size = 0; /// 64KiB
		req.mrq_size = 3; /// 4MiB
		req.num_stag = 0; /// 8K
		req.tcq_cinj = 1;
		req.mrq_cinj = 1;
		req.toq_mem = MMAP(64*1024);
		req.tcq_mem = MMAP(16*1024);
		req.mrq_mem = MMAP(4*1024*1024);
		param.toq = req.toq_mem;
		param.tcq = req.tcq_mem;
		param.mrq = req.mrq_mem;
		memset(param.toq, 0, 64*1024);
		memset(param.tcq, 0, 16*1024);
		memset(param.mrq, 0, 4*1024*1024);
		ret = ioctl(cq_fd, TOF_IOCTL_INIT_CQ, &req);
		if(ret != 0){
			perror("ioctl, TOF_IOCTL_INIT_CQ");
			goto err;
		}
	}

	/* alloc stag */
	param.ctrl_in_buf = MMAP(CTRL_MSGLEN);
	param.ctrl_out_buf = MMAP(CTRL_MSGLEN);
	param.bar_in_buf = MMAP(CTRL_MSGLEN);
	param.bar_out_buf = MMAP(CTRL_MSGLEN);
	param.data_buf = MMAP(param.length);

	ret = alloc_stag(cq_fd, CTRL_MSGLEN, LOCAL().ctrl_in_stag, param.ctrl_in_buf);
	if (ret) {
		goto err;
	}
	ret = alloc_stag(cq_fd, CTRL_MSGLEN, LOCAL().ctrl_out_stag, param.ctrl_out_buf);
	if (ret) {
		goto err;
	}
	ret = alloc_stag(cq_fd, CTRL_MSGLEN, LOCAL().bar_in_stag, param.bar_in_buf);
	if (ret) {
		goto err;
	}
	ret = alloc_stag(cq_fd, CTRL_MSGLEN, LOCAL().bar_out_stag, param.bar_out_buf);
	if (ret) {
		goto err;
	}
	ret = alloc_stag(cq_fd, param.length, LOCAL().data_stag, param.data_buf);
	if (ret) {
		goto err;
	}

	param.toq_cnt = 0;
	param.mrq_cnt = 0;
	memset(param.data_buf, LOCAL().clear_pattern, param.length);
	clear_msg(param.ctrl_in_buf, 0);
	clear_msg(param.ctrl_out_buf, 0);
	tofu_barrier_init();

	if (cpid == 0) {
		/* Single process mode or Last generated process */
		ret = (IS_SEND() ? do_send() : do_recv());
	} else {
		ret = (IS_SEND() ? dummy_send() : dummy_recv());
	}

	if (ret) {
		goto err;
	}

	/* check signal */
	if (param.mrq_cnt > 4*1024*1024/32) {
		if(((param.mode & OPT_RTSIG) && caused_signal_number > 32) ||
		   (!(param.mode & OPT_RTSIG) && caused_signal_number == SIGTERM)){
			printf("sig=%d\n", caused_signal_number);
		}
		else{
			goto err;
		}
	} else if (verbose) {
		printf("no signal\n");
	}

	/* TODO: resorce release */
	/* TODO: release MMAP() mapping */
err:
	munmap(param.toq_reg, 4096);
err_mmap:
	close(cq_fd);
err_open:
	/* Cleanup child process */
	if (cpid != 0) {
		pid_t wpid;

		/* Wait for receipt of SIGCHLD */
		wpid = wait(&ret);
		if (wpid == -1) {
			perror("wait");
		}
		if (verbose) {
			printf("%s: wait cpid=%d wpid=%d status=%d\n", 
				__FUNCTION__, cpid, wpid, ret);
		}
	}
err_fork:
	return 0;
}
