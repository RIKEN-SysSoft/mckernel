/*
 * \file pager.c
 *  License details are found in the file LICENSE.
 * \brief
 *	paging system
 * \author Yutaka Ishikawa <ishikawa@riken.jp>
 */
/*
 * HISTORY:
 */
#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <cpulocal.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <errno.h>
#include <cls.h>
#include <syscall.h>
#include <kmalloc.h>
#include <process.h>
#include <swapfmt.h>
#include <debug.h>

#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#define O_CREAT		00000100
#define O_TRUNC		00001000
#define SEEK_SET	0	 /* from include/uapi/linux/fs.h in Linux */
#define SEEK_CUR	1	 /* from include/uapi/linux/fs.h in Linux */
#define IS_TEXT(start, region) ((start) == (region)->text_start)
#define IS_DATA(start, region) ((start) == (region)->data_start)
#define IS_STACK(start, region) ((start) == (region)->stack_start)
#define IS_INVALID_USERADDRESS(addr, region)	\
	((((unsigned long) addr) < region->user_start)	\
	|| ((unsigned long) addr) >= region->user_end)
#define IS_INVALID_LENGTH(len, region)	\
	((len) > (region->user_end - region->user_start))
#define IS_READONLY(flag)	(((flag)&VR_PROT_WRITE) == 0)
#define IS_NOTUSER(flag)	(((flag)&VR_AP_USER) == 0)


//#define DEBUG_PRINT_PROCESS

#ifdef DEBUG_PRINT_PROCESS
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

/*
 * Contiguous pages are represented by the "addrpair" structure.
 * - The swap_area, whose type is "struct arealist", keeps swappable pages
 *   using "areaent" structures that keeps a list of the "addrpair" structures.
 * - The mlock_area is also the "struct arealist" struct, keeping pages locked byt
 *   both McKernel and Linux.
 * - The mlock_container is also the "struct arealist" type, keeping pages loc
 */
/*
 * The page areas are independently managed by McKernel and Linux.
 * Pages locked by Linuxkernel are not known by McKernel. To get the information,
 * the mlockcntnr structure is used.
 * The mlockcntnr keeps the list of 
 */
#define MLOCKADDRS_SIZE	128
struct addrpair {
	unsigned long	start;
	unsigned long	end;
	unsigned long	flag;
};
struct areaent {
	struct areaent	*next;
	int		count;
	struct addrpair	pair[MLOCKADDRS_SIZE];
};

struct arealist {
	struct areaent	*head;
	struct areaent	*tail;
	int		count;
};

struct mlockcntnr {
	struct areaent	*from;
	int		ccount;
	struct areaent	*cur;
};

struct swapinfo {
	struct swap_header	*swphdr;
	struct swap_areainfo	*swap_info, *mlock_info;

	struct arealist	swap_area;
	struct arealist	mlock_area;
	struct mlockcntnr mlock_container;
#define UDATA_BUFSIZE	PAGE_SIZE 
	char	*swapfname;
	char	*udata_buf;	/* To read-store data from Linux to user space */

	void	*user_buf;
	size_t	ubuf_size, ubuf_alloced;
};

static void
area_print(struct vm_regions *region)
{
	dkprintf("text  %016lx:%016lx\n", region->text_start, region->text_end);
	dkprintf("data  %016lx:%016lx\n", region->data_start, region->data_end);
	dkprintf("brk   %016lx:%016lx\n", region->brk_start, region->brk_end);
	dkprintf("map   %016lx:%016lx\n", region->map_start, region->map_end);
	dkprintf("stack %016lx:%016lx\n", region->stack_start, region->stack_end);
	dkprintf("user  %016lx:%016lx\n", region->user_start, region->user_end);
}


static int
myalloc_init(struct swapinfo *si, void *p, size_t sz)
{
	extern SYSCALL_DECLARE(mlock);
	ihk_mc_user_context_t ctx0;
	int	cc;

	/* pin the buffer down in McKernel side */
	ihk_mc_syscall_arg0(&ctx0) = (uintptr_t) p;
	ihk_mc_syscall_arg1(&ctx0) = sz;
	cc = sys_mlock(__NR_mlock, &ctx0);
	if (cc < 0) return cc;
	/* init */
	si->user_buf = p;
	si->ubuf_size = sz;
	si->ubuf_alloced = 0;
	dkprintf("myalloc_init: buffer(%p) size(0x%lx)\n", si->user_buf, si->ubuf_size);
	return 0;
}

void
myalloc_finalize(struct swapinfo *si)
{
	extern SYSCALL_DECLARE(munlock);
	ihk_mc_user_context_t ctx0;

	/* unpindown in McKernel side */
	ihk_mc_syscall_arg0(&ctx0) = (uintptr_t) si->user_buf;
	ihk_mc_syscall_arg1(&ctx0) = si->ubuf_size;
	sys_munlock(__NR_munlock, &ctx0);
}

void *
myalloc(struct swapinfo *si, size_t sz)
{
	void	*p = NULL;

	if ((si->ubuf_alloced + sz) < si->ubuf_size) {
		p = (void*) &((char*)si->user_buf)[si->ubuf_alloced];
		si->ubuf_alloced += sz;
	}
	return p;
}

void
myfree(void *p)
{
	/* nothing so far */
}

static int
linux_open(char *fname, int flag, int mode)
{
	ihk_mc_user_context_t ctx0;
	int fd;

	ihk_mc_syscall_arg0(&ctx0) = -100;		/* dirfd = AT_FDCWD */
	ihk_mc_syscall_arg1(&ctx0) = (uintptr_t)fname;	/* pathname = fname */
	ihk_mc_syscall_arg2(&ctx0) = flag;		/* flags = flag */
	ihk_mc_syscall_arg3(&ctx0) = mode;		/* mode = mode */
	fd = syscall_generic_forwarding(__NR_openat, &ctx0);
	return fd;
}

static int
linux_unlink(char *fname)
{
	ihk_mc_user_context_t ctx0;

	ihk_mc_syscall_arg0(&ctx0) = -100;		/* dirfd = AT_FDCWD */
	ihk_mc_syscall_arg1(&ctx0) = (uintptr_t)fname;	/* pathname = fname */
	ihk_mc_syscall_arg2(&ctx0) = 0;			/* flags = 0 */
	return syscall_generic_forwarding(__NR_unlinkat, &ctx0);
}

static ssize_t
linux_read(int fd, void *buf, size_t count)
{
	ihk_mc_user_context_t ctx0;
	ssize_t		sz;
	size_t count0 = count;

	ihk_mc_syscall_arg0(&ctx0) = fd;
	sz = 0;
	for (;;) {
		ssize_t sz0;

		ihk_mc_syscall_arg1(&ctx0) = (uintptr_t) buf;
		ihk_mc_syscall_arg2(&ctx0) = count;
		sz0 = syscall_generic_forwarding(__NR_read, &ctx0);
		if (sz0 == -EINTR)
			continue;
		if (sz0 <= 0) {
			if (sz == 0)
				sz = sz0;
			break;
		}
		sz += sz0;
		if (sz == count0)
			break;
		count -= sz0;
		buf = (char *)buf + sz0;
	}
	return sz;
}

static ssize_t
linux_write(int fd, void *buf, size_t count)
{
	ihk_mc_user_context_t ctx0;
	ssize_t		sz;
	size_t count0 = count;

	ihk_mc_syscall_arg0(&ctx0) = fd;
	sz = 0;
	for (;;) {
		ssize_t sz0;

		ihk_mc_syscall_arg1(&ctx0) = (uintptr_t) buf;
		ihk_mc_syscall_arg2(&ctx0) = count;
		sz0 = syscall_generic_forwarding(__NR_write, &ctx0);
		if (sz0 == -EINTR)
			continue;
		if (sz0 <= 0) {
			if (sz == 0)
				sz = sz0;
			break;
		}
		sz += sz0;
		if (sz == count0)
			break;
		count -= sz0;
		buf = (char *)buf + sz0;
	}
	return sz;
}

static off_t
linux_lseek(int fd, off_t off, int whence)
{
	ihk_mc_user_context_t ctx0;
	int		cc;

	ihk_mc_syscall_arg0(&ctx0) = fd;
	ihk_mc_syscall_arg1(&ctx0) = off;
	ihk_mc_syscall_arg2(&ctx0) = whence;
	cc = syscall_generic_forwarding(__NR_lseek, &ctx0);
	return cc;
}

static int
linux_close(int fd)
{
	ihk_mc_user_context_t ctx0;
	int		cc;

	ihk_mc_syscall_arg0(&ctx0) = fd;
	cc = syscall_generic_forwarding(__NR_close, &ctx0);
	return cc;
}

/*
 * The munmap syscall from McKernel is handled by mccntrl module.
 * An extra argument, flag, is to set new remote page table if not zero.
 */
static int
linux_munmap(void *addr, size_t len, int flag)
{
	ihk_mc_user_context_t ctx0;
	int		cc;

	ihk_mc_syscall_arg0(&ctx0) = (uintptr_t) addr;
	ihk_mc_syscall_arg1(&ctx0) = len;
	ihk_mc_syscall_arg2(&ctx0) = flag;
	cc = syscall_generic_forwarding(__NR_munmap, &ctx0);
	return cc;
}

static int
pager_open(struct swapinfo *si, char *fname, int flag, int mode)
{
	int	fd;
	copy_to_user(si->udata_buf, fname, strlen(fname) + 1);
	fd = linux_open(si->udata_buf, flag, mode);
	return fd;
}

static int
pager_unlink(struct swapinfo *si, char *fname)
{
	copy_to_user(si->udata_buf, fname, strlen(fname) + 1);
	return linux_unlink(si->udata_buf);
}

static int 
pager_copy_from_user(void * dst, void * from, size_t size, struct process_vm *vm)
{
	int ret;
	void *virt;
	unsigned long psize;
	unsigned long rphys;
	int faulted = 0;

	if (size > PAGE_SIZE) {
		ret = -EFAULT;
		return ret;
	}
		
retry_lookup:
	/* remember page */
	ret = ihk_mc_pt_virt_to_phys_size(vm->address_space->page_table,
		dst, &rphys, &psize);

	if (ret) {
		uint64_t reason = PF_POPULATE | PF_WRITE | PF_USER;
		void *addr= (void *)(((unsigned long)dst)& PAGE_MASK);

		if (faulted) {
			ret = -EFAULT;
			return ret;
		}

		ret = page_fault_process_vm(vm, addr, reason);
		if (ret) {
			ret = -EFAULT;
			return ret;
		}

		faulted = 1;
		goto retry_lookup;
	}

	virt = phys_to_virt(rphys);

	ret = copy_from_user(virt, from, size);

	
	return ret;
}

static ssize_t
pager_read(struct swapinfo *si, int fd, void *start, size_t size,struct process_vm   *vm)
{
	ssize_t		off, sz, rs;

	for (off = 0; off < size; off += sz) {
		sz = size - off;
		sz = (sz > UDATA_BUFSIZE) ? UDATA_BUFSIZE : sz;
		rs = linux_read(fd, si->udata_buf, sz);
		if (rs != sz) return rs;
		
		rs = pager_copy_from_user(start + off, si->udata_buf, sz, vm); 
		if (rs != 0) return rs;
	}
	return off;
}

static ssize_t
pager_write(int fd, void *start, size_t size)
{
	ssize_t		sz;

	sz = linux_write(fd, start, size);
	return sz;
}

static int
mlocklist_req(unsigned long start, unsigned long end, struct addrpair *addr, int nent)
{
	ihk_mc_user_context_t ctx0;
	int		cc;

#define PAGER_REQ_MLOCK_LIST	0x0008
	ihk_mc_syscall_arg0(&ctx0) = PAGER_REQ_MLOCK_LIST;
	ihk_mc_syscall_arg1(&ctx0) = start;
	ihk_mc_syscall_arg2(&ctx0) = end;
	ihk_mc_syscall_arg3(&ctx0) = (unsigned long) addr;
	ihk_mc_syscall_arg4(&ctx0) = nent;
	cc = syscall_generic_forwarding(__NR_mmap, &ctx0);
	return cc;
}

/*
 * If the last entry of addrpair is -1, more paged locked by Linux exist.
 */
static int
mlocklist_morereq(struct swapinfo *si, unsigned long *start)
{
	struct areaent	went,*ent = si->mlock_area.tail;
	copy_from_user(&went, ent, sizeof(struct areaent));

	dkprintf("mlocklist_morereq: start = %ld and = %ld\n",
		went.pair[went.count].start, went.pair[went.count].end);
	if (went.pair[went.count].start != (unsigned long) -1) {
		return 0;
	}
	*start = went.pair[went.count].end;
	return 1;
}

static int
arealist_alloc(struct swapinfo *si, struct arealist *areap)
{
	struct areaent went;
	areap->head = areap->tail = myalloc(si, sizeof(struct areaent));
	if (areap->head == NULL) return -ENOMEM;
	memset(&went, 0, sizeof(struct areaent));
	copy_to_user(areap->head, &went, sizeof(struct areaent));
	return 0;
}

static int
arealist_init(struct swapinfo *si)
{
	int	cc;

	if ((cc = arealist_alloc(si, &si->swap_area)) < 0) return cc;
	cc = arealist_alloc(si, &si->mlock_area);
	return cc;
}


static void
arealist_free(struct arealist *area)
{
	struct areaent	*tmp;
	for (tmp = area->head; tmp != NULL; tmp = tmp->next) {
		myfree(tmp);
	}
	memset(area, 0, sizeof(struct arealist));
	return;
}

/*
 * returns the start address of addrpair and its size
 */
static int
arealist_get(struct swapinfo *si, struct addrpair **pair, struct arealist *area)
{
	struct areaent	*tmp,wtmp;
	struct areaent	*tail = area->tail;
	if (tail->count < MLOCKADDRS_SIZE - 1) { /* at least two entries are needed */
		if (pair) *pair = &tail->pair[tail->count];
		return MLOCKADDRS_SIZE - tail->count;
	}
	tmp = myalloc(si, sizeof(struct areaent));
	if (tmp == NULL) {
		return -1;
	}
	memset(&wtmp, 0, sizeof(struct areaent));
	copy_to_user(tmp, &wtmp, sizeof(struct areaent));
	copy_to_user(&(area->tail->next), &tmp, sizeof(struct areaent *));

	area->tail = tmp;
	if (pair) *pair = area->tail->pair;
	return MLOCKADDRS_SIZE;
};

static void
arealist_update(int cnt, struct arealist *area)
{
	int i;
	copy_from_user(&i, &(area->tail->count), sizeof(int));
	i += cnt;
	copy_to_user(&(area->tail->count), &i, sizeof(int));
	area->count += cnt;
}

static int
arealist_add(struct swapinfo *si, unsigned long start, unsigned long end,
             unsigned long flag, struct arealist *area)
{
	int	cc;
	struct addrpair	*addr,waddr;

	cc = arealist_get(si, &addr, area);
	if (cc < 0) return -1;
	waddr.start = start; waddr.end = end; waddr.flag = flag;
	copy_to_user(addr, &waddr, sizeof(struct addrpair));
	
	arealist_update(1, area);
	return 0;
}

static int
arealist_preparewrite(struct arealist *areap, struct swap_areainfo *info,
		      ssize_t off, struct process_vm *vm, int flag)
{
	struct areaent		*ent,went;
	int			count = 0;
	ssize_t			totsz = 0;
	unsigned long pos;
	struct page_table	*pt = vm->address_space->page_table;

	for (ent = areap->head; ent != NULL; ent = ent->next) {
		int i;
		copy_from_user(&went, ent, sizeof(struct areaent));
		for (i = 0; i < went.count; i++, count++) {
			ssize_t sz = went.pair[i].end - went.pair[i].start; 
			copy_to_user(&(info[count].start), &(went.pair[i].start), sizeof(unsigned long));
			copy_to_user(&(info[count].end), &(went.pair[i].end), sizeof(unsigned long));
			copy_to_user(&(info[count].flag), &(went.pair[i].flag), sizeof(unsigned long));
			if (flag) { /* position in file */
				
				pos = off + totsz;
			} else { /* physical memory */
				if (ihk_mc_pt_virt_to_phys(pt,
						(void*) ent->pair[i].start,
						 &pos)) {
					kprintf("Cannot get phys\n");
				}
			}
			copy_to_user(&(info[count].pos), &pos, sizeof(unsigned long));
			totsz += sz;
		}
	}
	return count;
}

static ssize_t
arealist_write(int fd, struct swap_areainfo *info, int count)
{
	ssize_t	       sz;

	sz = linux_write(fd, info, sizeof(struct swap_areainfo)*count);
	if (sz != sizeof(struct swap_areainfo)*count) return -1;
	return 0;
}

static void
arealist_print(char *msg, struct arealist *areap, int count)
{
	struct areaent	*ent;
	kprintf("%s: %d\n", msg, count);
	for (ent = areap->head; ent != NULL; ent = ent->next) {
		int i;
		for (i = 0; i < ent->count; i++) {
			
			kprintf("\t%p -- %p\n",
				(void*) ent->pair[i].start, (void*) ent->pair[i].end);
		}
	}
}

/*
 * 
 */
static int
mlockcntnr_sethead(struct swapinfo *si)
{
	int	cnt;
	cnt = arealist_get(si, 0, &si->mlock_area); /* Adjust arealist */
	if (cnt < 0) return -1;
	si->mlock_container.from = si->mlock_container.cur = si->mlock_area.tail;
	si->mlock_container.ccount = si->mlock_area.tail->count;
	return 0;
}

static int
mlockcntnr_isempty(struct swapinfo *si)
{
	return si->mlock_container.from == si->mlock_area.tail
		&& si->mlock_container.ccount == si->mlock_area.tail->count;
}

static int
mlockcntnr_addrent(struct swapinfo *si, struct addrpair *laddr)
{
	if (si->mlock_container.ccount == si->mlock_container.cur->count) {
		struct areaent	*tmp = si->mlock_container.cur->next;
		if (tmp == 0) return 0;
		si->mlock_container.cur = tmp;
		si->mlock_container.ccount = 1;
	}
	*laddr = si->mlock_container.cur->pair[si->mlock_container.ccount - 1];
	si->mlock_container.ccount++;
	return 1;
}

static void
print_area(char *label, unsigned long start, unsigned long sz,
	     struct vm_regions *region)
{
	char *type;

	if (start == region->text_start) {
		type = "text";
	} else if (start == region->data_start) {
		type = "data";
	} else if (start == region->brk_start) {
		type = "brk";
	} else if (start == region->stack_start) {
		type = "stack";
	} else if (start == region->user_start) {
		type = "user";
	} else if (start >= region->map_start
		   && start <= region->stack_start) {
		type = "map";
	} else {
		type = "other";
	}
	kprintf("%s: %s write(%p, %ld)\n", label, type, start, sz);
}

void
print_region(char *msg, struct process_vm *vm)
{
	struct vm_range		*range, *next;

	kprintf("%s:\n", msg);
	next = lookup_process_memory_range(vm, 0, -1);
	while ((range = next)) {
		next = next_process_memory_range(vm, range);
		if (range->memobj != NULL) continue;
		kprintf("\t%016lx:%016lx (%lx)\n",
			range->start, range->end, range->flag);
	}
}

static void
debug_dump(char *msg, unsigned char *p)
{
	kprintf("%s-> %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
		":%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		msg, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

int
do_pagein(int flag)
{
	struct thread		*thread = cpu_local_var(current);
	struct process_vm	*vm = thread->vm;
	int		fd, i;
	ssize_t		pos, sz, rs;
	struct swapinfo *si = vm->swapinfo;

	dkprintf("do_pagein: flag(%d) currss(%lx)\n", flag, vm->currss);
	fd = pager_open(si, si->swapfname, O_RDONLY, 0);
	pager_unlink(si, si->swapfname);
	if (fd < 0) {
		kprintf("do_pagein: Cannot open file: %s\n", si->swapfname);
		return fd;
	}
	/*
	 * In the current implementaion, the following working areas remain
	 * in the physical memory area:
	 *	swphdr, swap_info and mlock_info
	 */
	pos = sizeof(struct swap_header);
	pos += sizeof(struct swap_areainfo)*si->swphdr->count_sarea;
	pos += sizeof(struct swap_areainfo)*si->swphdr->count_marea;
	rs = linux_lseek(fd, pos, SEEK_SET);
	for (i = 0; i < si->swphdr->count_sarea; i++) {
		extern int ihk_mc_pt_print_pte(struct page_table *pt, void *virt);
		sz = si->swap_info[i].end - si->swap_info[i].start;
		dkprintf("pagein: %016lx:%016lx sz(%lx)\n", si->swap_info[i].start, si->swap_info[i].end, sz);
		rs = pager_read(si, fd, (void*) si->swap_info[i].start, sz, vm);
		if (rs != sz) goto err;
		// ihk_mc_pt_print_pte(vm->address_space->page_table, (void*) si->swap_info[i].start);
	}
	linux_close(fd);
	print_region("after pagin", vm);
	dkprintf("do_pagein: done, currss(%lx)\n", vm->currss);
	vm->swapinfo = NULL;
	kfree(si->swapfname);
	kfree(si);
	return 0;
err:
	linux_close(fd);
	ekprintf("pagein: read error: return(%lx) size(%lx)\n", rs, sz);
	vm->swapinfo = NULL;
	kfree(si->swapfname);
	kfree(si);
	return -1;
}

int
do_pageout(char *fname, void *buf, size_t size, int flag)
{
	struct thread		*thread = cpu_local_var(current);
	struct process_vm	*vm = thread->vm;
	struct vm_regions	*region = &vm->region;
	struct vm_range		*range, *next;
	struct addrpair		*addr;
	int		i, fd;
	long		cc;
	unsigned long	start, end;
	ssize_t		pos, sz;
	struct swapinfo *si;

	fd = -1;
	dkprintf("do_pageout: buf(%p) size(%d) flag(%d) currss(%lx)\n",
		 buf, size, flag, vm->currss);
	if (IS_INVALID_USERADDRESS(fname, region)
	    || IS_INVALID_USERADDRESS(buf, region)
	    || IS_INVALID_LENGTH(size, region)) {
		return -EINVAL;
	}
	if (!(si = kmalloc(sizeof(struct swapinfo), IHK_MC_AP_NOWAIT))) {
		ekprintf("do_pageout: Cannot allocate working memory in kmalloc\n");
		return -ENOMEM;
	}
	memset(si, '\0', sizeof(struct swapinfo));
	cc = myalloc_init(si, buf, size);
	if (cc < 0) {
		kfree(si);
		ekprintf("do_pageout: Cannot pin buf (%p) down\n", buf);
		return cc;
	}
	si->udata_buf = myalloc(si, UDATA_BUFSIZE);
	si->swapfname = kmalloc(strlen(fname) + 1, IHK_MC_AP_NOWAIT);
	if (si->swapfname == NULL) {
		kfree(si);
		ekprintf("do_pageout: Cannot allocate working memory in kmalloc\n");
		return -ENOMEM;
	}
	if (strcpy_from_user(si->swapfname, fname)) {
		cc = -EFAULT;
		goto err;
	}
	cc = arealist_init(si);
	if (cc < 0) {
		ekprintf("do_pageout: user buffer area is needed more than %d byte\n",
			 UDATA_BUFSIZE + sizeof(struct areaent)*2);
		goto err;
	}

	copy_to_user(si->udata_buf, si->swapfname, strlen(si->swapfname) + 1);
	fd = linux_open(si->udata_buf, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (fd < 0) {
		ekprintf("do_pageout: Cannot open/create file: %s\n", fname);
		cc = fd;
		goto err;
	}
	area_print(region);

	/* looking at ranges except for non anoymous, text, and data */
	next = lookup_process_memory_range(vm, 0, -1);
	while ((range = next)) {
		next = next_process_memory_range(vm, range);
		if (range->memobj != NULL) continue;
		if (IS_TEXT(range->start, region)
		    || IS_STACK(range->start, region)
		    || IS_INVALID_USERADDRESS(range->start, region)
		    || IS_READONLY(range->flag)
		    || IS_NOTUSER(range->flag)) continue;
		if (range->flag & VR_LOCKED) {
			/* this range is locked by McKernel */
			cc = arealist_add(si, range->start, range->end,
					  range->flag, &si->mlock_area);
			if (cc < 0) goto nomem;
			continue;
		}
		start = range->start; end = range->end;
		if ((cc = mlockcntnr_sethead(si)) < 0) goto nomem;
		/* Requesting mlock list in Linux Kernel. We do not know how much
		 * addrpair entries are needed. The Linux side stores -1 in
		 * the last entry of addrpair to inform more entries exist.
		 * the mlocklist_morereq function checks this condition. */
		do {
			if ((cc = arealist_get(si, &addr, &si->mlock_area)) < 0) goto nomem;
			cc = mlocklist_req(start, end, addr, cc);
			arealist_update(cc, &si->mlock_area);
		} while (mlocklist_morereq(si, &start));
		/* */
		if (mlockcntnr_isempty(si)) { /* whole range is going to swap */
			cc = arealist_add(si, range->start, range->end,
					  range->flag, &si->swap_area);
		} else { /*  partial range is going to swap */
			for (start = range->start; start < range->end;) {
				struct addrpair	laddr;
				if (mlockcntnr_addrent(si, &laddr) == 0) {
					/* No more entry locked by Linux */
					cc = arealist_add(si, start, range->end,
							  range->flag,
							  &si->swap_area);
					if (cc < 0) goto nomem;
					break;
				}
				if (start < laddr.start) {
					/* swap range from start to laddr.start */
					cc = arealist_add(si, start, laddr.start,
							  range->flag,
							  &si->swap_area);
					if (cc < 0) goto nomem;
				}
				start = laddr.end;
				kprintf("do_pageout: start(%ld) range->end(%ld)\n",
					start, range->end);
				break;
			}
		}
	}
	arealist_print("SWAP", &si->swap_area, si->swap_area.count);
	arealist_print("MLOCK", &si->mlock_area, si->mlock_area.count);
	si->swap_info = myalloc(si, sizeof(struct swap_areainfo)* si->swap_area.count);
	si->mlock_info =  myalloc(si, sizeof(struct swap_areainfo)* si->mlock_area.count);
	if (si->swap_info == NULL || si->mlock_info == NULL) goto nomem;

	/* preparing page store */
	si->swphdr = myalloc(si, sizeof(struct swap_header));
	copy_to_user(&(si->swphdr->magic), MCKERNEL_SWAP, SWAP_HLEN);
	copy_to_user(&(si->swphdr->version), MCKERNEL_SWAP_VERSION, SWAP_HLEN);
	copy_to_user(&(si->swphdr->count_sarea), &(si->swap_area.count), sizeof(unsigned int));
	copy_to_user(&(si->swphdr->count_marea), &(si->mlock_area.count), sizeof(unsigned int));
	if ((cc = pager_write(fd, si->swphdr, sizeof(struct swap_header)))
	    != sizeof(struct swap_header)) {
		if (cc >= 0)
			cc = -EIO;
		goto err;
	}
	pos = linux_lseek(fd, 0, SEEK_CUR);
	pos += sizeof(struct swap_areainfo)*(si->swap_area.count+si->mlock_area.count);
	cc = arealist_preparewrite(&si->swap_area, si->swap_info, pos, vm, 1);
	if (cc != si->swap_area.count) {
		ekprintf("do_pageout: ERROR file ent(%d) != list ent(%d) in swap_area\n",
			 cc, si->swap_area.count);
	}
	cc = arealist_preparewrite(&si->mlock_area, si->mlock_info, 0, vm, 0);
	if (cc != si->mlock_area.count) {
		ekprintf("do_pageout: ERROR file ent(%d) != list ent(%d) in swap_area\n",
			 cc, si->mlock_area.count);
	}
	/* arealists are stored */
	if ((cc = arealist_write(fd, si->swap_info, si->swap_area.count)) < 0) goto err;
	if ((cc = arealist_write(fd, si->mlock_info, si->mlock_area.count)) < 0) goto err;
	/* now pages are stored */
	for (i = 0; i < si->swap_area.count; i++) {
		struct swap_areainfo sw_info;
		copy_from_user(&sw_info, &(si->swap_info[i]), sizeof(struct swap_areainfo));
		sz = sw_info.end - sw_info.start;
		if ((cc = pager_write(fd, (void*) sw_info.start, sz)) != sz) {
			if (cc >= 0)
				cc = -EIO;
			goto err;
		}
	}
	if (flag & 0x04) {
		kprintf("skipping physical memory removal\n");
		goto free_exit;
	}
	kprintf("removing physical memory\n");
	for (i = 0; i < si->swap_area.count; i++) {
		struct swap_areainfo sw_info;
		copy_from_user(&sw_info, &(si->swap_info[i]), sizeof(struct swap_areainfo));
		cc = ihk_mc_pt_free_range(vm->address_space->page_table,
					  vm,
					  (void*) sw_info.start,
					  (void*) sw_info.end, NULL);
		if (cc < 0) {
			kprintf("ihk_mc_pt_clear_range returns: %d\n", cc);
		}
	}
#if 0
		range->flag |= VR_PAGEOUT;
#endif
	cc = linux_close(fd);
	fd = -1;
	/*
	 * Unmapping McKernel's user virtual spaces in Linux side.
	 * From here to the completion of do_pagein, the nonlocking user spaces
	 * except TEXT, STACK, readonly pages, are not invalid.
	 */
	for (i = 0; i < si->swap_area.count; i++) {
		struct swap_areainfo sw_info;
		copy_from_user(&sw_info, &(si->swap_info[i]), sizeof(struct swap_areainfo));
		sz = sw_info.end - sw_info.start;
		cc = linux_munmap((void*) sw_info.start, sz, 0);
		if (cc < 0) {
			kprintf("do_pageout: Cannot munmap: %lx len(%lx)\n",
				si->swap_info[i].start, sz);
		}
	}
	cc = 0;
	goto free_exit;
err:
	ekprintf("do_pageout: write error: %d\n", cc);
	goto free_exit;
nomem:
	ekprintf("do_pageout: cannot allocate working memory\n");
	cc = -ENOMEM;
free_exit:
	if (fd >= 0)
		linux_close(fd);
	dkprintf("do_pageout: done, currss(%lx)\n", vm->currss);
	arealist_free(&si->mlock_area); arealist_free(&si->swap_area); 
	if (cc != 0) {
		pager_unlink(si, si->swapfname);
		kfree(si->swapfname);
		kfree(si);
	}
	else {
		vm->swapinfo = si;
	}
	return cc;
}
