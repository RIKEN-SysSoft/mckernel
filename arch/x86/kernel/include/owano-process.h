#ifndef OWANO_PROCESS_H
#define	OWANO_PROCESS_H

extern void check_vm_range_list(char *msg, struct process_vm *vm);
extern struct process_vm *snap_vm_range_list(struct process_vm *vm);
extern void destroy_vm_range_list_snap(struct process_vm *snap);
extern void show_vm_range_list(struct process_vm *vm, struct vm_range *stop);
extern void diff_vm_range_list(struct process_vm *oldvm, struct process_vm *newvm);
extern void cmp_vm_range_list(struct process_vm *oldvm, struct process_vm *newvm, struct vm_range *except);

#ifdef	OWANO_IMPLEMENTATION

void check_vm_range_list(char *msg, struct process_vm *vm) {
	struct vm_regions *region = &vm->region;
	struct vm_range *range;
	struct vm_range *next;
	const int max = 1000000;
	int n;
	struct vm_range *p;
	struct vm_range *q;

kprintf("check_vm_range_list(%p,%p): %s\n", msg, vm, msg);
	n = 0;
	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		/* 範囲確認 */
		if ((range->start < region->user_start) || (region->user_end < range->end)) {
			kprintf("out of range:%s\n", msg);
			kprintf("%p: %lx-%lx %lx\n", range, range->start, range->end, range->flag);
			panic("out of range\n");
			/* no return */
		}

		/* リンク整合 */
		if (range->list.next->prev != &range->list) {
			kprintf("vm_range_list corrupt:next:%s\n", msg);
			show_vm_range_list(vm, next);
			panic("check_vm_range_list");
			/* no return */
		}
		if (range->list.prev->next != &range->list) {
			kprintf("vm_range_list corrupt:prev:%s\n", msg);
			show_vm_range_list(vm, range);
			panic("check_vm_range_list");
			/* no return */
		}

		/* ループ確認 */
		++n;
		if (n > max) {
			kprintf("vm_range_list corrupt:too many:%s\n", msg);
			show_vm_range_list(vm, range);
			panic("check_vm_range_list");
			/* no return */
		}
	}

	/* レンジ重なり */
	list_for_each_entry(p, &vm->vm_range_list, list) {
		list_for_each_entry(q, &vm->vm_range_list, list) {
			if (p == q) {
				continue;
			}
			if ((p->start < q->end) && (q->start < p->end)) {
				kprintf("overlapped vm_range:%s\n", msg);
				kprintf("%p: %lx-%lx %lx\n", p, p->start, p->end, p->flag);
				kprintf("%p: %lx-%lx %lx\n", q, q->start, q->end, q->flag);
				panic("overlapped vm_range\n");
				/* no return */
			}
		}
	}
	return;
}

struct process_vm *snap_vm_range_list(struct process_vm *vm) {
	struct process_vm *snap = NULL;
	struct vm_range *orig;
	struct vm_range *range;

kprintf("snap_vm_range_list(%p)\n", vm);
	snap = kmalloc(sizeof(*snap), IHK_MC_AP_NOWAIT);
	if (snap == NULL) {
		kprintf("snap_vm_range_list:kmalloc failed\n");
		return NULL;
	}
	memset(snap, 0, sizeof(*snap));
	INIT_LIST_HEAD(&snap->vm_range_list);
	snap->region = vm->region;

	list_for_each_entry(orig, &vm->vm_range_list, list) {
		range = kmalloc(sizeof(*range), IHK_MC_AP_NOWAIT);
		if (range == NULL) {
			kprintf("snap_vm_range_list:kmalloc(range) failed\n");
			destroy_vm_range_list_snap(snap);
			return NULL;
		}
		memcpy(range, orig, sizeof(*range));
		list_add_tail(&range->list, &snap->vm_range_list);
	}

	check_vm_range_list("snap_vm_range_list", snap);
	return snap;
}

void destroy_vm_range_list_snap(struct process_vm *snap) {
	struct vm_range *range;
	struct vm_range *next;

	check_vm_range_list("destroy_vm_range_list_snap", snap);
	list_for_each_entry_safe(range, next, &snap->vm_range_list, list) {
		list_del(&range->list);
		kfree(range);
	}

	kfree(snap);
	return;
}

void show_vm_range_list(struct process_vm *vm, struct vm_range *stop) {
	struct vm_range *range;
	struct vm_range *next;

	kprintf("vm_range_list: %p\n", &vm->vm_range_list);
	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		kprintf("%p: n %p p %p %lx-%lx %lx\n",
				range,
				range->list.next,
				range->list.prev,
				range->start,
				range->end,
				range->flag);
		if ((stop != NULL) && (range == stop)) {
			break;
		}
	}

	return;
}

static int is_same_vm_range(struct vm_range *lhs, struct vm_range *rhs) {
	return (1
			&& (lhs->start == rhs->start)
			&& (lhs->end == rhs->end)
			&& (lhs->flag == rhs->flag)
	       );
}

void diff_vm_range_list(struct process_vm *oldvm, struct process_vm *newvm) {
	struct vm_range *oldrange;
	struct vm_range *newrange;
	int tail = 0;
	int pending = 0;
	struct vm_range *pending_range = NULL;

	kprintf("vm_range_list: %p %p\n", oldvm, newvm);

	oldrange = list_first_entry(&oldvm->vm_range_list, struct vm_range, list);
	newrange = list_first_entry(&newvm->vm_range_list, struct vm_range, list);
	for (;;) {
		if ((&oldrange->list == &oldvm->vm_range_list)
				&& (&newrange->list == &newvm->vm_range_list)) {
			break;
		}

#define	is_list_end(e,h,m)	(&(e)->m == (h))
		if (!is_list_end(oldrange, &oldvm->vm_range_list, list)
				&& !is_list_end(newrange, &newvm->vm_range_list, list)
				&& is_same_vm_range(oldrange, newrange)) {
			/* same */
			if (tail > 0) {
				--tail;
				kprintf("  %012lx-%012lx %lx\n",
						oldrange->start,
						oldrange->end,
						oldrange->flag);
			}
			else if (pending <= 0) {
				pending_range = oldrange;
				pending = 1;
			}
			else if (pending <= 2) {
				++pending;
			}
			else {
				pending_range = list_entry(pending_range->list.next, struct vm_range, list);
			}
			oldrange = list_entry(oldrange->list.next, struct vm_range, list);
			newrange = list_entry(newrange->list.next, struct vm_range, list);
		}
		else {
			while (pending > 0) {
				kprintf("  %012lx-%012lx %lx\n",
						pending_range->start,
						pending_range->end,
						pending_range->flag);
				pending_range = list_entry(pending_range->list.next, struct vm_range, list);
				--pending;
			}

			if ((!is_list_end(oldrange, &oldvm->vm_range_list, list)
						&& is_list_end(newrange, &newvm->vm_range_list, list))
					|| (!is_list_end(oldrange, &oldvm->vm_range_list, list)
						&& !is_list_end(newrange, &newvm->vm_range_list, list)
						&& (oldrange->start <= newrange->start))) {
				/* delete */
				kprintf("- %012lx-%012lx %lx\n",
						oldrange->start,
						oldrange->end,
						oldrange->flag);
				oldrange = list_entry(oldrange->list.next, struct vm_range, list);
			}
			else {
				/* add */
				kprintf("+ %012lx-%012lx %lx\n",
						newrange->start,
						newrange->end,
						newrange->flag);
				newrange = list_entry(newrange->list.next, struct vm_range, list);
			}
			tail = 3;
		}
	}

	return;
}

void cmp_vm_range_list(struct process_vm *oldvm, struct process_vm *newvm, struct vm_range *except) {
	struct vm_range *oldrange;
	struct vm_range *newrange;

	oldrange = list_first_entry(&oldvm->vm_range_list, struct vm_range, list);
	newrange = list_first_entry(&newvm->vm_range_list, struct vm_range, list);
	for (;;) {
		if ((&oldrange->list == &oldvm->vm_range_list)
				&& (&newrange->list == &newvm->vm_range_list)) {
			break;
		}

#define	is_list_end(e,h,m)	(&(e)->m == (h))
		if (!is_list_end(oldrange, &oldvm->vm_range_list, list)
				&& !is_list_end(newrange, &newvm->vm_range_list, list)
				&& is_same_vm_range(oldrange, newrange)) {
			/* same */
			oldrange = list_entry(oldrange->list.next, struct vm_range, list);
			newrange = list_entry(newrange->list.next, struct vm_range, list);
		}
		else if ((!is_list_end(oldrange, &oldvm->vm_range_list, list)
					&& is_list_end(newrange, &newvm->vm_range_list, list))
				|| (!is_list_end(oldrange, &oldvm->vm_range_list, list)
					&& !is_list_end(newrange, &newvm->vm_range_list, list)
					&& (oldrange->start <= newrange->start))) {
			/* delete */
			if ((except == NULL)
					|| (oldrange->start < except->start)
					|| (except->end < oldrange->end))
			{
				kprintf("vm_range_list: %p %p\n", oldvm, newvm);
				kprintf("- %012lx-%012lx %lx\n",
						oldrange->start,
						oldrange->end,
						oldrange->flag);
				panic("cmp_vm_range_list:deleted\n");
			}
			oldrange = list_entry(oldrange->list.next, struct vm_range, list);
		}
		else {
			/* add */
			if ((except == NULL)
					|| (newrange->start < except->start)
					|| (except->end < newrange->end))
			{
				kprintf("vm_range_list: %p %p\n", oldvm, newvm);
				kprintf("+ %012lx-%012lx %lx\n",
						newrange->start,
						newrange->end,
						newrange->flag);
				panic("cmp_vm_range_list:added\n");
			}
			newrange = list_entry(newrange->list.next, struct vm_range, list);
		}
	}

	return;
}

#endif	/* OWANO_IMPLEMENTATION */
#endif	/* OWANO_PROCESS_H */
