#ifndef OWANO_MEMORY_H
#define	OWANO_MEMORY_H

/** \brief 指定されたページテーブルのマップ状況を表示する */
void ihk_mc_pt_show(page_table_t pt);

/** \brief 指定されたページテーブル間での相違を表示する */
void ihk_mc_pt_diff(page_table_t oldpt, page_table_t newpt);

/** \brief 指定されたページテーブルのコピーを作成する */
page_table_t ihk_mc_pt_snap(page_table_t srcpt);

/** \brief ihk_mc_pt_snap() で作成したコピーを解放する */
void ihk_mc_pt_destroy_snap(page_table_t pt);

#endif	/* OWANO_MEMORY_H */

#ifdef OWANO_IMPLEMENTATION
static struct page_table *__alloc_new_pt(enum ihk_mc_ap_flag ap_flag);

#define OM_GET_VIRT_INDICES(virt, l4i, l3i, l2i, l1i) \
	l4i = ((virt) >> PTL4_SHIFT) & (PT_ENTRIES - 1); \
	l3i = ((virt) >> PTL3_SHIFT) & (PT_ENTRIES - 1); \
	l2i = ((virt) >> PTL2_SHIFT) & (PT_ENTRIES - 1); \
	l1i = ((virt) >> PTL1_SHIFT) & (PT_ENTRIES - 1)

#define	OM_GET_INDICES_VIRT(l4i, l3i, l2i, l1i)		\
		( ((uint64_t)(l4i) << PTL4_SHIFT)	\
		| ((uint64_t)(l3i) << PTL3_SHIFT)	\
		| ((uint64_t)(l2i) << PTL2_SHIFT)	\
		| ((uint64_t)(l1i) << PTL1_SHIFT)	\
		)

static int snap_lookup_pte(struct page_table *pt, void *virt, pte_t **ptep, void **pgbasep, uint64_t *pgsizep)
{
	int l4idx, l3idx, l2idx, l1idx;

	OM_GET_VIRT_INDICES((uint64_t)virt, l4idx, l3idx, l2idx, l1idx);

	if (!(pt->entry[l4idx] & PFL4_PRESENT)) {
		return -ENOENT;
	}

	pt = phys_to_virt(pt->entry[l4idx] & PT_PHYSMASK);
	if (!(pt->entry[l3idx] & PFL3_PRESENT)) {
		return -ENOENT;
	}

	pt = phys_to_virt(pt->entry[l3idx] & PT_PHYSMASK);
	if (!(pt->entry[l2idx] & PFL2_PRESENT) || (pt->entry[l2idx] & PFL2_SIZE)) {
		*ptep = &pt->entry[l2idx];
		*pgbasep = (void *)OM_GET_INDICES_VIRT(l4idx, l3idx, l2idx, 0);
		*pgsizep = PTL2_SIZE;
		return 0;
	}

	pt = phys_to_virt(pt->entry[l2idx] & PT_PHYSMASK);
	*ptep = &pt->entry[l1idx];
	*pgbasep = (void *)OM_GET_INDICES_VIRT(l4idx, l3idx, l2idx, l1idx);
	*pgsizep = PTL1_SIZE;

	return 0;
}

typedef int snap_walk_pte_fn_t(void *args, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end);

static int snap_walk_pte_l1(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, snap_walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL1_SHIFT);
	eix = ((end == 0) || ((base + PTL2_SIZE) <= end))? PT_ENTRIES
		: (((end - base) + (PTL1_SIZE - 1)) >> PTL1_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL1_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int snap_walk_pte_l2(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, snap_walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL2_SHIFT);
	eix = ((end == 0) || ((base + PTL3_SIZE) <= end))? PT_ENTRIES
		: (((end - base) + (PTL2_SIZE - 1)) >> PTL2_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL2_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int snap_walk_pte_l3(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, snap_walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL3_SHIFT);
	eix = ((end == 0) || ((base + PTL4_SIZE) <= end))? PT_ENTRIES
		: (((end - base) + (PTL3_SIZE - 1)) >> PTL3_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL3_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int snap_walk_pte_l4(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, snap_walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL4_SHIFT);
	eix = (end == 0)? PT_ENTRIES
		:(((end - base) + (PTL4_SIZE - 1)) >> PTL4_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL4_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

struct show_args {
	struct page_table *pt;

	int		nrange;
	int		final;
	uint64_t	start;
	uint64_t	end;
	uint64_t	pstart;
	uint64_t	pend;
	uint64_t	pgsize;
};

static void show_show_args(struct show_args *args)
{
	if (++args->nrange == 1) {
		kprintf("ihk_mc_pt_show(%p):\n", args->pt);
		if (args->start == -1) {
			kprintf("no active pages\n");
			goto final;
		}
	}
	else if (args->start == -1) {
		return;
	}

	kprintf("%012lx-%012lx: %08lx-%08lx [%06x] (%lx)\n",
			args->start, args->end, args->pstart, args->pend,
			args->pgsize, (args->end - args->start));

final:
	if (args->final) {
		kprintf("-------- end of show\n");
	}
	return;
}

static int show_l1(void *args0, pte_t *ptep, uint64_t base, uint64_t start, uint64_t end)
{
	struct show_args *args = args0;
	uint64_t phys;

	if (*ptep & PFL1_PRESENT) {
		phys = *ptep & PT_PHYSMASK;
		if (args->start != -1) {
			if ((args->end == base) && (args->pend == phys)
					&& (args->pgsize == PTL1_SIZE)) {
				args->end += args->pgsize;
				args->pend += args->pgsize;
				return 0;
			}
			show_show_args(args);
		}

		args->start = base;
		args->end = base + PTL1_SIZE;
		args->pstart = phys;
		args->pend = phys + PTL1_SIZE;
		args->pgsize = PTL1_SIZE;
		return 0;
	}
	return 0;
}

static int show_l2(void *args0, pte_t *ptep, uint64_t base, uint64_t start, uint64_t end)
{
	struct show_args *args = args0;
	struct page_table *pt;
	uint64_t phys;

	if ((*ptep & PFL2_PRESENT) && (*ptep & PFL2_SIZE)) {
		phys = *ptep & PT_PHYSMASK & ~(PTL2_SIZE - 1);
		if (args->start != -1) {
			if ((args->end == base) && (args->pend == phys)
					&& (args->pgsize == PTL2_SIZE)) {
				args->end += args->pgsize;
				args->pend += args->pgsize;
				return 0;
			}
			show_show_args(args);
		}

		args->start = base;
		args->end = base + PTL2_SIZE;
		args->pstart = phys;
		args->pend = phys + PTL2_SIZE;
		args->pgsize = PTL2_SIZE;
		return 0;
	}
	if (*ptep & PFL2_PRESENT) {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
		snap_walk_pte_l1(pt, base, start, end, &show_l1, args0);
	}
	return 0;
}

static int show_l3(void *args0, pte_t *ptep, uint64_t base, uint64_t start, uint64_t end)
{
	struct page_table *pt;

	if (*ptep & PFL3_PRESENT) {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
		snap_walk_pte_l2(pt, base, start, end, &show_l2, args0);
	}
	return 0;
}

static int show_l4(void *args0, pte_t *ptep, uint64_t base, uint64_t start, uint64_t end)
{
	struct page_table *pt;

	if (*ptep & PFL4_PRESENT) {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
		snap_walk_pte_l3(pt, base, start, end, &show_l3, args0);
	}
	return 0;
}

void ihk_mc_pt_show(page_table_t pt)
{
	struct show_args args;

	memset(&args, 0, sizeof(args));
	args.pt = pt;
	args.start = -1;

	snap_walk_pte_l4(pt, 0, 0, 0, &show_l4, &args);

	args.final = 1;
	show_show_args(&args);

	return;
}

struct snap_args {
	struct page_table *pt;
};

static int snap_l1(void *args0, pte_t *ptep, uint64_t base, uint64_t start, uint64_t end)
{
	struct snap_args *args = args0;
	uint64_t phys;
	int error;
	pte_t *ptep2;
	void *pgbase;
	uint64_t pgsize;

	if (*ptep & PFL1_PRESENT) {
		phys = *ptep & PT_PHYSMASK;
#if 0
		error = ihk_mc_pt_set_range(args->pt, (void *)base,
				(void *)(base+PTL1_SIZE), phys, 0);
#else
		error = ihk_mc_pt_set_page(args->pt, (void *)base, phys, PTATTR_FOR_USER);
#endif
		if (error) {
			kprintf("snap_l1:ihk_mc_pt_set_range failed %d\n", error);
			return error;
		}
		error = snap_lookup_pte(args->pt, (void *)base, &ptep2, &pgbase, &pgsize);
		if (error) {
			kprintf("snap_l1:snap_lookup_pte failed %d\n", error);
			return error;
		}
		*ptep2 = *ptep;
	}
	return 0;
}
static int snap_l2(void *args0, pte_t *ptep, uint64_t base, uint64_t start, uint64_t end)
{
	struct snap_args *args = args0;
	uint64_t phys;
	int error;
	pte_t *ptep2;
	void *pgbase;
	uint64_t pgsize;
	struct page_table *pt;

	if (*ptep & PFL2_PRESENT) {
		if (*ptep & PFL2_SIZE) {
			phys = *ptep & PT_PHYSMASK & (PTL2_SIZE - 1);
#if 0
			error = ihk_mc_pt_set_range(args->pt, (void *)base,
					(void *)(base+PTL2_SIZE), phys, 0);
#else
			error = ihk_mc_pt_set_large_page(args->pt, (void *)base,
					phys, PTATTR_FOR_USER);
#endif
			if (error) {
				kprintf("snap_l2:ihk_mc_pt_set_range failed %d\n", error);
				return error;
			}
			error = snap_lookup_pte(args->pt, (void *)base, &ptep2, &pgbase, &pgsize);
			if (error) {
				kprintf("snap_l2:snap_lookup_pte failed %d\n", error);
				return error;
			}
			*ptep2 = *ptep;
		}
		else {
			pt = phys_to_virt(*ptep & PT_PHYSMASK);
			snap_walk_pte_l1(pt, base, start, end, &snap_l1, args0);
		}
	}
	return 0;
}
static int snap_l3(void *args0, pte_t *ptep, uint64_t base, uint64_t start, uint64_t end)
{
	struct page_table *pt;

	if (*ptep & PFL3_PRESENT) {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
		snap_walk_pte_l2(pt, base, start, end, &snap_l2, args0);
	}
	return 0;
}
static int snap_l4(void *args0, pte_t *ptep, uint64_t base, uint64_t start, uint64_t end)
{
	struct page_table *pt;

	if (*ptep & PFL4_PRESENT) {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
		snap_walk_pte_l3(pt, base, start, end, &snap_l3, args0);
	}
	return 0;
}

page_table_t ihk_mc_pt_snap(page_table_t srcpt)
{
	struct snap_args args;

	args.pt = __alloc_new_pt(IHK_MC_AP_CRITICAL);
	snap_walk_pte_l4(srcpt, 0, 0, 0, &snap_l4, &args);
	kprintf("ihk_mc_pt_snap(%p): %p\n", srcpt, args.pt);

	return args.pt;
}

struct diff_args {
	struct page_table *	oldpt;
	struct page_table *	newpt;

	int			nrange;
	int			final;
	uint64_t		mode;
	uint64_t		start;
	uint64_t		end;
	uint64_t		pstart;
	uint64_t		pend;
	uint64_t		pgsize;
};

static void show_diff_args(struct diff_args *args)
{
	if (++args->nrange == 1) {
		kprintf("ihk_mc_pt_diff(%p,%p):\n", args->oldpt, args->newpt);
		if (args->start == -1) {
			kprintf("no difference\n");
			goto final;
		}
	}
	else if (args->start == -1) {
		return;
	}

	if (args->mode & PFL1_PRESENT) {
		kprintf("[%d] %012lx-%012lx: mapped %08lx-%08lx [%06x] (%lx)\n",
				args->nrange,
				args->start, args->end, args->pstart, args->pend,
				args->pgsize, (args->end - args->start));
	}
	else if (args->mode & PFL1_WRITABLE) {
		kprintf("[%d] %012lx-%012lx: changed %08lx --> %08lx [%06x]\n",
				args->nrange,
				args->start, args->end, args->pstart, args->pend,
				args->pgsize);
	}
	else {
		kprintf("[%d] %012lx-%012lx: unmapped %08lx-%08lx [%06x] (%lx)\n",
				args->nrange,
				args->start, args->end, args->pstart, args->pend,
				args->pgsize, (args->end - args->start));
	}

final:
	if (args->final) {
		kprintf("-------- end of diff\n");
	}
	return;
}

static void diff_pte_l1(struct page_table *oldpt, struct page_table *newpt, uint64_t base, struct diff_args *args)
{
	int i;
	uint64_t off;
	pte_t diff;
	uint64_t phys;
	pte_t oldpte;
	pte_t newpte;

	for (i = 0; i < PT_ENTRIES; ++i) {
		off = i * PTL1_SIZE;
		oldpte = (oldpt == NULL)? 0: oldpt->entry[i];
		newpte = (newpt == NULL)? 0: newpt->entry[i];
		diff = oldpte ^ newpte;
		if (diff & PFL1_PRESENT) {
			if (oldpte & PFL1_PRESENT) {
				phys = oldpte & PT_PHYSMASK;
				if (args->start != -1) {
					if (!(args->mode & PFL1_PRESENT)
							&& (args->end == (base + off))
							&& (args->pend == phys)
							&& (args->pgsize == PTL1_SIZE)) {
						args->end += args->pgsize;
						args->pend += args->pgsize;
						continue;
					}
					show_diff_args(args);
				}
				args->mode = 0;
				args->start = base + off;
				args->end = base + off + PTL1_SIZE;
				args->pstart = phys;
				args->pend = phys + PTL1_SIZE;
				args->pgsize = PTL1_SIZE;
			}
			else {
				phys = newpte & PT_PHYSMASK;
				if (args->start != -1) {
					if ((args->mode & PFL1_PRESENT)
							&& (args->end == (base + off))
							&& (args->pend == phys)
							&& (args->pgsize == PTL1_SIZE)) {
						args->end += args->pgsize;
						args->pend += args->pgsize;
						continue;
					}
					show_diff_args(args);
				}
				args->mode = PFL1_PRESENT;
				args->start = base + off;
				args->end = base + off + PTL1_SIZE;
				args->pstart = phys;
				args->pend = phys + PTL1_SIZE;
				args->pgsize = PTL1_SIZE;
			}
		}
		else if ((oldpte & PFL1_PRESENT) && diff) {
			if (args->start != -1) {
				show_diff_args(args);
				args->start = -1;
			}

			args->mode = PFL1_WRITABLE;
			args->start = base + off;
			args->end = base + off + PTL1_SIZE;
			args->pstart = oldpte;
			args->pend = newpte;
			args->pgsize = PTL1_SIZE;

			show_diff_args(args);
			args->start = -1;
		}
	}
	return;
}

static void diff_pte_l2(struct page_table *oldpt, struct page_table *newpt, uint64_t base, struct diff_args *args)
{
	int i;
	uint64_t off;
	pte_t oldpte;
	pte_t newpte;
	pte_t diff;
	struct page_table *p;
	struct page_table *q;
	uint64_t phys;
	pte_t pte;
	uint64_t mode;

	for (i = 0; i < PT_ENTRIES; ++i) {
		off = i * PTL2_SIZE;
		oldpte = (oldpt == NULL)? 0: oldpt->entry[i];
		newpte = (newpt == NULL)? 0: newpt->entry[i];
		diff = oldpte ^ newpte;
		if (diff & PFL2_PRESENT) {
			pte = (oldpte & PFL2_PRESENT)? oldpte: newpte;
			mode = (oldpte & PFL2_PRESENT)? 0: PF_PRESENT;
			phys = pte & PT_PHYSMASK;
			if (pte & PFL2_SIZE) {
				phys &= ~(PTL2_SIZE - 1);
				if (args->start != -1) {
					if ((args->mode == mode)
							&& (args->end == (base + off))
							&& (args->pend == phys)
							&& (args->pgsize == PTL2_SIZE)) {
						args->end += args->pgsize;
						args->pend += args->pgsize;
						continue;
					}
					show_diff_args(args);
				}
				args->mode = mode;
				args->start = base + off;
				args->end = base + off + PTL2_SIZE;
				args->pstart = phys;
				args->pend = phys + PTL2_SIZE;
				args->pgsize = PTL2_SIZE;
			}
			else {
				p = !(oldpte & PFL2_PRESENT)? NULL
					: phys_to_virt(oldpte & PT_PHYSMASK);
				q = !(newpte & PFL2_PRESENT)? NULL
					: phys_to_virt(newpte & PT_PHYSMASK);
				diff_pte_l1(p, q, base+off, args);
			}
		}
		else if (oldpte & PFL2_PRESENT) {
			if (diff & PFL2_SIZE) {
				if (args->start != -1) {
					show_diff_args(args);
					args->start = -1;
				}
				p = phys_to_virt(oldpte & PT_PHYSMASK);
				q = phys_to_virt(newpte & PT_PHYSMASK);
				if (oldpte & PFL2_SIZE) {
					phys = oldpte & PT_PHYSMASK;

					args->mode = 0;
					args->start = base + off;
					args->end = base + off + PTL2_SIZE;
					args->pstart = phys;
					args->pend = phys + PTL2_SIZE;
					args->pgsize = PTL2_SIZE;

					show_diff_args(args);
					args->start = -1;

					diff_pte_l1(NULL, q, base+off, args);
				}
				else {
					diff_pte_l1(p, NULL, base+off, args);

					phys = newpte & PT_PHYSMASK;

					args->mode = PFL1_PRESENT;
					args->start = base + off;
					args->end = base + off + PTL2_SIZE;
					args->pstart = phys;
					args->pend = phys + PTL2_SIZE;
					args->pgsize = PTL2_SIZE;

					show_diff_args(args);
					args->start = -1;
				}
				if (args->start != -1) {
					show_diff_args(args);
					args->start = -1;
				}
			}
			else if (!(oldpte & PFL2_SIZE)) {
				p = phys_to_virt(oldpte & PT_PHYSMASK);
				q = phys_to_virt(newpte & PT_PHYSMASK);
				diff_pte_l1(p, q, base+off, args);
			}
			else if (diff) {
				if (args->start != -1) {
					show_diff_args(args);
					args->start = -1;
				}

				args->mode = PFL1_WRITABLE;
				args->start = base + off;
				args->end = base + off + PTL2_SIZE;
				args->pstart = oldpte;
				args->pend = newpte;
				args->pgsize = PTL2_SIZE;

				show_diff_args(args);
				args->start = -1;
			}
		}
	}
	return;
}

static void diff_pte_l3(struct page_table *oldpt, struct page_table *newpt, uint64_t base, struct diff_args *args)
{
	int i;
	uint64_t off;
	pte_t oldpte;
	pte_t newpte;
	pte_t diff;
	struct page_table *p;
	struct page_table *q;
	uint64_t phys;
	pte_t pte;
	uint64_t mode;

	for (i = 0; i < PT_ENTRIES; ++i) {
		off = i * PTL3_SIZE;
		oldpte = (oldpt == NULL)? 0: oldpt->entry[i];
		newpte = (newpt == NULL)? 0: newpt->entry[i];
		diff = oldpte ^ newpte;
		if (diff & PFL3_PRESENT) {
			pte = (oldpte & PFL3_PRESENT)? oldpte: newpte;
			mode = (oldpte & PFL3_PRESENT)? 0: PF_PRESENT;
			phys = pte & PT_PHYSMASK;
			if (pte & PFL3_SIZE) {
				phys &= ~(PTL3_SIZE - 1);
				if (args->start != -1) {
					if ((args->mode == mode)
							&& (args->end == (base + off))
							&& (args->pend == phys)
							&& (args->pgsize == PTL3_SIZE)) {
						args->end += args->pgsize;
						args->pend += args->pgsize;
						continue;
					}
					show_diff_args(args);
				}
				args->mode = mode;
				args->start = base + off;
				args->end = base + off + PTL3_SIZE;
				args->pstart = phys;
				args->pend = phys + PTL3_SIZE;
				args->pgsize = PTL3_SIZE;
			}
			else {
				p = !(oldpte & PFL3_PRESENT)? NULL
					: phys_to_virt(oldpte & PT_PHYSMASK);
				q = !(newpte & PFL3_PRESENT)? NULL
					: phys_to_virt(newpte & PT_PHYSMASK);
				diff_pte_l2(p, q, base+off, args);
			}
		}
		else if (oldpte & PFL3_PRESENT) {
			if (diff & PFL3_SIZE) {
				kprintf("%lx:L3:changed\n", base+off);
			}
			else {
				p = !(oldpte & PFL3_PRESENT)? NULL
					: phys_to_virt(oldpte & PT_PHYSMASK);
				q = !(newpte & PFL3_PRESENT)? NULL
					: phys_to_virt(newpte & PT_PHYSMASK);
				diff_pte_l2(p, q, base+off, args);
			}
		}
	}
	return;
}

static void diff_pte_l4(struct page_table *oldpt, struct page_table *newpt, uint64_t base, struct diff_args *args)
{
	int i;
	uint64_t off;
	struct page_table *p;
	struct page_table *q;

	for (i = 0; i < PT_ENTRIES; ++i) {
		off = i * PTL4_SIZE;
		p = !(oldpt->entry[i] & PFL4_PRESENT)? NULL
			: phys_to_virt(oldpt->entry[i] & PT_PHYSMASK);
		q = !(newpt->entry[i] & PFL4_PRESENT)? NULL
			: phys_to_virt(newpt->entry[i] & PT_PHYSMASK);
		diff_pte_l3(p, q, base+off, args);
	}
	return;
}

void ihk_mc_pt_diff(page_table_t oldpt, page_table_t newpt)
{
	struct diff_args args;

	memset(&args, 0, sizeof(args));
	args.oldpt = oldpt;
	args.newpt = newpt;
	args.start = -1;

	diff_pte_l4(oldpt, newpt, 0, &args);

	args.final = 1;
	show_diff_args(&args);
}

void ihk_mc_pt_destroy_snap(page_table_t pt)
{
	struct page_table *l4pt;
	int l4ix;
	struct page_table *l3pt;
	int l3ix;
	struct page_table *l2pt;
	int l2ix;
	struct page_table *l1pt;

	l4pt = pt;
	for (l4ix = 0; l4ix < PT_ENTRIES; ++l4ix) {
		if (!(l4pt->entry[l4ix] & PFL4_PRESENT)) {
			continue;
		}

		l3pt = phys_to_virt(l4pt->entry[l4ix] & PT_PHYSMASK);
		for (l3ix = 0; l3ix < PT_ENTRIES; ++l3ix) {
			if (!(l3pt->entry[l3ix] & PFL3_PRESENT)
					|| (l3pt->entry[l3ix] & PFL3_SIZE)) {
				continue;
			}

			l2pt = phys_to_virt(l3pt->entry[l3ix] & PT_PHYSMASK);
			for (l2ix = 0; l2ix < PT_ENTRIES; ++l2ix) {
				if (!(l2pt->entry[l2ix] & PFL2_PRESENT)
						|| (l2pt->entry[l2ix] & PFL2_SIZE)) {
					continue;
				}

				l1pt = phys_to_virt(l2pt->entry[l2ix] & PT_PHYSMASK);
				arch_free_page(l1pt);
			}
			arch_free_page(l2pt);
		}
		arch_free_page(l3pt);
	}
	arch_free_page(l4pt);
	return;
}
#endif /* OWANO_IMPLEMENTATION */
