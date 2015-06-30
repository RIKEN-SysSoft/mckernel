#include <linux/module.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/binfmts.h>
#include <linux/elfcore.h>
#include <linux/elf.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include "mcctrl.h"

static int pathcheck(const char *file, const char *list)
{
	const char *p;
	const char *q;
	const char *r;
	int l;

	if(!*list)
		return 1;
	p = list;
	do{
		q = strchr(p, ':');
		if(!q)
			q = strchr(p, '\0');
		for(r = q - 1; r >= p && *r == '/'; r--);
		l = r - p + 1;

		if(!strncmp(file, p, l) &&
		   file[l] == '/')
			return 1;

		p = q + 1;
	} while(*q);
	return 0;
}

static int load_elf(struct linux_binprm *bprm)
{
	const char *i_name;
	char *cp;
	struct file *file;
	char interp[BINPRM_BUF_SIZE];
	int retval;
	struct elfhdr *elf_ex = (struct elfhdr *)bprm->buf;
	typedef struct {
		char	*name;
		char	*val;
		int	l;
	} envdata;
	envdata env[] = {
		{.name = "MCEXEC"},
#define env_mcexec (env[0].val)
		{.name = "MCEXEC_WL"},
#define env_mcexec_wl (env[1].val)
		{.name = "MCEXEC_BL"},
#define env_mcexec_bl (env[2].val)
		{.name = NULL}
	};
	envdata *ep;
	unsigned long off = 0;
	struct page *page;
	char *addr = NULL;
	int i;
	unsigned long p;
	int st;
	int mode;
	int cnt[2];
	char buf[32];
	int l;
	int pass;

	if(memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0)
		return -ENOEXEC;
	if(elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN)
		return -ENOEXEC;

	if(elf_ex->e_ident[EI_CLASS] != ELFCLASS64)
		return -ENOEXEC;

	cp = strrchr(bprm->interp, '/');
	if(!cp ||
	   !strcmp(cp, "/mcexec") ||
	   !strcmp(cp, "/ihkosctl") ||
	   !strcmp(cp, "/ihkconfig"))
		return -ENOEXEC;

	cnt[0] = bprm->argc;
	cnt[1] = bprm->envc;
	for(pass = 0; pass < 2; pass++){
		p = bprm->p;
		mode = cnt[0] == 0? (cnt[1] == 0? 2: 1): 0;
		if(pass == 1){
			for(ep = env; ep->name; ep++){
				if(ep->l)
					ep->val = kmalloc(ep->l, GFP_KERNEL);
			}
		}
		ep = NULL;
		l = 0;
		for(i = 0, st = 0; mode != 2;){
			if(st == 0){
				off = p & ~PAGE_MASK;
				retval = get_user_pages(current, bprm->mm,
				                        bprm->p, 1, 0, 1,
				                        &page, NULL);
				if(retval <= 0)
					return -EFAULT;
				addr = kmap_atomic(page);
				st = 1;
			}
			if(addr[off]){
				if(mode == 1){
					if(ep){
						if(pass == 1)
							ep->val[l] = addr[off];
						l++;
					}
					else if(addr[off] == '='){
						if(l < 32)
							buf[l] = '\0';
						buf[31] = '\0';
						for(ep = env; ep->name; ep++)
							if(!strcmp(ep->name, buf))
								break;
						if(ep->name)
							l = 0;
						else
							ep = NULL;
					}
					else{
						if(l < 32)
							buf[l] = addr[off];
						l++;
					}

				}
			}
			else{
				if(mode == 1 && ep){
					if(pass == 0){
						ep->l = l + 1;
					}
					else{
						ep->val[l] = '\0';
					}
				}
				ep = NULL;
				l = 0;
				i++;
				if(i == cnt[mode]){
					i = 0;
					mode++;
				}
			}
			off++;
			p++;
			if(off == PAGE_SIZE || mode == 2){
				kunmap_atomic(addr);
				put_page(page);
				st = 0;
			}
		}
	}

	if(!env_mcexec || !strcmp(env_mcexec, "0") || !strcmp(env_mcexec, "off"))
		retval = 1;
	else{
		retval = 0;
		if(strchr(env_mcexec, '/') && strlen(env_mcexec) < BINPRM_BUF_SIZE)
			strcpy(interp, env_mcexec);
		else
			strcpy(interp, MCEXEC_PATH);
	}

	if(retval);
	else if(env_mcexec_wl)
		retval = !pathcheck(bprm->interp, env_mcexec_wl);
	else if(env_mcexec_bl)
		retval = pathcheck(bprm->interp, env_mcexec_bl);
	else
		retval = pathcheck(bprm->interp, "/usr:/bin:/sbin:/opt");

	for(ep = env; ep->name; ep++)
		if(ep->val)
			kfree(ep->val);
	if(retval)
		return -ENOEXEC;

	file = open_exec(interp);
	if (IS_ERR(file))
		return -ENOEXEC;

	retval = remove_arg_zero(bprm);
	if (retval){
		fput(file);
		return retval;
	}
	retval = copy_strings_kernel(1, &bprm->interp, bprm);
	if (retval < 0){
		fput(file);
		return retval; 
	}
	bprm->argc++;
	i_name = interp;
	retval = copy_strings_kernel(1, &i_name, bprm);
	if (retval){
		fput(file);
		return retval; 
	}
	bprm->argc++;
#if 1
	retval = bprm_change_interp(interp, bprm);
	if (retval < 0){
		fput(file);
		return retval;
	}
#else
	if(brpm->interp != bprm->filename)
		kfree(brpm->interp);
	kfree(brpm->filename);
	bprm->filename = bprm->interp = kstrdup(interp, GFP_KERNEL);
	if(!bprm->interp){
		fput(file);
		return -ENOMEM;
	}
#endif

	allow_write_access(bprm->file);
	fput(bprm->file);
	bprm->file = file;

	retval = prepare_binprm(bprm);
	if (retval < 0){
		return retval;
	}
	return search_binary_handler(bprm);
}

static struct linux_binfmt mcexec_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_elf,
};

void __init binfmt_mcexec_init(void)
{
	insert_binfmt(&mcexec_format);
}

void __exit binfmt_mcexec_exit(void)
{
	unregister_binfmt(&mcexec_format);
}
