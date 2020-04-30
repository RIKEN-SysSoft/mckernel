/**
 * \file executer/user/mcinspect.c
 *   License details are found in the file LICENSE.
 *
 * \brief
 *   A DWARF based inspection tool for McKernel.
 *
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 *      Copyright (C) 2019  RIKEN
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <dwarf.h>
#include <libdwarf/libdwarf.h>
#include <getopt.h>
#include <libgen.h>
#include <bfd.h>

void usage(char **argv)
{
	printf("Usage: %s <options>\n", basename(argv[0]));
	printf("Inspect internal state of McKernel.\n");
	printf("\n");
	printf("Mandatory arguments to long options are mandatory for short options too.\n");
	printf("    --help                      Display this help message.\n");
	printf("    --kernel PATH               Path to kernel image.\n");
	printf("    --ps                        List processes running on LWK.\n");
	printf("    --vtop                      Dump page tables.\n");
	printf("    -v, --va ADDR               Dump page tables for ADDR only.\n");
	printf("    -p, --pid PID               Use process PID for vtop.\n");
	printf("    --debug                     Enable debug mode.\n");
	printf("\n");
	printf("Examples: \n");
	printf("    %s --kernel=smp-x86/kernel/mckernel.img --ps\n", basename(argv[0]));
	printf("    %s --kernel=smp-x86/kernel/mckernel.img --vtop --pid 100 --va 0x3fffff800000\n",
			basename(argv[0]));
}

int debug;
int mcfd;

/*
 * BFD based symbol table
 */
bfd *symbfd = NULL;
asymbol **symtab = NULL;
ssize_t nsyms;
#define NOSYMBOL (-1UL)

unsigned long int lookup_bfd_symbol(char *name)
{
	int i;

	for (i = 0; i < nsyms; ++i) {
		if (!strcmp(symtab[i]->name, name)) {
			return (symtab[i]->section->vma + symtab[i]->value);
		}
	}

	return NOSYMBOL;
}

int init_bfd_symbols(char *fname) {
	ssize_t needs;
	bfd_boolean ok;

	symbfd = bfd_openr(fname, NULL);

	if (!symbfd) {
		bfd_perror("bfd_openr");
		return -1;
	}

	ok = bfd_check_format(symbfd, bfd_object);
	if (!ok) {
		bfd_perror("bfd_check_format");
		return -1;
	}

	needs = bfd_get_symtab_upper_bound(symbfd);
	if (needs < 0) {
		bfd_perror("bfd_get_symtab_upper_bound");
		return -1;
	}

	if (!needs) {
		printf("no symbols\n");
		return -1;
	}

	symtab = malloc(needs);
	if (!symtab) {
		perror("malloc");
		return -1;
	}

	nsyms = bfd_canonicalize_symtab(symbfd, symtab);
	if (nsyms < 0) {
		bfd_perror("bfd_canonicalize_symtab");
		return -1;
	}

	return 0;
}

/*
 * Walk DWARF tree and call func with arg for each Die
 */
int dwarf_walk_tree(Dwarf_Debug dbg,
	int (*func)(Dwarf_Debug dbg, Dwarf_Die die, void *arg), void *arg)
{
	Dwarf_Bool is_info;
	Dwarf_Unsigned cu_length;
	Dwarf_Half cu_version;
	Dwarf_Off cu_abbrev_offset;
	Dwarf_Half cu_pointer_size;
	Dwarf_Half cu_offset_size;
	Dwarf_Half cu_extension_size;
	Dwarf_Sig8 type_signature;
	Dwarf_Unsigned type_offset;
	Dwarf_Unsigned cu_next_offset;
	Dwarf_Error err;
	Dwarf_Die unit;
	Dwarf_Die die;
	int rc;

	/* Iterate compile and type units */
	for (is_info = 0; is_info < 2; ++is_info) {
		rc = dwarf_next_cu_header_c(dbg, is_info, &cu_length,
				&cu_version, &cu_abbrev_offset, &cu_pointer_size,
				&cu_offset_size, &cu_extension_size, &type_signature,
				&type_offset, &cu_next_offset, &err);

		while (rc != DW_DLV_NO_ENTRY) {
			char *name = NULL;
			const char *tag_name;
			Dwarf_Half tag;
			Dwarf_Die next;

			if (rc != DW_DLV_OK) {
				fprintf(stderr, "error: dwarf_next_cu_header_c: %d %s\n",
						rc, dwarf_errmsg(err));
				return -1;
			}

			rc = dwarf_siblingof(dbg, NULL, &unit, &err);
			if (rc != DW_DLV_OK) {
				fprintf(stderr, "error: dwarf_siblingof failed: %d %s\n",
						rc, dwarf_errmsg(err));
				return -1;
			}

			if (debug) {
				rc = dwarf_diename(unit, &name, &err);
				if (rc == DW_DLV_NO_ENTRY) {
					name = NULL;
				}
				else if (rc != DW_DLV_OK) {
					fprintf(stderr, "error: dwarf_diename error: %d %s\n",
							rc, dwarf_errmsg(err));
					return -1;
				}

				rc = dwarf_tag(unit, &tag, &err);
				if (rc != DW_DLV_OK) {
					fprintf(stderr, "dwarf_tag error: %d %s\n",
							rc, dwarf_errmsg(err));
					return -1;
				}

				rc = dwarf_get_TAG_name(tag, &tag_name);
				if (rc != DW_DLV_OK) {
					fprintf(stderr,
							"dwarf_get_TAG_name error: %d\n", rc);
					return -1;
				}

				printf("%p <%d> %s: %s\n", unit, tag,
						tag_name, name ? name : "<no name>");
			}

			/* Iterate entries in this unit */
			rc = dwarf_child(unit, &die, &err);
			if (rc == DW_DLV_ERROR) {
				fprintf(stderr, "dwarf_child error: %d %s\n",
						rc, dwarf_errmsg(err));
				return -1;
			}

			while (die) {
				if (debug) {
					char *name = NULL;
					const char *tag_name;
					Dwarf_Half tag;

					rc = dwarf_diename(die, &name, &err);
					if (rc == DW_DLV_NO_ENTRY) {
						name = NULL;
					}
					else if (rc != DW_DLV_OK) {
						fprintf(stderr, "error: dwarf_diename error: %d %s\n",
								rc, dwarf_errmsg(err));
						return -1;
					}

					rc = dwarf_tag(die, &tag, &err);
					if (rc != DW_DLV_OK) {
						fprintf(stderr, "dwarf_tag error: %d %s\n",
								rc, dwarf_errmsg(err));
						return -1;
					}

					rc = dwarf_get_TAG_name(tag, &tag_name);
					if (rc != DW_DLV_OK) {
						fprintf(stderr,
								"dwarf_get_TAG_name error: %d\n", rc);
						return -1;
					}

					printf("    %p <%d> %s: %s\n", die, tag,
							tag_name, name ? name : "<no name>");
				}

				if (func) {
					rc = func(dbg, die, arg);
					/* Stop when DW_DLV_OK reached */
					if (rc == DW_DLV_OK) {
						return 0;
					}
				}

				rc = dwarf_siblingof(dbg, die, &next, &err);
				dwarf_dealloc(dbg, die, DW_DLA_DIE);
				if (name)
					dwarf_dealloc(dbg, name, DW_DLA_STRING);

				if (rc != DW_DLV_OK)
					break;

				die = next;
			}

			rc = dwarf_next_cu_header_c(dbg, is_info, &cu_length,
					&cu_version, &cu_abbrev_offset, &cu_pointer_size,
					&cu_offset_size, &cu_extension_size, &type_signature,
					&type_offset, &cu_next_offset, &err);
		}
	}

	return -1;
}

int dwarf_get_size(Dwarf_Debug dbg,
		Dwarf_Die die,
		unsigned long *psize,
		Dwarf_Error *perr)
{
	Dwarf_Attribute attr;
	Dwarf_Unsigned size;
	Dwarf_Half form;
	int rc;

	rc = dwarf_attr(die, DW_AT_byte_size, &attr, perr);
	if (rc != DW_DLV_OK) {
		return rc;
	}

	rc = dwarf_whatform(attr, &form, perr);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: getting whatform: %s\n",
			__func__, dwarf_errmsg(*perr));
		return rc;
	}

	if (form == DW_FORM_data1 ||
			form == DW_FORM_data2 ||
			form == DW_FORM_data2 ||
			form == DW_FORM_data4 ||
			form == DW_FORM_data8 ||
			form == DW_FORM_udata) {
		dwarf_formudata(attr, &size, 0);
	}
	else if (form == DW_FORM_sdata) {
		Dwarf_Signed ssize;
		dwarf_formsdata(attr, &ssize, 0);

		if (ssize < 0) {
			fprintf(stderr, "%s: unsupported negative size\n",
				__func__);
			return DW_DLV_ERROR;
		}

		size = (Dwarf_Unsigned) ssize;
	}
	else {
		Dwarf_Locdesc **locdescs;
		Dwarf_Signed len;

		if (dwarf_loclist_n(attr, &locdescs, &len,  perr)
				== DW_DLV_ERROR) {
			fprintf(stderr, "%s: unsupported member size\n",
					__func__);
			return DW_DLV_ERROR;
		}

		if (len != 1 ||
				locdescs[0]->ld_cents != 1 ||
				(locdescs[0]->ld_s[0]).lr_atom
				!= DW_OP_plus_uconst) {
			fprintf(stderr,
					"%s: unsupported location expression\n",
					__func__);
			return DW_DLV_ERROR;
		}

		size = (locdescs[0]->ld_s[0]).lr_number;
	}
	dwarf_dealloc(dbg, attr, DW_DLA_ATTR);

	*psize = (unsigned long)size;
	return DW_DLV_OK;
}

/*
 * Find the size of a type.
 */
struct dwarf_size_arg {
	char *name;
	unsigned long *sizep;
};

int dwarf_size(Dwarf_Debug dbg, Dwarf_Die die, void *arg)
{
	struct dwarf_size_arg *ds =
		(struct dwarf_size_arg *)arg;
	Dwarf_Half tag;
	Dwarf_Error err;
	char *name = NULL;
	int rc;
	unsigned long size;

	rc = dwarf_tag(die, &tag, &err);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: dwarf_tag: %d %s\n",
				__func__, rc, dwarf_errmsg(err));
		goto out;
	}

	rc = dwarf_diename(die, &name, &err);
	if (rc == DW_DLV_NO_ENTRY) {
		name = NULL;
	}
	else if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: dwarf_diename: %d %s\n",
				__func__, rc, dwarf_errmsg(err));
		goto out;
	}

	if (!name || strcasecmp(name, ds->name)) {
		rc = DW_DLV_NO_ENTRY;
		goto out;
	}

	rc = dwarf_get_size(dbg, die, &size, &err);
	if (rc == DW_DLV_NO_ENTRY) {
		goto out;
	}
	else if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: getting size: %s\n",
				__func__, dwarf_errmsg(err));
		goto out;
	}

	if (debug) {
		fprintf(stdout, "size of type \"%s\": %lu\n",
				ds->name, size);
	}

	*ds->sizep = size;
	rc = DW_DLV_OK;

out:
	if (name)
		dwarf_dealloc(dbg, name, DW_DLA_STRING);

	return rc;
}

#define DWARF_GET_SIZE(__name__)  \
({  \
	unsigned long size; \
	int rc; \
	struct dwarf_size_arg ds = { \
	    .name = #__name__, \
	    .sizep = &size, \
	}; \
	rc = dwarf_walk_tree(dbg, dwarf_size, &ds); \
	if (rc != DW_DLV_OK) { \
		fprintf(stderr, "%s: error: finding size of %s\n", \
			__func__, ds.name); \
	   exit(1); \
	} \
	size; \
})


int dwarf_get_offset(Dwarf_Debug dbg,
		Dwarf_Die die,
		unsigned long *poffset,
		Dwarf_Error *perr)
{
	Dwarf_Attribute attr;
	Dwarf_Unsigned offset;
	Dwarf_Half form;
	int rc;

	rc = dwarf_attr(die, DW_AT_data_member_location, &attr, perr);
	if (rc != DW_DLV_OK) {
		return rc;
	}

	rc = dwarf_whatform(attr, &form, perr);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: getting whatform: %s\n",
			__func__, dwarf_errmsg(*perr));
		return rc;
	}

	if (form == DW_FORM_data1 ||
			form == DW_FORM_data2 ||
			form == DW_FORM_data2 ||
			form == DW_FORM_data4 ||
			form == DW_FORM_data8 ||
			form == DW_FORM_udata) {
		dwarf_formudata(attr, &offset, 0);
	}
	else if (form == DW_FORM_sdata) {
		Dwarf_Signed soffset;
		dwarf_formsdata(attr, &soffset, 0);

		if (soffset < 0) {
			fprintf(stderr, "%s: unsupported negative offset\n",
				__func__);
			return DW_DLV_ERROR;
		}

		offset = (Dwarf_Unsigned) soffset;
	}
	else {
		Dwarf_Locdesc **locdescs;
		Dwarf_Signed len;

		if (dwarf_loclist_n(attr, &locdescs, &len,  perr)
				== DW_DLV_ERROR) {
			fprintf(stderr, "%s: unsupported member offset\n",
					__func__);
			return DW_DLV_ERROR;
		}

		if (len != 1 ||
				locdescs[0]->ld_cents != 1 ||
				(locdescs[0]->ld_s[0]).lr_atom
				!= DW_OP_plus_uconst) {
			fprintf(stderr,
					"%s: unsupported location expression\n",
					__func__);
			return DW_DLV_ERROR;
		}

		offset = (locdescs[0]->ld_s[0]).lr_number;
	}
	dwarf_dealloc(dbg, attr, DW_DLA_ATTR);

	*poffset = (unsigned long)offset;
	return DW_DLV_OK;
}

/*
 * Find the offset of a field in a struct.
 */
struct dwarf_struct_field_offset_arg {
	char *struct_name;
	char *field_name;
	unsigned long *offp;
};

int dwarf_struct_field_offset(Dwarf_Debug dbg, Dwarf_Die die, void *arg)
{
	struct dwarf_struct_field_offset_arg *dsfo =
		(struct dwarf_struct_field_offset_arg *)arg;
	Dwarf_Half tag;
	Dwarf_Error err;
	Dwarf_Die child, next;
	char *name = NULL;
	int rc;
	unsigned long offset;
	int found = 0;

	rc = dwarf_tag(die, &tag, &err);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: dwarf_tag: %d %s\n",
				__func__, rc, dwarf_errmsg(err));
		goto out;
	}

	rc = dwarf_diename(die, &name, &err);
	if (rc == DW_DLV_NO_ENTRY) {
		name = NULL;
	}
	else if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: dwarf_diename: %d %s\n",
				__func__, rc, dwarf_errmsg(err));
		goto out;
	}

	if (tag != DW_TAG_structure_type || !name ||
			strcasecmp(name, dsfo->struct_name)) {
		rc = DW_DLV_NO_ENTRY;
		goto out;
	}

	rc = dwarf_child(die, &child, &err);
	if (rc == DW_DLV_ERROR) {
		fprintf(stderr, "%s: dwarf_child error: %d %s\n",
				__func__, rc, dwarf_errmsg(err));
		rc = DW_DLV_NO_ENTRY;
		goto out;
	}

	while (child) {
		rc = dwarf_diename(child, &name, &err);
		if (rc == DW_DLV_NO_ENTRY) {
			name = NULL;
		}
		else if (rc != DW_DLV_OK) {
			fprintf(stderr, "%s: error: dwarf_diename: %d %s\n",
					__func__, rc, dwarf_errmsg(err));
			goto out;
		}

		rc = dwarf_tag(child, &tag, &err);
		if (rc != DW_DLV_OK) {
			fprintf(stderr, "%s: error: dwarf_tag: %d %s\n",
					__func__, rc, dwarf_errmsg(err));
			goto out;
		}

		if (tag != DW_TAG_member || !name ||
				strcasecmp(name, dsfo->field_name)) {
			goto next_child;
		}

		rc = dwarf_get_offset(dbg, child, &offset, &err);
		if (rc == DW_DLV_NO_ENTRY) {
			offset = 0;
		}
		else if (rc != DW_DLV_OK) {
			fprintf(stderr, "%s: error: getting dwarf attr offset: %s\n",
					__func__, dwarf_errmsg(err));
			goto out;
		}

		if (debug) {
			fprintf(stdout, "offset of field \"%s\" in struct \"%s\": %lu\n",
					dsfo->field_name, dsfo->struct_name, offset);
		}

		*dsfo->offp = offset;
		dwarf_dealloc(dbg, child, DW_DLA_DIE);
		found = 1;
		break;

next_child:
		rc = dwarf_siblingof(dbg, child, &next, &err);
		dwarf_dealloc(dbg, child, DW_DLA_DIE);
		if (rc != DW_DLV_OK) {
			fprintf(stderr, "%s: error: dwarf_siblingof: %d %s\n",
					__func__, rc, dwarf_errmsg(err));
			rc = DW_DLV_NO_ENTRY;
			goto out;
		}

		child = next;
	}

	if (found) {
		rc = DW_DLV_OK;
	}
	else {
		rc = DW_DLV_NO_ENTRY;
	}

out:
	if (name)
		dwarf_dealloc(dbg, name, DW_DLA_STRING);

	return rc;
}

#define DWARF_GET_OFFSET_IN_STRUCT(__struct_name__, __field_name__)  \
({  \
	unsigned long offset; \
	int rc; \
	struct dwarf_struct_field_offset_arg dsfo = { \
	    .struct_name = #__struct_name__, \
	    .field_name = #__field_name__, \
	    .offp = &offset, \
	}; \
	rc = dwarf_walk_tree(dbg, dwarf_struct_field_offset, &dsfo); \
	if (rc != DW_DLV_OK) { \
		fprintf(stderr, "%s: error: finding %s in struct %s\n", \
		   __func__, dsfo.field_name, dsfo.struct_name); \
	   exit(1); \
	} \
	offset; \
})


/*
 * Find the address of a global variable.
 */
int dwarf_get_address(Dwarf_Debug dbg,
		Dwarf_Die die,
		unsigned long *paddr,
		Dwarf_Error *perr)
{
	Dwarf_Unsigned addr;
	Dwarf_Half form;
	Dwarf_Half directform = 0;
	int rc, i;
	int found = 0;

	Dwarf_Signed atcnt = 0;
	Dwarf_Attribute *atlist = 0;

#if 0
	Dwarf_Attribute attr;

	rc = dwarf_attr(die, DW_AT_location, &attr, perr);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: warning: no location attr: %s\n",
				__func__, dwarf_errmsg(*perr));
		return rc;
	}
#endif

	rc = dwarf_attrlist(die, &atlist, &atcnt, perr);
	if (rc == DW_DLV_ERROR) {
		fprintf(stderr, "%s: error: getting attrlist: %s\n",
				__func__, dwarf_errmsg(*perr));
		return rc;
	}
	else if (rc == DW_DLV_NO_ENTRY) {
		/* indicates there are no attrs.  It is not an error. */
		return rc;
	}

	for (i = 0; i < atcnt; i++) {
		Dwarf_Half attr_i;
		Dwarf_Attribute attr;

		rc = dwarf_whatattr(atlist[i], &attr_i, perr);
		if (rc != DW_DLV_OK) {
			fprintf(stderr, "%s: error: getting attr: %s\n",
					__func__, dwarf_errmsg(*perr));
			goto dealloc_out;
		}
		attr = atlist[i];

		if (attr_i != DW_AT_location) {
			continue;
		}
		printf("%s: DW_AT_location\n", __func__);

		rc = dwarf_whatform(attr, &form, perr);
		if (rc != DW_DLV_OK) {
			fprintf(stderr, "%s: error: getting whatform: %s\n",
					__func__, dwarf_errmsg(*perr));
			goto dealloc_out;
		}
		dwarf_whatform_direct(attr, &directform, perr);

		if (form == DW_FORM_block1 ||
				form == DW_FORM_block2 ||
				form == DW_FORM_block4 ||
				form == DW_FORM_block ||
				form == DW_FORM_data4 ||
				form == DW_FORM_data8 ||
				form == DW_FORM_sec_offset) {

			Dwarf_Locdesc **locdescs;
			Dwarf_Signed len;

			if (dwarf_loclist_n(attr, &locdescs, &len,  perr)
					== DW_DLV_ERROR) {
				fprintf(stderr, "%s: dwarf_loclist_n: %s\n",
						__func__, dwarf_errmsg(*perr));
				rc = DW_DLV_ERROR;
				goto dealloc_out;
			}

			if (len != 1 ||
					locdescs[0]->ld_cents != 1 ||
					(locdescs[0]->ld_s[0]).lr_atom
					!= DW_OP_addr) {
				fprintf(stderr,
						"%s: unsupported addr expression\n",
						__func__);
				rc = DW_DLV_ERROR;
				goto dealloc_out;
			}

			addr = (locdescs[0]->ld_s[0]).lr_number;
		}
		else if (form == DW_FORM_exprloc)  {
			Dwarf_Half address_size = 0;
			Dwarf_Ptr x = 0;
			Dwarf_Unsigned tempud = 0;
			Dwarf_Locdesc *locdescs = 0;
			Dwarf_Signed len = 0;

			rc = dwarf_formexprloc(attr, &tempud, &x, perr);
			if (rc == DW_DLV_NO_ENTRY) {
				fprintf(stderr, "%s: dwarf_formexprloc: no entry?\n",
						__func__);
				goto dealloc_out;
			}
			else if (rc == DW_DLV_ERROR) {
				fprintf(stderr, "%s: dwarf_formexprloc(): %s\n",
						__func__, dwarf_errmsg(*perr));
				goto dealloc_out;
			}

			rc = dwarf_get_die_address_size(die, &address_size, perr);
			if (rc == DW_DLV_NO_ENTRY) {
				fprintf(stderr, "%s: dwarf_get_die_address_size: no entry?\n",
						__func__);
				goto dealloc_out;
			}
			else if (rc == DW_DLV_ERROR) {
				fprintf(stderr, "%s: dwarf_get_die_address_size: %s\n",
						__func__, dwarf_errmsg(*perr));
				goto dealloc_out;
			}

			rc = dwarf_loclist_from_expr_a(dbg, x, tempud, address_size,
					&locdescs, &len, perr);
			if (rc == DW_DLV_ERROR) {
				fprintf(stderr, "%s: dwarf_loclist_from_expr_a: %s\n",
						__func__, dwarf_errmsg(*perr));
				goto dealloc_out;
			}
			else if (rc == DW_DLV_NO_ENTRY) {
				fprintf(stderr, "%s: dwarf_loclist_from_expr_a: no entry?\n",
						__func__);
				goto dealloc_out;
			}

			/* len is always 1 */
			if (len != 1 ||
					locdescs[0].ld_cents != 1 ||
					(locdescs[0].ld_s[0]).lr_atom
					!= DW_OP_addr) {
				fprintf(stderr,
						"%s: unsupported addr expression\n",
						__func__);
				goto dealloc_out;
			}

			addr = (locdescs[0].ld_s[0]).lr_number;
		}
		else {
			fprintf(stderr, "%s: unsupported form type?\n",
					__func__);
			goto dealloc_out;
		}

		*paddr = (unsigned long)addr;
		if (debug) {
			printf("%s: addr: 0x%lx\n", __func__, (unsigned long)addr);
		}

		found = 1;
		break;
	}

dealloc_out:
	for (i = 0; i < atcnt; i++) {
		dwarf_dealloc(dbg, atlist[i], DW_DLA_ATTR);
	}

	dwarf_dealloc(dbg, atlist, DW_DLA_LIST);

	if (found) {
		rc = DW_DLV_OK;
	}
	else {
		rc = DW_DLV_NO_ENTRY;
	}

	return rc;
}

struct dwarf_global_var_addr_arg {
	char *variable;
	unsigned long *addrp;
};

int dwarf_global_var_addr(Dwarf_Debug dbg, Dwarf_Die die, void *arg)
{
	struct dwarf_global_var_addr_arg *gva =
		(struct dwarf_global_var_addr_arg *)arg;
	Dwarf_Half tag;
	Dwarf_Error err;
	char *name = NULL;
	unsigned long addr;
	int rc;

	rc = dwarf_tag(die, &tag, &err);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: dwarf_tag: %d %s\n",
				__func__, rc, dwarf_errmsg(err));
		goto out;
	}

	rc = dwarf_diename(die, &name, &err);
	if (rc == DW_DLV_NO_ENTRY) {
		name = NULL;
	}
	else if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: dwarf_diename: %d %s\n",
				__func__, rc, dwarf_errmsg(err));
		goto out;
	}

	if (tag != DW_TAG_variable || !name ||
			strcasecmp(name, gva->variable)) {
		rc = DW_DLV_NO_ENTRY;
		goto out;
	}

	printf("%s: inspecting %s\n", __func__, name);

	rc = dwarf_get_address(dbg, die, &addr, &err);
	if (rc == DW_DLV_NO_ENTRY) {
		printf("%s: inspecting %s -> DW_DLV_NO_ENTRY for addr?\n", __func__, name);
		goto out;
	}
	else if (rc != DW_DLV_OK) {
		fprintf(stderr, "%s: error: getting dwarf addr location: %s\n",
				__func__, dwarf_errmsg(err));
		goto out;
	}

	if (debug) {
		fprintf(stdout, "%s: found %s @ 0x%lx\n", __func__, name, addr);
	}

	*gva->addrp = addr;
	rc = DW_DLV_OK;

out:
	if (name)
		dwarf_dealloc(dbg, name, DW_DLA_STRING);

	return rc;
}


#define DWARF_GET_VARIABLE_ADDRESS(__variable__) \
({ \
	unsigned long addr; \
	int rc; \
	struct dwarf_global_var_addr_arg gva = { \
		.variable = #__variable__, \
		.addrp = &addr, \
	}; \
	addr = lookup_bfd_symbol(gva.variable); \
	if (addr == NOSYMBOL) { \
		rc = dwarf_walk_tree(dbg, dwarf_global_var_addr, &gva); \
		if (rc != DW_DLV_OK) { \
			fprintf(stderr, "%s: error: finding addr of %s\n", \
				__func__, gva.variable); \
			exit(1); \
		} \
	} \
	addr; \
})


/* IHK kernel inspection I/F */
#define IHK_OS_READ_KADDR             0x112a39

#define IHK_OS_READ_KADDR_VIRT	0
#define IHK_OS_READ_KADDR_PHYS	1
struct ihk_os_read_kaddr_desc {
	unsigned long kaddr;
	unsigned long len;
	void *ubuf;
	int flags;
};


void ihk_read_kernel(unsigned long addr,
	unsigned long len, void *buf, int flags)
{
	struct ihk_os_read_kaddr_desc desc;

	desc.kaddr = addr;
	desc.len = len;
	desc.ubuf = buf;
	desc.flags = flags;

	if (ioctl(mcfd, IHK_OS_READ_KADDR, &desc) != 0) {
		fprintf(stderr, "%s: error: accessing kernel addr 0x%lx\n",
			__func__, addr);
		exit(1);
	}
}

#define ihk_read_val(addr, pval) \
	ihk_read_kernel(addr, sizeof(*pval), (void *)pval, \
		IHK_OS_READ_KADDR_VIRT)

#define ihk_read_val_phys(addr, pval) \
	ihk_read_kernel(addr, sizeof(*pval), (void *)pval, \
		IHK_OS_READ_KADDR_PHYS)

#define get_pointer_symbol_val(__variable__, pval) \
({ \
	unsigned long addr; \
	addr = DWARF_GET_VARIABLE_ADDRESS(__variable__); \
	ihk_read_kernel(addr, sizeof(*pval), (void *)pval, \
		IHK_OS_READ_KADDR_VIRT); \
})


#define PS_RUNNING           0x1
#define PS_INTERRUPTIBLE     0x2
#define PS_UNINTERRUPTIBLE   0x4
#define PS_ZOMBIE            0x8
#define PS_EXITED            0x10
#define PS_STOPPED           0x20

/*
 * Globals
 */
int nr_cpus;
unsigned long clv;
unsigned long clv_size;
unsigned long clv_runq_offset;
unsigned long clv_idle_offset;
unsigned long clv_current_offset;
unsigned long thread_tid_offset;
unsigned long thread_sched_list_offset;
unsigned long thread_proc_offset;
unsigned long thread_status_offset;
unsigned long process_pid_offset;
unsigned long process_vm_offset;
unsigned long process_saved_cmdline_offset;
unsigned long process_saved_cmdline_len_offset;
unsigned long vm_address_space_offset;
unsigned long address_space_page_table_offset;

void init_globals(Dwarf_Debug dbg)
{
	unsigned long num_processors_addr;

	num_processors_addr = DWARF_GET_VARIABLE_ADDRESS(mck_num_processors);
	ihk_read_val(num_processors_addr, &num_processors_addr);
	ihk_read_val(num_processors_addr, &nr_cpus);
	ihk_read_val(DWARF_GET_VARIABLE_ADDRESS(clv), &clv);
	clv_size = DWARF_GET_SIZE(cpu_local_var);

	clv_runq_offset = DWARF_GET_OFFSET_IN_STRUCT(cpu_local_var, runq);
	clv_idle_offset = DWARF_GET_OFFSET_IN_STRUCT(cpu_local_var, idle);
	clv_current_offset = DWARF_GET_OFFSET_IN_STRUCT(cpu_local_var, current);
	thread_tid_offset = DWARF_GET_OFFSET_IN_STRUCT(thread, tid);
	thread_proc_offset = DWARF_GET_OFFSET_IN_STRUCT(thread, proc);
	thread_status_offset = DWARF_GET_OFFSET_IN_STRUCT(thread, status);
	thread_sched_list_offset =
		DWARF_GET_OFFSET_IN_STRUCT(thread, sched_list);
	process_pid_offset = DWARF_GET_OFFSET_IN_STRUCT(process, pid);
	process_saved_cmdline_offset =
		DWARF_GET_OFFSET_IN_STRUCT(process, saved_cmdline);
	process_saved_cmdline_len_offset =
		DWARF_GET_OFFSET_IN_STRUCT(process, saved_cmdline_len);
	process_vm_offset =
		DWARF_GET_OFFSET_IN_STRUCT(process, vm);
	vm_address_space_offset =
		DWARF_GET_OFFSET_IN_STRUCT(process_vm, address_space);
	address_space_page_table_offset =
		DWARF_GET_OFFSET_IN_STRUCT(address_space, page_table);
}

void print_thread(int cpu,
		unsigned long thread,
		unsigned long idle,
		int active)
{
	int tid;
	int pid;
	int status;
	unsigned long proc;
	char *comm = "(unknown)";
	char *cmd_line = NULL;
	long cmd_line_len;
	long cmd_line_addr;

	ihk_read_val(thread + thread_tid_offset, &tid);
	ihk_read_val(thread + thread_proc_offset, &proc);
	ihk_read_val(thread + thread_status_offset, &status);
	ihk_read_val(proc + process_pid_offset, &pid);
	ihk_read_val(proc + process_saved_cmdline_len_offset,
			&cmd_line_len);

	if (thread == idle) {
		comm = "(idle)";
	}

	if (cmd_line_len) {
		cmd_line = malloc(cmd_line_len + 1);
		if (!cmd_line) {
			fprintf(stderr, "%s: error: allocating cmdline\n",
					__func__);
			exit(1);
		}
		memset(cmd_line, 0, cmd_line_len + 1);

		ihk_read_val(proc + process_saved_cmdline_offset, &cmd_line_addr);
		ihk_read_kernel(cmd_line_addr, cmd_line_len, cmd_line,
				IHK_OS_READ_KADDR_VIRT);
		comm = basename(cmd_line);
	}

	printf("%3d %s%6d %6d 0x%16lx %2s %s\n",
			cpu, active ? ">" : " ", tid, pid, thread,
			//"DS",
			status == PS_RUNNING ? "R" :
			status == PS_INTERRUPTIBLE ? "IN" :
			status == PS_UNINTERRUPTIBLE ? "UN" :
			status == PS_ZOMBIE ? "Z" :
			status == PS_EXITED ? "E" :
			status == PS_STOPPED ? "S" : "U",
			comm);

	if (cmd_line)
		free(cmd_line);
}

int mcps(Dwarf_Debug dbg)
{
	int cpu;

	printf("%3s %s%6s %6s %18s %2s %s\n",
		"CPU", " ", "TID", "PID", "Thread", "ST", "exe");
	printf("-----------------------------------------------\n");

	/* Iterate CPUs */
	for (cpu = 0; cpu < nr_cpus; ++cpu) {
		unsigned long per_cpu;
		unsigned long runq;
		unsigned long thread;
		unsigned long thread_sched_list;
		unsigned long idle;
		unsigned long current;

		per_cpu = clv + (clv_size * cpu);
		runq = per_cpu + clv_runq_offset;
		idle = per_cpu + clv_idle_offset;
		ihk_read_val(per_cpu + clv_current_offset, &current);
		ihk_read_val(per_cpu + clv_runq_offset, &thread_sched_list);

		print_thread(cpu, current, idle, 1);

		/* Iterate threads */
		for (; thread_sched_list != runq;
				ihk_read_val(thread_sched_list, &thread_sched_list)) {
			thread = thread_sched_list - thread_sched_list_offset;

			if (thread == current)
				continue;

			print_thread(cpu, thread, idle, 0);
		}

		if (current != idle) {
			print_thread(cpu, idle, idle, 0);
		}
	}

	return 0;
}

int find_proc(Dwarf_Debug dbg, int pid, unsigned long *rproc)
{
	int cpu;

	/* Iterate CPUs */
	for (cpu = 0; cpu < nr_cpus; ++cpu) {
		unsigned long per_cpu;
		unsigned long runq;
		unsigned long thread;
		unsigned long thread_sched_list;
		int ipid;

		per_cpu = clv + (clv_size * cpu);
		runq = per_cpu + clv_runq_offset;
		ihk_read_val(per_cpu + clv_runq_offset, &thread_sched_list);

		/* Iterate threads */
		for (; thread_sched_list != runq;
				ihk_read_val(thread_sched_list, &thread_sched_list)) {
			unsigned long proc;

			thread = thread_sched_list - thread_sched_list_offset;

			ihk_read_val(thread + thread_proc_offset, &proc);
			ihk_read_val(proc + process_pid_offset, &ipid);

			if (pid == ipid) {
				*rproc = proc;
				return 0;
			}
		}
	}

	return -1;
}


#if 0
void do_pte_walk_single(Dwarf_Debug dbg,
	unsigned long pt, int level, unsigned long va)
{
	unsigned long pte;
	int idx = va >> ptl_shift(level);

	ihk_read_val(pt + idx * sizeof(pte), &pte);
	if (pte_is_type_page(pte, level)) {

	}

	if (level > 1) {
		pt =
		do_pte_walk_single();
	}
}


int print_pte_single(Dwarf_Debug dbg,
	unsigned long pt, unsigned long va)
{
	int level = PGTABLE_LEVELS;
	printf("VA: 0x%lx -> \n", va);
	do_pte_walk_single(dbg, pt, PGTABLE_LEVELS, va);
}

#endif


int mcvtop(Dwarf_Debug dbg, int pid, unsigned long vtop_addr)
{
	unsigned long proc = 0;
	unsigned long init_pt;
	unsigned long vm, ap, pt = 0;

	if (pid != 0) {
		if (find_proc(dbg, pid, &proc) < 0) {
			fprintf(stderr, "%s: error: finding PID %d\n",
				__func__, pid);
			return -1;
		}
	}

	get_pointer_symbol_val(swapper_page_table, &init_pt);
	printf("%s: init_pt: 0x%lx\n", __func__, init_pt);

	if (proc) {
		ihk_read_val(proc + process_vm_offset, &vm);
		ihk_read_val(vm + vm_address_space_offset, &ap);
		ihk_read_val(ap + address_space_page_table_offset, &pt);
	}

	return 0;
}


int help;
int ps;
int vtop;
int pid;
unsigned long vtop_addr;

struct option mcinspect_options[] = {
	{
		.name =		"kernel",
		.has_arg =	required_argument,
		.flag =		NULL,
		.val =		'k',
	},
	{
		.name =		"ps",
		.has_arg =	no_argument,
		.flag =		&ps,
		.val =		1,
	},
	{
		.name =		"help",
		.has_arg =	no_argument,
		.flag =		&help,
		.val =		1,
	},
	{
		.name =		"debug",
		.has_arg =	no_argument,
		.flag =		&debug,
		.val =		1,
	},
	{
		.name =		"vtop",
		.has_arg =	no_argument,
		.flag =		&vtop,
		.val =		1,
	},
	{
		.name =		"va",
		.has_arg =	required_argument,
		.flag =		NULL,
		.val =		'v',
	},
	{
		.name =		"pid",
		.has_arg =	required_argument,
		.flag =		NULL,
		.val =		'p',
	},
	/* end */
	{ NULL, 0, NULL, 0, },
};


int main(int argc, char **argv)
{
	Dwarf_Debug dbg = 0;
	int dwarffd = -1;
	int rc = DW_DLV_ERROR;
	char *kernel_path = NULL;
	Dwarf_Error error;
	Dwarf_Handler errhand = 0;
	Dwarf_Ptr errarg = 0;
	int opt;

	debug = 0;
	mcfd = -1;
	help = 0;
	ps = 0;
	vtop = 0;
	vtop_addr = -1UL;
	pid = 0;

	while ((opt = getopt_long(argc, argv, "+k:v:p:",
					mcinspect_options, NULL)) != -1) {
		switch (opt) {
		case 'k':
			kernel_path = optarg;
			break;

		case 'v':
			vtop_addr = strtoul(optarg, 0, 16);
			if (vtop_addr == 0 ||
					errno == EINVAL || errno == ERANGE) {
				fprintf(stderr, "error: invalid VA? (expected format: 0xXXXX)\n\n");
				usage(argv);
				exit(1);
			}
			break;

		case 'p':
			pid = atoi(optarg);
			break;
		}
	}

	if (help) {
		usage(argv);
		exit(0);
	}

	if (!kernel_path) {
		fprintf(stderr, "error: you must specify the kernel image\n\n");
		usage(argv);
		exit(1);
	}

	if (!ps && !vtop) {
		printf("PID: %d\n", pid);
		usage(argv);
		exit(1);
	}

	if (init_bfd_symbols(kernel_path) < 0) {
		fprintf(stderr, "error: accessing ELF image %s\n", kernel_path);
		exit(1);
	}

	mcfd = open("/dev/mcos0", O_RDONLY);
	if (mcfd < 0) {
		fprintf(stderr, "error: opening IHK OS device file\n");
		exit(1);
	}

	dwarffd = open(kernel_path, O_RDONLY);
	if (dwarffd < 0) {
		fprintf(stderr, "error: opening %s\n", kernel_path);
		exit(1);
	}

	rc = dwarf_init(dwarffd, DW_DLC_READ, errhand, errarg, &dbg, &error);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "error: accessing DWARF information\n");
		exit(1);
	}

	init_globals(dbg);

	if (ps)
		mcps(dbg);

	if (vtop) {
		mcvtop(dbg, pid, vtop_addr);
	}

	dwarf_finish(dbg, &error);
	close(dwarffd);
	close(mcfd);
	return 0;
}


