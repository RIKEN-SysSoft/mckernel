/*
 * Trivial dwarf parser to extract part of a struct from debug infos
 *
 * Author: Dominique Martinet <dominique.martinet@cea.fr>
 * License: WTFPLv2
 *
 * Canonical source: http://cgit.notk.org/asmadeus/dwarf-extract-struct.git
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include "libdwarf/dwarf.h"
#include "libdwarf/libdwarf.h"


static void parse_dwarf(Dwarf_Debug dbg, const char *struct_name,
		const char *field_names[], int field_count);
static void find_struct(Dwarf_Debug dbg, Dwarf_Die die, const char *struct_name,
		const char *field_names[], int field_count, int level);
static void find_fields(Dwarf_Debug dbg, Dwarf_Die struct_die, Dwarf_Die die,
		const char *struct_name, const char *field_names[],
		int field_count, int level);
static void print_field(Dwarf_Debug dbg, Dwarf_Die die, const char *field_name,
		int pad_num);

int debug = 0;

void usage(const char *argv[]) {
	fprintf(stderr, "%s debug_file struct_name [field [field...]]\n",
		argv[0]);
}

int main(int argc, const char *argv[]) {
	Dwarf_Debug dbg = 0;
	int fd = -1;
	const char *filepath;
	const char *struct_name;
	int res = DW_DLV_ERROR;
	Dwarf_Error error;
	Dwarf_Handler errhand = 0;
	Dwarf_Ptr errarg = 0;

	if(argc < 3) {
		usage(argv);
		exit(1);
	}

	filepath = argv[1];
	struct_name = argv[2];

	fd = open(filepath,O_RDONLY);
	if(fd < 0) {
		fprintf(stderr, "Failure attempting to open %s\n",filepath);
	}
	res = dwarf_init(fd, DW_DLC_READ, errhand, errarg, &dbg, &error);
	if(res != DW_DLV_OK) {
		fprintf(stderr, "Giving up, cannot do DWARF processing\n");
		exit(1);
	}

	parse_dwarf(dbg, struct_name, argv + 3, argc - 3);

	res = dwarf_finish(dbg,&error);
	if(res != DW_DLV_OK) {
		fprintf(stderr, "dwarf_finish failed!\n");
	}
	close(fd);
	return 0;
}

static void parse_dwarf(Dwarf_Debug dbg, const char *struct_name,
		const char *field_names[], int field_count) {
	Dwarf_Bool is_info = 1;
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
	int rc;


	/* Iterate compile and type units */
	for (is_info = 0; is_info < 2; ++is_info) {
		rc = dwarf_next_cu_header_c(dbg, is_info, &cu_length,
				&cu_version, &cu_abbrev_offset, &cu_pointer_size,
				&cu_offset_size, &cu_extension_size, &type_signature,
				&type_offset, &cu_next_offset, &err);

		while (rc != DW_DLV_NO_ENTRY) {
			Dwarf_Die die;

			if (rc != DW_DLV_OK) {
				fprintf(stderr, "error dwarf_next_cu_header_c: %d %s\n",
						rc, dwarf_errmsg(err));
				exit(1);
			}

			rc = dwarf_siblingof(dbg, NULL, &die, &err);
			if (rc != DW_DLV_OK) {
				fprintf(stderr, "first dwarf_siblingof failed: %d %s\n",
						rc, dwarf_errmsg(err));
				exit(1);
			}

			find_struct(dbg, die, struct_name, field_names, field_count, 0);

			rc = dwarf_next_cu_header_c(dbg, is_info, &cu_length,
					&cu_version, &cu_abbrev_offset, &cu_pointer_size,
					&cu_offset_size, &cu_extension_size, &type_signature,
					&type_offset, &cu_next_offset, &err);
		}
	}

	fprintf(stderr, "struct %s not found\n", struct_name);
	exit(2);
}

static void find_struct(Dwarf_Debug dbg, Dwarf_Die die, const char *struct_name,
		const char *field_names[], int field_count, int level) {
	Dwarf_Die next;
	Dwarf_Error err;
	int rc;

	if (level > 1)
		return;

	do {
		char *name;
		const char *tag_name;
		Dwarf_Half tag;

		rc = dwarf_diename(die, &name, &err);
		if (rc == DW_DLV_NO_ENTRY) {
			name = NULL;
		} else if (rc != DW_DLV_OK) {
			fprintf(stderr, "dwarf_diename error: %d %s\n",
				rc, dwarf_errmsg(err));
			exit(1);
		}

		if (debug) {
			printf("diename: %s\n", name);
		}

		rc = dwarf_tag(die, &tag, &err);
		if (rc != DW_DLV_OK) {
			fprintf(stderr, "dwarf_tag error: %d %s\n",
				rc, dwarf_errmsg(err));
			exit(1);
		}

		if (debug) {
			rc = dwarf_get_TAG_name(tag, &tag_name);
			if (rc != DW_DLV_OK) {
				fprintf(stderr,
					"dwarf_get_TAG_name error: %d\n", rc);
				exit(1);
			}

			printf("<%d> %p <%d> %s: %s\n", level, die, tag,
			       tag_name, name ? name : "<no name>");
		}

		rc = dwarf_child(die, &next, &err);
		if (rc == DW_DLV_ERROR) {
			fprintf(stderr, "dwarf_child error: %d %s\n",
				rc, dwarf_errmsg(err));
			exit(1);
		}
		if (rc == DW_DLV_OK) {
			if (tag == DW_TAG_structure_type
				&& name && strcasecmp(name, struct_name) == 0) {
				find_fields(dbg, die, next, struct_name,
					    field_names, field_count,
					    level + 1);
				fprintf(stderr,
					"Found struct %s but it did not have all members given!\nMissing:\n",
					struct_name);
				for (rc = 0; rc < field_count; rc++) {
					if (field_names[rc])
						fprintf(stderr, "%s\n",
							field_names[rc]);
				}
				exit(3);
			}
			find_struct(dbg, next, struct_name, field_names,
				    field_count, level + 1);
			dwarf_dealloc(dbg, next, DW_DLA_DIE);
		}


		rc = dwarf_siblingof(dbg, die, &next, &err);
		dwarf_dealloc(dbg, die, DW_DLA_DIE);
		if (name)
			dwarf_dealloc(dbg, name, DW_DLA_STRING);

		if (rc != DW_DLV_OK)
			break;

		die = next;
	} while (die);
}

static int dwarf_get_offset(Dwarf_Debug dbg, Dwarf_Die die,
		int *poffset, Dwarf_Error *perr) {
	Dwarf_Attribute attr;
	Dwarf_Unsigned offset;
	int rc;

	rc = dwarf_attr(die, DW_AT_data_member_location, &attr, perr);
	if (rc != DW_DLV_OK) {
		return rc;
	}
	Dwarf_Half form;
	rc = dwarf_whatform(attr, &form, perr);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "Error getting whatform: %s\n",
			dwarf_errmsg(*perr));
		exit(5);
	}
	if (form == DW_FORM_data1 || form == DW_FORM_data2
		|| form == DW_FORM_data2 || form == DW_FORM_data4
		|| form == DW_FORM_data8 || form == DW_FORM_udata) {
		dwarf_formudata(attr, &offset, 0);
	} else if (form == DW_FORM_sdata) {
		Dwarf_Signed soffset;
		dwarf_formsdata(attr, &soffset, 0);
		if (soffset < 0) {
			fprintf(stderr,
				"unsupported negative offset\n");
			exit(5);
		}
		offset = (Dwarf_Unsigned) soffset;
	} else {
		Dwarf_Locdesc **locdescs;
		Dwarf_Signed len;
		if (dwarf_loclist_n(attr, &locdescs, &len,  perr)
				== DW_DLV_ERROR) {
			 fprintf(stderr, "unsupported member offset\n");
			 exit(5);
		}
		if (len != 1
		    || locdescs[0]->ld_cents != 1
		    || (locdescs[0]->ld_s[0]).lr_atom
				!= DW_OP_plus_uconst) {
			 fprintf(stderr,
				"unsupported location expression\n");
			 exit(5);
		}
		offset = (locdescs[0]->ld_s[0]).lr_number;
	}
	dwarf_dealloc(dbg, attr, DW_DLA_ATTR);

	*poffset = (int) offset;
	return DW_DLV_OK;
}

static int dwarf_get_size(Dwarf_Debug dbg, Dwarf_Die die,
		int *psize, Dwarf_Error *perr) {
	Dwarf_Attribute attr;
	Dwarf_Unsigned size;
	int rc;

	rc = dwarf_attr(die, DW_AT_byte_size, &attr, perr);
	if (rc != DW_DLV_OK) {
		return rc;
	}
	Dwarf_Half form;
	rc = dwarf_whatform(attr, &form, perr);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "Error getting whatform: %s\n",
			dwarf_errmsg(*perr));
		exit(5);
	}
	if (form == DW_FORM_data1 || form == DW_FORM_data2
		|| form == DW_FORM_data2 || form == DW_FORM_data4
		|| form == DW_FORM_data8 || form == DW_FORM_udata) {
		dwarf_formudata(attr, &size, 0);
	} else if (form == DW_FORM_sdata) {
		Dwarf_Signed ssize;
		dwarf_formsdata(attr, &ssize, 0);
		if (ssize < 0) {
			fprintf(stderr,
				"unsupported negative size\n");
			exit(5);
		}
		size = (Dwarf_Unsigned) ssize;
	} else {
		Dwarf_Locdesc **locdescs;
		Dwarf_Signed len;
		if (dwarf_loclist_n(attr, &locdescs, &len,  perr)
				== DW_DLV_ERROR) {
			 fprintf(stderr, "unsupported member size\n");
			 exit(5);
		}
		if (len != 1
		    || locdescs[0]->ld_cents != 1
		    || (locdescs[0]->ld_s[0]).lr_atom
				!= DW_OP_plus_uconst) {
			 fprintf(stderr,
				"unsupported location expression\n");
			 exit(5);
		}
		size = (locdescs[0]->ld_s[0]).lr_number;
	}
	dwarf_dealloc(dbg, attr, DW_DLA_ATTR);

	*psize = (int) size;
	return DW_DLV_OK;
}

static int dwarf_get_arraysize(Dwarf_Debug dbg, Dwarf_Die die,
		int *psize, Dwarf_Error *perr) {
	Dwarf_Attribute attr;
	Dwarf_Unsigned lower_bound, upper_bound;
	int rc;
	Dwarf_Die child;
	Dwarf_Half form;

	rc = dwarf_child(die, &child, perr);
	if (rc == DW_DLV_NO_ENTRY) {
		fprintf(stderr,
				"Could not deref child of array: no entry\n");
		return rc;
	}
	if (rc != DW_DLV_OK) {
		fprintf(stderr,
				"Could not get child entry of array: %s\n",
				dwarf_errmsg(*perr));
		return rc;
	}

	rc = dwarf_attr(child, DW_AT_lower_bound, &attr, perr);
	/* Not present? Assume zero */
	if (rc != DW_DLV_OK) {
		lower_bound = 0;
		goto upper;
	}

	rc = dwarf_whatform(attr, &form, perr);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "Error getting whatform: %s\n",
				dwarf_errmsg(*perr));
		exit(5);
	}

	if (form == DW_FORM_data1 || form == DW_FORM_data2
		|| form == DW_FORM_data2 || form == DW_FORM_data4
		|| form == DW_FORM_data8 || form == DW_FORM_udata) {
		dwarf_formudata(attr, &lower_bound, 0);
	} else if (form == DW_FORM_sdata) {
		Dwarf_Signed ssize;
		dwarf_formsdata(attr, &ssize, 0);
		if (ssize < 0) {
			fprintf(stderr,
				"unsupported negative size\n");
			exit(5);
		}
		lower_bound = (Dwarf_Unsigned) ssize;
	} else {
		Dwarf_Locdesc **locdescs;
		Dwarf_Signed len;
		if (dwarf_loclist_n(attr, &locdescs, &len,  perr)
				== DW_DLV_ERROR) {
			 fprintf(stderr, "unsupported member size\n");
			 exit(5);
		}
		if (len != 1
		    || locdescs[0]->ld_cents != 1
		    || (locdescs[0]->ld_s[0]).lr_atom
				!= DW_OP_plus_uconst) {
			 fprintf(stderr,
				"unsupported location expression\n");
			 exit(5);
		}
		lower_bound = (locdescs[0]->ld_s[0]).lr_number;
	}
	dwarf_dealloc(dbg, attr, DW_DLA_ATTR);

upper:
	rc = dwarf_attr(child, DW_AT_upper_bound, &attr, perr);
	if (rc != DW_DLV_OK) {
		return rc;
	}

	rc = dwarf_whatform(attr, &form, perr);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "Error getting whatform: %s\n",
			dwarf_errmsg(*perr));
		exit(5);
	}

	if (form == DW_FORM_data1 || form == DW_FORM_data2
		|| form == DW_FORM_data2 || form == DW_FORM_data4
		|| form == DW_FORM_data8 || form == DW_FORM_udata) {
		dwarf_formudata(attr, &upper_bound, 0);
	} else if (form == DW_FORM_sdata) {
		Dwarf_Signed ssize;
		dwarf_formsdata(attr, &ssize, 0);
		if (ssize < 0) {
			fprintf(stderr,
				"unsupported negative size\n");
			exit(5);
		}
		upper_bound = (Dwarf_Unsigned) ssize;
	} else {
		Dwarf_Locdesc **locdescs;
		Dwarf_Signed len;
		if (dwarf_loclist_n(attr, &locdescs, &len,  perr)
				== DW_DLV_ERROR) {
			 fprintf(stderr, "unsupported member size\n");
			 exit(5);
		}
		if (len != 1
		    || locdescs[0]->ld_cents != 1
		    || (locdescs[0]->ld_s[0]).lr_atom
				!= DW_OP_plus_uconst) {
			 fprintf(stderr,
				"unsupported location expression\n");
			 exit(5);
		}
		upper_bound = (locdescs[0]->ld_s[0]).lr_number;
	}
	dwarf_dealloc(dbg, attr, DW_DLA_ATTR);

	*psize = ((int)upper_bound - (int)lower_bound + 1);
	return DW_DLV_OK;
}



static int deref_type(Dwarf_Debug dbg, Dwarf_Die type_die,
		Dwarf_Die *new_type_die, Dwarf_Half *ptype_tag,
		Dwarf_Error *perr) {
	Dwarf_Attribute pointer_attr;
	Dwarf_Off pointer_off;
	int rc;

	rc = dwarf_attr(type_die, DW_AT_type, &pointer_attr,
			perr);
	if (rc != DW_DLV_OK)
		return rc;

	rc = dwarf_global_formref(pointer_attr, &pointer_off,
				  perr);
	if (rc != DW_DLV_OK)
		return rc;

	rc = dwarf_offdie_b(dbg, pointer_off, 1, new_type_die,
			    perr);
	if (rc != DW_DLV_OK)
		return rc;

	dwarf_dealloc(dbg, pointer_attr, DW_DLA_ATTR);

	if (ptype_tag)
		rc = dwarf_tag(*new_type_die, ptype_tag, perr);

	return rc;
}

static void find_fields(Dwarf_Debug dbg, Dwarf_Die struct_die, Dwarf_Die die,
		const char *struct_name, const char *field_names[],
		int field_count, int level) {
	Dwarf_Die next;
	Dwarf_Error err;
	int rc, i, printed_count = 0;
	int size;

	printf("struct %s {\n\tunion {\n",
		struct_name);

	rc =  dwarf_get_size(dbg, struct_die, &size, &err);
	if (rc != DW_DLV_OK) {
		fprintf(stderr, "could not get size for struct %s: %s\n",
			struct_name, dwarf_errmsg(err));
		exit(1);
	}
	printf("\t\tchar whole_struct[%d];\n", size);

	do {
		char *name;
		const char *tag_name;
		Dwarf_Half tag;

		rc = dwarf_diename(die, &name, &err);
		if (rc == DW_DLV_NO_ENTRY) {
			name = NULL;
		} else if (rc != DW_DLV_OK) {
			fprintf(stderr, "dwarf_diename error: %d %s\n",
				rc, dwarf_errmsg(err));
			exit(1);
		}

		rc = dwarf_tag(die, &tag, &err);
		if (rc != DW_DLV_OK) {
			fprintf(stderr, "dwarf_tag error: %d %s\n",
				rc, dwarf_errmsg(err));
			exit(1);
		}

		if (debug) {
			rc = dwarf_get_TAG_name(tag, &tag_name);
			if (rc != DW_DLV_OK) {
				fprintf(stderr,
					"dwarf_get_TAG_name error: %d\n", rc);
				exit(1);
			}

			printf("<%d> %p <%d> %s: %s\n", level, die, tag,
			       tag_name, name ? name : "<no name>");
		}

		if (tag == DW_TAG_member && name) {
			for (i = 0; i < field_count; i++) {
				if (!field_names[i])
					continue;
				if (strcasecmp(name, field_names[i]) == 0) {
					print_field(dbg, die, field_names[i],
						printed_count);
					field_names[i] = NULL;
					printed_count++;
					break;
				}
			}
			if (printed_count == field_count) {
				printf("\t};\n};\n");
				exit(0);
			}
		}

		rc = dwarf_siblingof(dbg, die, &next, &err);
		dwarf_dealloc(dbg, die, DW_DLA_DIE);
		if (name)
			dwarf_dealloc(dbg, name, DW_DLA_STRING);

		if (rc != DW_DLV_OK)
			break;

		die = next;
	} while (die);
}

static void print_field(Dwarf_Debug dbg, Dwarf_Die die, const char *field_name,
		int padnum) {
	Dwarf_Attribute attr;
	Dwarf_Error err;
	int offset = 0;
	char type_buf[1024];
	char array_buf[128] = "";
	char pointer_buf[128] = "";
	int rc;

	rc = dwarf_get_offset(dbg, die, &offset, &err);
	if (rc == DW_DLV_NO_ENTRY) {
		fprintf(stderr, "Found %s but no offset, assuming 0\n",
			field_name);
	} else if (rc != DW_DLV_OK) {
		fprintf(stderr, "Error getting dwarf attr offset: %s\n",
			dwarf_errmsg(err));
		exit(4);
	}

	rc = dwarf_attr(die, DW_AT_type, &attr, &err);
	if (rc == DW_DLV_NO_ENTRY) {
		fprintf(stderr,
			"Found %s but no type, can't assume that one out..\n",
			field_name);
		exit(6);
	} else if (rc != DW_DLV_OK) {
		fprintf(stderr, "Error getting dwarf attrlist: %s\n",
			dwarf_errmsg(err));
		exit(6);
	} else {
		Dwarf_Die type_die, next;
		Dwarf_Off type_off;
		Dwarf_Half type_tag;
		char *type_name;
		int pointer = 0;
		int embeded_struct = 0;

		rc = dwarf_global_formref(attr, &type_off, &err);
		if (rc != DW_DLV_OK) {
			fprintf(stderr,
				"Error getting ref offset for type: %s\n",
				dwarf_errmsg(err));
			exit(7);
		}

		rc = dwarf_offdie_b(dbg, type_off, 1, &type_die, &err);
		if (rc != DW_DLV_OK) {
			fprintf(stderr,
				"Error getting die from offset for type: %s\n",
				dwarf_errmsg(err));
			exit(7);
		}

		rc = dwarf_tag(type_die, &type_tag, &err);
		if (rc != DW_DLV_OK) {
			fprintf(stderr, "dwarf_tag error: %d %s\n",
				rc, dwarf_errmsg(err));
			exit(7);
		}

		while (type_tag == DW_TAG_pointer_type) {
			pointer_buf[pointer++] = '*';

			rc = deref_type(dbg, type_die, &next,
					&type_tag, &err);
			/* No entry here means void* */
			if (rc == DW_DLV_NO_ENTRY)
				break;

			if (rc != DW_DLV_OK) {
				fprintf(stderr,
					"Could not deref type for %s: %s\n",
					field_name, dwarf_errmsg(err));
				exit(7);
			}

			dwarf_dealloc(dbg, type_die, DW_DLA_DIE);
			type_die = next;
		}

		if (type_tag == DW_TAG_array_type) {
			int next_offset, size;

			rc = deref_type(dbg, type_die, &next,
					&type_tag, &err);
			if (rc == DW_DLV_NO_ENTRY) {
				fprintf(stderr,
					"Could not deref array type for %s: no entry\n",
					field_name);
				exit(7);
			}
			if (rc != DW_DLV_OK) {
				fprintf(stderr,
					"Could not deref type for %s: %s\n",
					field_name, dwarf_errmsg(err));
				exit(7);
			}

			rc = dwarf_get_arraysize(dbg, type_die, &size, &err);
			if (rc != DW_DLV_OK) {
				fprintf(stderr,
					"Could not get array size for %s: %s\n",
					field_name, dwarf_errmsg(err));
				exit(7);
			}
			type_die = next;

			snprintf(array_buf, 128, "[%d]", size);
		}

		/* If it's still pointer at this point, it's void * */
		if (type_tag != DW_TAG_pointer_type) {
			rc = dwarf_diename(type_die, &type_name, &err);
			if (rc != DW_DLV_OK) {
#if 0
				fprintf(stderr, "dwarf_diename error: %s\n",
					rc == DW_DLV_NO_ENTRY ?
						"no name" : dwarf_errmsg(err));
				const char *tag_name;

				rc = dwarf_get_TAG_name(type_tag, &tag_name);
				if (rc != DW_DLV_OK) {
					fprintf(stderr,
						"dwarf_get_TAG_name error: %d\n",
						rc);
				}

				fprintf(stderr, "Bad tag %s (%d)?\n",
					tag_name, type_tag);
				exit(7);
#endif
				if (rc == DW_DLV_NO_ENTRY) {
					embeded_struct = 1;
				}
			}
		}

		if (type_tag == DW_TAG_structure_type) {
			snprintf(type_buf, 1024, "struct %s %s",
				 embeded_struct ? "FILL_IN_MANUALLY" : type_name, pointer_buf);
		} else if (type_tag == DW_TAG_enumeration_type) {
			snprintf(type_buf, 1024, "enum %s %s",
				 type_name, pointer_buf);
		} else if (type_tag == DW_TAG_base_type
				|| type_tag == DW_TAG_typedef) {
			snprintf(type_buf, 1024, "%s %s", type_name,
				pointer_buf);
		} else if (type_tag == DW_TAG_pointer_type) {
			snprintf(type_buf, 1024, "void %s", pointer_buf);
		} else {
			const char *tag_name;

			rc = dwarf_get_TAG_name(type_tag, &tag_name);
			if (rc != DW_DLV_OK) {
				fprintf(stderr,
					"dwarf_get_TAG_name error: %d\n", rc);
			}

			fprintf(stderr,
				"Type tag %s (%d) is not implemented, please add it\n",
				tag_name, type_tag);
			exit(7);
		}

		if (type_tag != DW_TAG_pointer_type)
			dwarf_dealloc(dbg, type_name, DW_DLA_STRING);
		dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
		dwarf_dealloc(dbg, type_die, DW_DLA_DIE);
	}

	printf("\t\tstruct {\n\t\t\tchar padding%i[%u];\n\t\t\t%s%s%s;\n\t\t};\n",
		padnum, (unsigned int) offset,
		type_buf, field_name, array_buf);
}
