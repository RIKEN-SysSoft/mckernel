/*
 * UBSAN handlers
 * Types shamelessly copied over from linux
 */

#include <string.h>
#include <lwk/stddef.h>
#include <kmsg.h>
#include <kmalloc.h>

enum {
	type_kind_int = 0,
	type_kind_float = 1,
	type_unknown = 0xffff
};

struct type_descriptor {
	short type_kind;
	short type_info;
	char type_name[1];
};

struct source_location {
	const char *file_name;
	union {
		unsigned long reported;
		struct {
			int line;
			int column;
		};
	};
};

struct type_mismatch_data_v1 {
	struct source_location location;
	struct type_descriptor *type;
	unsigned char log_alignment;
	unsigned char type_check_kind;
};

struct type_mismatch_data {
	struct source_location location;
	struct type_descriptor *type;
	unsigned long alignment;
	unsigned char type_check_kind;
};

struct overflow_data {
	struct source_location location;
	struct type_descriptor *type;
};

struct nonnull_arg_data {
	struct source_location location;
	struct source_location attr_location;
	int arg_index;
};

struct vla_bound_data {
	struct source_location location;
	struct type_descriptor *type;
};

struct out_of_bounds_data {
	struct source_location location;
	struct type_descriptor *array_type;
	struct type_descriptor *index_type;
};

struct shift_out_of_bounds_data {
	struct source_location location;
	struct type_descriptor *lhs_type;
	struct type_descriptor *rhs_type;
};

struct unreachable_data {
	struct source_location location;
};

struct invalid_value_data {
	struct source_location location;
	struct type_descriptor *type;
};

struct pointer_overflow_data {
	struct source_location location;
};


const char *type_check_kinds[] = {
	"load of",
	"store to",
	"reference binding to",
	"member access within",
	"member call on",
	"constructor call on",
	"downcast of",
	"downcast of"
};

#define REPORTED_BIT 31

#define COLUMN_MASK (~(1U << REPORTED_BIT))
#define LINE_MASK   (~0U)

#define VALUE_LENGTH 40



void ubsan_prologue(struct source_location *loc)
{
	kprintf("UBSAN: Undefined behaviour in %s:%d:%d\n", loc->file_name,
		loc->line & LINE_MASK, loc->column & COLUMN_MASK);
}


void __ubsan_handle_type_mismatch(struct type_mismatch_data *data,
				  unsigned long ptr)
{
	ubsan_prologue(&data->location);
	if (!ptr) {
		kprintf("%s: null pointer deref\n", __func__);
	} else if (data->alignment && !IS_ALIGNED(ptr, data->alignment)) {
		kprintf("%s: pointer %#16lx of type %s is not aligned at %#lx\n",
			__func__, ptr, data->type->type_name, data->alignment);
	} else {
		kprintf("%s: %s address %#16lx with insufficient space for an object of type %s\n",
			__func__, type_check_kinds[data->type_check_kind], ptr,
			data->type->type_name);
	}
}

void __ubsan_handle_type_mismatch_v1(struct type_mismatch_data_v1 *data_v1,
				  unsigned long ptr)
{
	struct type_mismatch_data data = {
		.location = data_v1->location,
		.type = data_v1->type,
		.alignment = 1UL << data_v1->log_alignment,
		.type_check_kind = data_v1->type_check_kind,
	};
	__ubsan_handle_type_mismatch(&data, ptr);
}

void __ubsan_handle_pointer_overflow(struct pointer_overflow_data *data,
				     unsigned long base, unsigned long result)
{
	ubsan_prologue(&data->location);
	kprintf("%s: pointer overflow from %lx to %lx\n",
		__func__, base, result);
}

void __ubsan_handle_add_overflow(struct overflow_data *data,
				unsigned long lhs,
				unsigned long rhs)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %lx %lx\n", __func__, lhs, rhs);

}
void __ubsan_handle_sub_overflow(struct overflow_data *data,
				unsigned long lhs,
				unsigned long rhs)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %lx %lx\n", __func__, lhs, rhs);
}

void __ubsan_handle_mul_overflow(struct overflow_data *data,
				unsigned long lhs,
				unsigned long rhs)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %lx %lx\n", __func__, lhs, rhs);
}

void __ubsan_handle_negate_overflow(struct overflow_data *data,
				unsigned long old_val)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %lx\n", __func__, old_val);
}

void __ubsan_handle_divrem_overflow(struct overflow_data *data,
				unsigned long lhs,
				unsigned long rhs)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %lx %lx\n", __func__, lhs, rhs);
}

void __ubsan_handle_vla_bound_not_positive(struct vla_bound_data *data,
					   unsigned long bound)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %lx\n", __func__, bound);
}

void __ubsan_handle_out_of_bounds(struct out_of_bounds_data *data,
				unsigned long index)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %lx\n", __func__, index);
}

void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *data,
					unsigned long lhs, unsigned long rhs)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %lx %lx\n", __func__, lhs, rhs);
}

void __ubsan_handle_builtin_unreachable(struct unreachable_data *data)
{
	ubsan_prologue(&data->location);
	kprintf("%s\n", __func__);
	panic(__func__);
}

void __ubsan_handle_load_invalid_value(struct invalid_value_data *data,
				unsigned long val)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %lx\n", __func__, val);
}

