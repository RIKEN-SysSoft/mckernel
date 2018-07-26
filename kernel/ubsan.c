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

// from include/linux/kernel.h
#define IS_ALIGNED(x, a)                (((x) & ((typeof(x))(a) - 1)) == 0)


void ubsan_prologue(struct source_location *loc)
{
	kprintf("UBSAN: Undefined behaviour in %s:%d:%d\n", loc->file_name,
		loc->line & LINE_MASK, loc->column & COLUMN_MASK);
}

static int type_is_int(struct type_descriptor *type)
{
	return type->type_kind == type_kind_int;
}

static int type_is_signed(struct type_descriptor *type)
{
	return  type->type_info & 1;
}

static unsigned type_bit_width(struct type_descriptor *type)
{
	return 1 << (type->type_info >> 1);
}

static int is_inline_int(struct type_descriptor *type)
{
	unsigned inline_bits = sizeof(unsigned long)*8;
	unsigned bits = type_bit_width(type);

	return bits <= inline_bits;
}

static int64_t get_signed_val(struct type_descriptor *type, unsigned long val)
{
	if (is_inline_int(type)) {
		unsigned extra_bits = sizeof(int64_t)*8 - type_bit_width(type);
		return ((int64_t)val) << extra_bits >> extra_bits;
	}

	if (type_bit_width(type) == 64)
		return *(int64_t *)val;

	return *(int64_t *)val;
}

static int val_is_negative(struct type_descriptor *type, unsigned long val)
{
	return type_is_signed(type) && get_signed_val(type, val) < 0;
}

static uint64_t get_unsigned_val(struct type_descriptor *type, unsigned long val)
{
	if (is_inline_int(type))
		return val;

	if (type_bit_width(type) == 64)
		return *(uint64_t *)val;

	return *(uint64_t *)val;
}

static void val_to_string(char *str, size_t size, struct type_descriptor *type,
	unsigned long value)
{
	if (type_is_int(type)) {
		if (type_is_signed(type)) {
			snprintf(str, size, "%lld",
				get_signed_val(type, value));
		} else {
			snprintf(str, size, "%llu",
				get_unsigned_val(type, value));
		}
	}
}

void __ubsan_handle_type_mismatch(struct type_mismatch_data *data,
				  unsigned long ptr)
{
	ubsan_prologue(&data->location);
	kprintf("%s: %s %x of type %s\n", __func__,
		type_check_kinds[data->type_check_kind], ptr,
		data->type->type_name);
	if (!ptr) {
		kprintf("Null pointer\n");
	} else if (data->alignment && !IS_ALIGNED(ptr, data->alignment)) {
		kprintf("Access was not aligned properly, expected %ld byte alignment\n",
			data->alignment);
	} else {
		kprintf("Insufficient space?\n");
	}
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
	struct type_descriptor *rhs_type = data->rhs_type;
	struct type_descriptor *lhs_type = data->lhs_type;
	char rhs_str[VALUE_LENGTH];
	char lhs_str[VALUE_LENGTH];

	ubsan_prologue(&data->location);

	val_to_string(rhs_str, sizeof(rhs_str), rhs_type, rhs);
	val_to_string(lhs_str, sizeof(lhs_str), lhs_type, lhs);

	if (val_is_negative(rhs_type, rhs))
		kprintf("shift exponent %s is negative\n", rhs_str);

	else if (get_unsigned_val(rhs_type, rhs) >=
		type_bit_width(lhs_type))
		kprintf("shift exponent %s is too large for %u-bit type %s\n",
			rhs_str,
			type_bit_width(lhs_type),
			lhs_type->type_name);
	else if (val_is_negative(lhs_type, lhs))
		kprintf("left shift of negative value %s\n",
			lhs_str);
	else
		kprintf("left shift of %s by %s places cannot be"
			" represented in type %s\n",
			lhs_str, rhs_str,
			lhs_type->type_name);

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

