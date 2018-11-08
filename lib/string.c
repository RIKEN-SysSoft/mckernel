/**
 * \file page_alloc.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Manipulate strings.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#include <kmalloc.h>
#include <string.h>
#include <memory.h>
#include <arch-string.h>

size_t strlen(const char *p)
{
	const char *head = p;

	while(*p){
		p++;
	}
	
	return p - head;
}

size_t strnlen(const char *p, size_t maxlen)
{
	const char *head = p;

	while(*p && maxlen > 0){
		p++;
		maxlen--;
	}
	
	return p - head;
}

char *strcpy(char *dest, const char *src)
{
	char *head = dest;

	while((*(dest++) = *(src++)));

	return head;
}

char *strncpy(char *dest, const char *src, size_t maxlen)
{
	char *head = dest;
	ssize_t len = maxlen;

	if(len <= 0)
		return head;
	while((*(dest++) = *(src++)) && --len);
	if(len > 0){
		while(--len){
			*(dest++) = '\0';
		}
	}

	return head;
}

int strcmp(const char *s1, const char *s2)
{
	while(*s1 && *s1 == *s2){
		s1++;
		s2++;
	}

	return *s1 - *s2;
}

int strncmp(const char *s1, const char *s2, size_t n)
{
	while(*s1 && *s1 == *s2 && n > 1){
		s1++;
		s2++;
		n--;
	}
	return *s1 - *s2;
}

char *strchr(const char *s, int n) {
	char *p = (char *)s; 
	while (1) {
		if (*p == n)
		{
			return p;
		} else if (*p == '\0') {
			break;
		}
		++p;
	}
	return NULL;
}

char *
strrchr(const char *s, int c)
{
	const char *last = NULL;

	do {
		if (*s == c) {
			last = s;
		}
	} while (*(s++));

	return (char *)last;
} /* strrchr() */

char *strpbrk(const char *s, const char *accept)
{
	const char *a;

	do {
		for (a = accept; *a; a++)
			if (*s == *a)
				return (char *)s;
	} while (*(s++));

	return NULL;
}

char *strstr(const char *haystack, const char *needle)
{
	int len = strlen(needle);

	while(*haystack){
		if(!strncmp(haystack, needle, len)){
			return (char *)haystack;
		}
		haystack++;
	}
	return NULL;
}

void *memcpy(void *dest, const void *src, size_t n)
{
	const char *p1 = src;
	char *p2 = dest;

	while(n > 0){
		*p2 = *p1;
		p1++;
		p2++;
		n--;
	}

	return dest;
}

void *memcpy_long(void *dest, const void *src, size_t n)
{
	const unsigned long *p1 = src;
	unsigned long *p2 = dest;

	n /= sizeof(unsigned long);
	while (n > 0) {
		*(p2++) = *(p1++);
		n--;
	}

	return dest;
}

#ifndef ARCH_FAST_MEMSET
void *memset(void *s, int c, size_t n)
{
	char *s_aligned = (void *)(((unsigned long)s + 7) & ~7);
	char *e_aligned = (void *)(((unsigned long)s + n) & ~7);
	char *e = ((char *)s + n);
	char *p;
	unsigned long *l;
#define C ((unsigned long)(c & 0xff))
	unsigned long pat = C | C << 8 | C << 16 | C << 24 | C << 32 |
		C << 40 | C << 48 | C << 56;
#undef C

	if(s_aligned < e_aligned){
		p = s;
		while(p < s_aligned){
			*(p++) = (char)c;
		}
		l = (unsigned long *)s_aligned;
		while((char *)l < e_aligned){
			*(l++) = pat;
		}
		p = e_aligned;
		while(p < e){
			*(p++) = (char)c;
		}
	}else{
		p = s;
		while(p < e){
			*(p++) = (char)c;
		}
	}

	return s;
}
#endif

int memcmp(const void *s1, const void *s2, size_t n)
{
	const char *p1 = s1;
	const char *p2 = s2;

	while(*p1 == *p2 && n > 1){
		p1++;
		p2++;
		n--;
	}
	return *p1 - *p2;
}

/* 
 * Flatten out a (char **) string array into the following format:
 * [nr_strings][char *offset of string_0]...[char *offset of string_n-1][char *offset of end of string][string0]...[stringn_1]
 *
 * sizes all are longs.
 *
 * NOTE: copy this string somewhere, add the address of the string to each offset
 * and we get back a valid argv or envp array.
 *
 * pre_strings is already flattened, so we just need to manage counts and copy
 * the string parts appropriately.
 *
 * returns the total length of the flat string and updates flat to
 * point to the beginning.
 */
int flatten_strings_from_user(char *pre_strings, char **strings, char **flat)
{
	int full_len, i;
	int nr_strings = 0;
	int pre_strings_count = 0;
	int pre_strings_len = 0;
	long *_flat;
	long *pre_strings_flat;
	char *p;
	long r;
	int ret;

	/* When strings is NULL, make array one NULL */
	if (!strings) {
		full_len = sizeof(long) + sizeof(char *);
		_flat = kmalloc(full_len, IHK_MC_AP_NOWAIT);
		if (!_flat) {
			return -ENOMEM;
		}
		memset(_flat, 0, full_len);
		*flat = (char *)_flat;
		return full_len;
	}

	/* How many strings do we have? */
	for (;;) {
		ret = getlong_user(&r, (void *)(strings + nr_strings));
		if (ret < 0)
			return ret;

		if (r == 0)
			break;

		++nr_strings;
	}

	/* Count full length */
	full_len = sizeof(long) + sizeof(char *); // Counter and terminating NULL
	if (pre_strings) {
		pre_strings_flat = (long *)pre_strings;
		pre_strings_count = pre_strings_flat[0];

		pre_strings_len = pre_strings_flat[pre_strings_count + 1];
		pre_strings_len -= sizeof(long) * (pre_strings_count + 2);

		full_len += pre_strings_count * sizeof(long) + pre_strings_len;
	}

	for (i = 0; i < nr_strings; ++i) {
		char *userp;
		int len;

		ret = getlong_user((long *)&userp, (void *)(strings + i));
		if (ret < 0)
			return ret;

		len = strlen_user(userp);

		if(len < 0)
			return len;
		// Pointer + actual value
		full_len += sizeof(char *) + len + 1;
	}

	full_len = (full_len + sizeof(long) - 1) & ~(sizeof(long) - 1);

	_flat = kmalloc(full_len, IHK_MC_AP_NOWAIT);
	if (!_flat) {
		return -ENOMEM;
	}

	/* Number of strings */
	_flat[0] = nr_strings + pre_strings_count;

	// Actual offset
	p = (char *)(_flat + nr_strings + pre_strings_count + 2);

	if (pre_strings) {
		for (i = 0; i < pre_strings_count; i++) {
			_flat[i + 1] = pre_strings_flat[i + 1] +
					nr_strings * sizeof(long);
		}
		memcpy(p, pre_strings + pre_strings_flat[1],
		       pre_strings_len);
		p += pre_strings_len;
	}

	for (i = 0; i < nr_strings; ++i) {
		char *userp;
		_flat[i + pre_strings_count + 1] = p - (char *)_flat;

		ret = getlong_user((long *)&userp, (void *)(strings + i));
		if (ret < 0)
			return ret;

		strcpy_from_user(p, userp);
		p = strchr(p, '\0') + 1;
	}
	_flat[nr_strings + pre_strings_count + 1] = p - (char *)_flat;

	*flat = (char *)_flat;
	return p - (char *)_flat;
}
