/**
 * \file string.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare string manipulation functions.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __STRING_H
#define __STRING_H

#include <types.h>
#include <arch-string.h>

size_t strlen(const char *p);
size_t strnlen(const char *p, size_t maxlen);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t maxlen);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strstr(const char *haystack, const char *needle);
char *strchr(const char *s, int n);
char *strrchr(const char *s, int n);
void *memcpy(void *dest, const void *src, size_t n);
void *memcpy_long(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memset(void *s, int n, size_t l);

#ifdef ARCH_FAST_MEMCPY
#define fast_memcpy	__inline_memcpy
#else
#define fast_memcpy memcpy
#endif

#ifdef ARCH_FAST_MEMSET
#define memset __inline_memset
#endif

extern int snprintf(char * buf, size_t size, const char *fmt, ...);
extern int sprintf(char * buf, const char *fmt, ...);
extern int sscanf(const char * buf, const char * fmt, ...);
extern int scnprintf(char * buf, size_t size, const char *fmt, ...);

unsigned long strtol(const char *cp, char **endp, unsigned int base);
int flatten_strings(int nr_strings, char *first, char **strings, char **flat);
int flatten_strings_from_user(int nr_strings, char *first, char **strings, char **flat);

#endif
