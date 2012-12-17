#ifndef __STRING_H
#define __STRING_H

#include <types.h>

size_t strlen(const char *p);
size_t strnlen(const char *p, size_t maxlen);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t maxlen);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t n);
char *strstr(const char *haystack, const char *needle);
void *memcpy(void *dest, const void *src, size_t n);
void *memcpy_long(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memset(void *s, int n, size_t l);

unsigned long strtol(const char *cp, char **endp, unsigned int base);

#endif
