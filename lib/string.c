#include <string.h>

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

	while((*(dest++) = *(src++)) && --len);
	if(len > 0){
		while(len--){
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
