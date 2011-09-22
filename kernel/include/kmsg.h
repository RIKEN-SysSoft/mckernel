#ifndef KMSG_H
#define KMSG_H

void kputs(char *buf);
int kprintf(const char *format, ...);

void kmsg_init(void);

#endif
