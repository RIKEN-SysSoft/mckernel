/**
 * \file kmsg.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Functions of output to McKernel message
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#ifndef KMSG_H
#define KMSG_H

void kmsg_init(void);
void kputs(char *buf);
int kprintf(const char *format, ...);

#endif
