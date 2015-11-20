/**
 * \file vsprintf.h
 *  License details are found in the file LICENSE.
 * \brief
 *  declare printf() like functions
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY
 */

#ifndef VSPRINTF_H
#define VSPRINTF_H

#include <stdarg.h>
#include <types.h>

extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
extern int snprintf(char *buf, size_t size, const char *fmt, ...);

#endif
