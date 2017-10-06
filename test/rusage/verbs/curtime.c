#include <stdio.h>
#include <sys/time.h>

#define CURTIME_LIB 1

double cur_time(){
	struct timeval tp;
	gettimeofday(&tp, NULL);
	return tp.tv_sec + tp.tv_usec * 1.0E-6;
}

