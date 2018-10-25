#ifndef _ASYNC_PROGRESS_INCLUDED_
#define _ASYNC_PROGRESS_INCLUDED_

enum progress_state {
	PROGRESS_INIT = 0,
	PROGRESS_START,
	PROGRESS_FINALIZE
};

void progress_init();
void progress_start();
void progress_stop(double *time_progress);
void progress_finalize();

#endif
