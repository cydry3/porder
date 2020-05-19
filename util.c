#include "porder.h"

void retry_interval_nano()
{
	static struct timespec interval = {
		.tv_sec = 0,
		.tv_nsec = 1,
	};
	nanosleep(&interval, NULL);
}
