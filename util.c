#include "porder.h"

void retry_interval_nano(void)
{
	static struct timespec interval = {
		.tv_sec = 0,
		.tv_nsec = 1,
	};
	nanosleep(&interval, NULL);
}

char *get_bin_dir(void)
{
	static char fullpath[MAX_PORDER_PATHLEN];
	int length;

	length = readlink("/proc/self/exe", fullpath, sizeof(fullpath));
	if (length < 0) {
		fprintf(stderr, "failed in resolving path");
		exit(EXIT_FAILURE);
	}
	if (length >= MAX_PORDER_PATHLEN) {
		fprintf(stderr, "failed in resolve path, path is too long");
		exit(EXIT_FAILURE);
	}

	fullpath[length-PORDER_NAMELEN] = '\0';

	return fullpath;
}

char *bin_rootpath_with(const char *filename)
{
	char *fullpath = get_bin_dir();
	if ((strlen(fullpath) + strlen(filename)) > MAX_PORDER_PATHLEN) {
		fprintf(stderr, "failed in checking path, path is too long");
		exit(EXIT_FAILURE);
	}

	strcat(fullpath, filename);

	return fullpath;
}
