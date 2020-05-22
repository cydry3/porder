#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define SIZE 64 
#define IOVLEN 2

int main() {
	char *file = "./test_readv.c";
	char buf_f[SIZE];
	char buf_s[SIZE];
	struct iovec v[2];

	v[0].iov_base = buf_f;
	v[0].iov_len = SIZE;

	v[1].iov_base = buf_s;
	v[1].iov_len = SIZE;

	int f = open(file, O_RDONLY);
	if (f == -1) {
		fprintf(stderr, "failed open file.\n");
		exit(1);
	}

	ssize_t n = readv(f, v, IOVLEN);
	char *fv = (char *)(v[0].iov_base);
	fv[SIZE-1] = '\0';
	char *sv = (char *)(v[1].iov_base);
	sv[SIZE-1] = '\0';

	printf("1:%s\n", fv);
	printf("2:%s\n", sv);

	close(f);
	return 0;
}
