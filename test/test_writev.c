#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define SIZE 64 
#define IOVLEN 2

int main() {
	char *str0 = "hello ";
	char *str1 = "world\n";
	struct iovec iov[2];
	ssize_t n;

	iov[0].iov_base = str0;
	iov[0].iov_len = strlen(str0);
	iov[1].iov_base = str1;
	iov[1].iov_len = strlen(str1);

	n = writev(STDOUT_FILENO, iov, 2);
	printf("n=%d\n", n);
	return 0;
}
