#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SIZE 32

int main()
{
	char *file = "./test_pread64.c";
	char *buf[SIZE]; 
	size_t read_size = SIZE;
	off_t offset = 0;

	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "failed open file.\n");
		exit(1);
	}

	pread(fd, buf, read_size, offset);
	printf("%s", buf);
	close(fd);
}
