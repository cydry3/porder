#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>


int main() 
{
	int wstatus;

	pid_t pid = fork();
	if (pid == -1) {
		fprintf(stderr, "failed fork\n");
		exit(1);
	}
	
	if (pid == 0) {
		sleep(3);
		printf("tracee/C:exited\n");
	} else {
		printf("tracee/C:%d\n", pid);
		printf("tracee/P:%d\n", getpid());
		wait(&wstatus);
		printf("tracee/P:exited\n");
	}
	return 0;
}
