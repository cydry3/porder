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
		pid_t ppid = getppid();
		printf("PPID:%d\n", ppid);
	} else {
		waitpid(pid, &wstatus, 0);
	}
	return 0;
}
