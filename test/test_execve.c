#include <stdio.h>
#include <unistd.h>

int main()
{
	char *envs[] = { NULL };
	char *args[] = { "/bin/sleep", "3", NULL };

	execve(args[0], args, envs);
	printf("Hello, world!(unreachable line)\n");
}
