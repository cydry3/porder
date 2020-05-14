#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>


void print_segv(int n)
{
	printf("catch a signal `%s`\n", strsignal(n));
	exit(1);
}

int main()
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = print_segv;
	sa.sa_flags = 0;
	sigaction(SIGSEGV, &sa, NULL);

	int range[8];
	printf("out of", range[4096]);
	return 0;
}
