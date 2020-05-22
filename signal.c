#include "porder.h"

void print_sig(int sig)
{
	printf("Child received signal %d\n", sig);
}

void print_signal_string(int signum)
{
	switch(signum) {
		case 1 /* 1 */: printf("SIGHUP"); break;
		case 2 /* 2 */: printf("SIGINT"); break;
		case 3 /* 3 */: printf("SIGQUIT"); break;
		case 4 /* 4 */: printf("SIGILL"); break;
		case 5 /* 5 */: printf("SIGTRAP"); break;
		case 6 /* 6 */: printf("SIGABRT"); break;
		case 7 /* 7 */: printf("SIGBUS"); break;
		case 8 /* 8 */: printf("SIGFPE"); break;
		case 9 /* 9 */: printf("SIGKILL"); break;
		case 10 /* 10 */: printf("SIGUSR1"); break;
		case 11 /* 11 */: printf("SIGSEGV"); break;
		case 12 /* 12 */: printf("SIGUSR2"); break;
		case 13 /* 13 */: printf("SIGPIPE"); break;
		case 14 /* 14 */: printf("SIGALRM"); break;
		case 15 /* 15 */: printf("SIGTERM"); break;
		case 16 /* 16 */: printf("SIGSTKFLT"); break;
		case 17 /* 17 */: printf("SIGCHLD"); break;
		case 18 /* 18 */: printf("SIGCONT"); break;
		case 19 /* 19 */: printf("SIGSTOP"); break;
		case 20 /* 20 */: printf("SIGTSTP"); break;
		case 21 /* 21 */: printf("SIGTTIN"); break;
		case 22 /* 22 */: printf("SIGTTOU"); break;
		case 23 /* 23 */: printf("SIGURG"); break;
		case 24 /* 24 */: printf("SIGXCPU"); break;
		case 25 /* 25 */: printf("SIGXFSZ"); break;
		case 26 /* 26 */: printf("SIGVTALRM"); break;
		case 27 /* 27 */: printf("SIGPROF"); break;
		case 28 /* 28 */: printf("SIGWINCH"); break;
		case 29 /* 29 */: printf("SIGIO"); break;
		case 30 /* 30 */: printf("SIGPWR"); break;
		case 31 /* 31 */: printf("SIGSYS"); break;
		case 32 /* 32 */: printf("SIGRTMIN"); break;
		default: break;
	}
}
