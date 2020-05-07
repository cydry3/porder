#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <signal.h>
#include <asm/unistd_64.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef char trace_step_status_t;

void print_syscall_name(unsigned long long int s);
void trace_status_to_syscall(trace_step_status_t *ts_status);
int  is_trace_status_on_syscall(trace_step_status_t *ts_status);
int  is_trace_status_on_singlestep(trace_step_status_t *ts_status);

