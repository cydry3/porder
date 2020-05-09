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

typedef struct syscall_status {;
	int exec_after;
	int in_syscall;
} syscall_status;


// main.c
void trace_status_to_syscall(trace_step_status_t *ts_status);
int  is_trace_status_on_syscall(trace_step_status_t *ts_status);
int  is_trace_status_on_singlestep(trace_step_status_t *ts_status);
long get_child_memory_data(pid_t pid, void *addr);
long long int
instruction_address_offset(long long unsigned int *addr, pid_t pid);


// output.c
void print_sig(int sig);
void print_pid(pid_t pid);
void print_exec_after_msg(unsigned long long int syscall_num);
void print_syscall_args_at_before_point(struct user_regs_struct *regs, pid_t pid);
void print_syscall_args_at_after_point(struct user_regs_struct *regs, pid_t pid);
void print_start_syscall_msg(struct user_regs_struct *regs, pid_t pid);
void print_error_value(long long int err,
						unsigned long long int syscall_num);
void print_return_value(pid_t pid, struct user_regs_struct *regs);
void print_end_syscall_msg(pid_t pid, struct user_regs_struct *regs);
void print_regs_at_after_exec_point(pid_t pid);
void print_regs_at_start_point(pid_t pid);
void print_regs_at_end_point(pid_t pid);
void print_child_memory_data(pid_t pid, void *addr);
void print_instruction_on_child(pid_t pid, int post_fd);
void print_syscall_name(unsigned long long int s);


// aux_scripts.c
void prepare_conv_table(pid_t child_pid);
int spawn_post_printer();


// status.c
void init_syscall_status(syscall_status *s_status);
void once_toggle_exec_status(syscall_status *s_status);
void toggle_syscall_status(syscall_status *s_status);
int is_exec_after(syscall_status *s_status);
int is_in_syscall(syscall_status *s_status);
int in_syscall(syscall_status *s_status);

void trace_status_to_singlestep(trace_step_status_t *ts_status);
void trace_status_to_syscall(trace_step_status_t *ts_status);
int is_trace_status_on_singlestep(trace_step_status_t *ts_status);
int is_trace_status_on_syscall(trace_step_status_t *ts_status);

// args.c
void args_parse(int *mode, char **dest, char **argv, size_t argc);
