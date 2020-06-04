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
#include <search.h>
#include <ctype.h>
#include <time.h>
#include <asm/prctl.h>

#define _GNU_SOURCE
#include <sys/uio.h>

ssize_t process_vm_readv(pid_t pid,
						const struct iovec *local_iov,
						unsigned long liovcnt,
						const struct iovec *remote_iov,
						unsigned long riovcnt,
						unsigned long flags);



typedef char trace_step_status_t;

typedef struct syscall_status {;
	int in_syscall;
} syscall_status;

struct child_context {
	pid_t pid;
	int signum;
	char forked;
	char start;
	char end;
	char verbose;
	syscall_status syscall;
	trace_step_status_t tracestep;
	struct user_regs_struct *regs;
};


// main.c
void trace_status_to_syscall(trace_step_status_t *ts_status);
int  is_trace_status_on_syscall(trace_step_status_t *ts_status);
int  is_trace_status_on_singlestep(trace_step_status_t *ts_status);
long get_child_memory_data(pid_t pid, void *addr);
long long int
instruction_address_offset(long long unsigned int *addr, pid_t pid);
void continue_trace_option(pid_t child_pid);
void continue_child(pid_t child_pid);
void trace_option(pid_t child_pid);
void start_trace(struct child_context *c_ctx);
void handle_sigtraps(struct child_context *c_ctx);
void start_trace_on_syscall(struct child_context *c_ctx);
void ignore_signal_number(int *sig);
void restart_trace(struct child_context *c_ctx);
void stop_child(pid_t pid);
void continue_trace(struct child_context *ctx);

// output.c
void print_sig(int sig);
void print_pid(pid_t pid);
void print_instruction_on_child(pid_t pid);
void print_syscall(struct child_context *ctx);
void print_fork_context(struct child_context *ctx);
void print_syscall(struct child_context *ctx);
void print_sigtrap_by_other_process(struct child_context *ctx);

// name.c
void print_syscall_name(struct child_context *ctx);

// retval.c
void print_syscall_args_retval(struct child_context *ctx);

// signal.c
void print_signal_string(int signum);

// aux_scripts.c
void prepare_conv_table(pid_t child_pid);
int spawn_post_printer(int pipefd[]);


// status.c
void init_syscall_status(syscall_status *s_status);
void toggle_syscall_status(syscall_status *s_status);
int is_in_syscall(syscall_status *s_status);
int in_syscall(syscall_status *s_status);

void trace_status_to_singlestep(trace_step_status_t *ts_status);
void trace_status_to_syscall(trace_step_status_t *ts_status);
int is_trace_status_on_singlestep(trace_step_status_t *ts_status);
int is_trace_status_on_syscall(trace_step_status_t *ts_status);

void init_child_context (pid_t pid, struct child_context *c_ctx);

// args.c
#define PORDER_INST_MODE    0x00
#define PORDER_SYSCALL_MODE 0x01
#define PORDER_DEBUG_MODE   0x02
#define PORDER_MODE_MASK    0x0f
#define PORDER_VERBOSE_MODE (1u<<4)

void args_parse(int *mode, char **dest, char **argv, size_t argc);
int is_syscall_mode(int mode);
int is_singlestep_mode(int mode);
int is_debug_mode(int mode);
int is_verbose_mode(int mode);

// debug.c
int debug_loop(pid_t child_pid);

// inspect.c
pid_t get_pid_forked_on_child(pid_t child_pid);
int get_user_register(struct user_regs_struct *regs, pid_t pid);
void *deref_child_pointer(pid_t pid, void *ptr);

// context.c
struct child_context *enroll_context(pid_t pid);
struct child_context *recept_context(pid_t pid);
void set_fork_context(struct child_context *ctx);
int is_fork_context(struct child_context *ctx);
void update_syscall_context(struct child_context *ctx);
void init_child_context(pid_t pid, struct child_context *c_ctx);
void set_verbose_ctx_by_mode(struct child_context *ctx, int mode);

// util.c
#define MAX_PORDER_PATHLEN 256
#define PORDER_NAMELEN 6
void retry_interval_nano(void);
char *bin_rootpath_with(const char *filename);
