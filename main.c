#include "porder.h"

void args_copy(char **dest, char **argv, size_t argc) {
	for (int i = 1; i < argc; i++)
		dest[i-1] = argv[i];
	dest[argc-1] = NULL;
}

void be_tracee() {
	long res = ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
	if (res == -1) {
		fprintf(stderr, "failed make chiled process traceed\n");
		exit(1);
	}
}

void child_main(char **args)
{
	be_tracee();
	raise(SIGSTOP);

	char *envs[] = { NULL };
	int res = execve(args[0], args, envs);
	if (res == -1) {
		fprintf(stderr, "failed execute %s",args[0]);
		exit(1);
	}
	fprintf(stderr, "This should be unreachable line");
}

void continue_trace_option(pid_t child_pid)
{
	long res = ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACEEXEC);
	if (res == -1) {
		fprintf(stderr, "failed set a trace option\n");
		exit(1);
	}
}

void trace_option(pid_t child_pid)
{
	long res = ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACESYSGOOD);
	if (res == -1) {
		fprintf(stderr, "failed set a trace option\n");
		exit(1);
	}
}

void continue_child(pid_t child_pid)
{
	long res = ptrace(PTRACE_CONT, child_pid, NULL, NULL);
	if (res == -1) {
		fprintf(stderr, "failed continue a child process tracing\n");
		exit(1);
	}
}

void start_trace_on_syscall(pid_t child_pid, int sig)
{
	long res = ptrace(PTRACE_SYSCALL, child_pid, NULL, sig);
	if (res == -1) {
		fprintf(stderr, "failed start a trace\n");
		exit(1);
	}
}

void start_trace_on_singlestep(pid_t child_pid, int sig)
{
	long res = ptrace(PTRACE_SINGLESTEP, child_pid, NULL, sig);
	if (res == -1) {
		fprintf(stderr, "failed start a trace\n");
		exit(1);
	}
}

void start_trace(pid_t child_pid, int sig, trace_step_status_t *ts_status)
{
	if (is_trace_status_on_syscall(ts_status))
		start_trace_on_syscall(child_pid, sig);

	else if (is_trace_status_on_singlestep(ts_status))
		start_trace_on_singlestep(child_pid, sig);

	else {
		fprintf(stderr, "unreachable in starting trace.\n");
		exit(1);
	}
}

int is_sigtrap(int *sig)
{
	return *sig == SIGTRAP;
}

int is_sigtrap_by_tracing_good(int *sig)
{
	return *sig == (SIGTRAP|0x80);
}

void ignore_signal_number(int *sig)
{
		*sig = 0;
}

void ignore_signal_number_sigtraps(int *sig)
{
	if ((is_sigtrap(sig)) || ( is_sigtrap_by_tracing_good(sig)))
		*sig = 0;
}

void handle_on_syscall(pid_t pid, int *signum, syscall_status *sstatus, trace_step_status_t *ts_status)
{
	// Syscall before & after point. in addtion, exec after point.
	if (is_exec_after(sstatus)) {
		if (is_in_syscall(sstatus))
			print_regs_at_end_point(pid);
		else
			print_regs_at_start_point(pid);

	} else {
		print_regs_at_after_exec_point(pid);
	}
	trace_option(pid);
	ignore_signal_number(signum);
	start_trace(pid, *signum, ts_status);
}

char *pid_to_proc_path(pid_t pid)
{
	static char path_buf[20];

	snprintf(path_buf, 20, "/proc/%d/maps", pid);
	return path_buf;
}

char *get_base_address(char *path_buf)
{
	static char procinfo_buf[16];

	int fd = open(path_buf, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "failed open proc file\n");
		exit(1);
	}

	ssize_t ok;
	char cur;
	int i = 0;
	while (i < 16) {
		if (cur == '-') {
			procinfo_buf[i-1] = '\0';
			break;
		}
		ok = read(fd, (procinfo_buf + i), 1);
		if (ok == -1) {
			fprintf(stderr, "failed reading proc file %s\n",
					path_buf);
			close(fd);
			exit(1);
		}
		cur = procinfo_buf[i];
		i++;
	}
	close(fd);

	return procinfo_buf;
}

long long int
get_child_mem_mapped_base_address(pid_t pid)
{
	char *path_buf = pid_to_proc_path(pid);
	char *proc_info = get_base_address(path_buf);

	char *endptr;
	long long int base_p = strtoll(proc_info, &endptr, 16);
	return base_p;
}

long long int
instruction_address_offset(long long unsigned int *addr, pid_t pid)
{
	static long long int base_p;
	static char once = 1;

	if (once) {
		once = 0;
		base_p = get_child_mem_mapped_base_address(pid);
		return 0;
	}

	return (*addr) - base_p;
}

long get_child_memory_data(pid_t pid, void *addr)
{
	long res = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
	if (errno != 0) {
		fprintf(stderr, "failed peeking child process's memory text. %s\n",
				strerror(errno));
		exit(1);
	}
	return res;
}

void handle_on_singlestep(pid_t pid, int *signum, syscall_status *sstatus, trace_step_status_t *ts_status, int post_fd)
{
	print_instruction_on_child(pid, post_fd);

	trace_option(pid);
	ignore_signal_number(signum);
	start_trace(pid, *signum, ts_status);
}

void handle_sigtrap_by_tracing(pid_t pid, int *signum, syscall_status *sstatus, trace_step_status_t *ts_status, int post_fd)
{
	if (is_trace_status_on_syscall(ts_status))
		handle_on_syscall(pid, signum, sstatus, ts_status);

	else if (is_trace_status_on_singlestep(ts_status))
		handle_on_singlestep(pid, signum, sstatus, ts_status, post_fd);

	else {
		fprintf(stderr, "unreachable in handling a sigtrap by tracing.\n");
		exit(1);
	}
}

void handle_sigtrap_by_othter(pid_t pid, int *signum, syscall_status *sstatus, trace_step_status_t *ts_status)
{
	printf("int3 instruction executed.\n");
	trace_option(pid);
	ignore_signal_number(signum);

	trace_status_to_singlestep(ts_status);
	start_trace(pid, *signum, ts_status);
}

int is_on_tracing(int *signum, trace_step_status_t *ts_status)
{
	return ((is_sigtrap_by_tracing_good(signum)) ||
			(is_sigtrap(signum) && (is_trace_status_on_singlestep(ts_status))));
}

void handle_sigtraps(pid_t pid, int *signum, syscall_status *sstatus, trace_step_status_t *ts_status, int post_fd)
{
	if (is_on_tracing(signum, ts_status))
		handle_sigtrap_by_tracing(pid, signum, sstatus, ts_status, post_fd);

	else
		handle_sigtrap_by_othter(pid, signum, sstatus, ts_status);
}

int parent_main(pid_t child_pid)
{
	int wstatus = 0;
	syscall_status sstatus;
	init_syscall_status(&sstatus);

	trace_step_status_t ts_status;
	trace_status_to_singlestep(&ts_status);

	int post_fd = STDOUT_FILENO;
	int pipefd[2];

	pid_t pid = waitpid(child_pid, &wstatus, 0);
	continue_trace_option(pid);
	continue_child(pid);

	while (1) {
		pid = waitpid(pid, &wstatus, 0);
		if (pid == -1)
			return 1;

		if (WIFEXITED(wstatus)) {
			break;

		} else if (WIFSIGNALED(wstatus)){
			int signum = WTERMSIG(wstatus);
			// debug:
			print_sig(signum);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
			// debug:
			print_sig(wstatus>>8);

			prepare_conv_table(pid);    		  // `pre-process`
			post_fd = spawn_post_printer(pipefd); // `post-proecess`

			trace_option(pid);
			start_trace(pid, 0, &ts_status);

		} else if (WIFSTOPPED(wstatus)){
			int signum = WSTOPSIG(wstatus);
			// debug:
			// print_pid(pid);
			// print_sig(signum);
	
			handle_sigtraps(pid, &signum, &sstatus, &ts_status, post_fd);

		} else if (WIFCONTINUED(wstatus)) {
			print_sig(SIGCONT);

		} else {
			printf("others!\n");
		}
	}

	return 0;
}


int main(int argc, char *argv[])
{
	char *args[10];
	args_copy(args, argv, argc);

	pid_t pid = fork();
	if ((pid == -1))
		exit(1);

	if (pid == 0) {
		child_main(args);
	} else {
		parent_main(pid);
	}
	return 0;
}
