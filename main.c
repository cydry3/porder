#include "porder.h"

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
	long res = ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEEXEC|PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK);
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

void stop_child(pid_t pid)
{
	int ok = kill(pid, SIGKILL);
	if (ok == 1) {
		fprintf(stderr, "failed stop child process(PID:%d) %s", pid, strerror(errno));
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

void restart_trace(pid_t pid, int sig, trace_step_status_t *ts_status)
{
	trace_option(pid);
	ignore_signal_number(&sig);
	start_trace(pid, sig, ts_status);
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

	else if (is_trace_status_on_singlestep(ts_status)) {
		fprintf(stderr, "debug-");
		handle_on_singlestep(pid, signum, sstatus, ts_status, post_fd);

	}

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

int prepare_singlestep_tracing (pid_t pid, int pipefd[]) {
	prepare_conv_table(pid);    		  // `pre-process`
	return spawn_post_printer(pipefd); // `post-proecess`
}

void set_trace_status_by_mode(trace_step_status_t *ts_status, int mode)
{
	if (mode == 0)
		trace_status_to_singlestep(ts_status);
	else if (mode == 1)
		trace_status_to_syscall(ts_status);
	else {
		fprintf(stderr, "unexpected trace mode %d\n", mode);
		exit(1);
	}
}

int parent_main(pid_t child_pid, int mode)
{
	if (mode == 2)
		return debug_loop(child_pid);

	int signum = 0;
	int wstatus = 0;
	struct child_status c_status;
	int post_fd = STDOUT_FILENO;
	int pipefd[2];

	pid_t pid = waitpid(child_pid, &wstatus, 0);

	init_child_status(pid, &c_status);
	set_trace_status_by_mode(&c_status.tracestep, mode);

	continue_trace_option(c_status.pid);
	continue_child(c_status.pid);

	while (1) {
		pid = wait(&wstatus);
		if (pid == -1)
			return 1;

		if (WIFEXITED(wstatus)) {
			break;

		} else if (WIFSIGNALED(wstatus)){
			signum = WTERMSIG(wstatus);
			// debug:
			print_sig(signum);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
			// debug:
			print_sig(wstatus>>8);

			if (is_trace_status_on_singlestep(&c_status.tracestep))
				prepare_singlestep_tracing(pid, pipefd);

			trace_option(pid);
			start_trace(pid, 0, &c_status.tracestep);

		} else if (wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
			signum = (wstatus>>8);
			fprintf(stderr, "PID:%d clone-ed(%d)\n", pid, signum);
			restart_trace(pid, signum, &c_status.tracestep);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_FORK<<8)) {
			signum = (wstatus>>8);
			pid_t forked_pid = get_pid_forked_on_child(pid);
			fprintf(stderr, "PID:%d fork-ed(%d) -> new(%d)\n", pid, signum, forked_pid);
			restart_trace(pid, signum, &c_status.tracestep);
			restart_trace(forked_pid, signum, &c_status.tracestep);

		} else if (WIFSTOPPED(wstatus)){
			signum = WSTOPSIG(wstatus);
			// debug:
			// print_pid(pid);
			// print_sig(signum);
	
			handle_sigtraps(pid, &signum, &c_status.syscall, &c_status.tracestep, post_fd);

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
	char *cmd[10];
	int mode = 1; // default
	args_parse(&mode, cmd, argv, argc);
	printf("mode %d\n", mode);
	printf("cmd  %s\n", cmd[0]);

	pid_t pid = fork();
	if ((pid == -1))
		exit(1);

	if (pid == 0) {
		child_main(cmd);
	} else {
		parent_main(pid, mode);
	}
	return 0;
}
