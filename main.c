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

void start_trace_on_syscall(struct child_status *c_status)
{
	long res = ptrace(PTRACE_SYSCALL, c_status->pid, NULL, c_status->signum);
	if (res == -1) {
		fprintf(stderr, "failed start a syscall trace (pid:%d)(sig:%d)\n",
				c_status->pid, c_status->signum);
		exit(1);
	}
}

void start_trace_on_singlestep(struct child_status *c_status)
{
	long res = ptrace(PTRACE_SINGLESTEP, c_status->pid, NULL, c_status->signum);
	if (res == -1) {
		fprintf(stderr, "failed start a trace\n");
		exit(1);
	}
}

void start_trace(struct child_status *c_status)
{
	if (is_trace_status_on_syscall(&c_status->tracestep))
		start_trace_on_syscall(c_status);

	else if (is_trace_status_on_singlestep(&c_status->tracestep))
		start_trace_on_singlestep(c_status);

	else {
		fprintf(stderr, "unreachable in starting trace.\n");
		exit(1);
	}
}

void restart_trace(struct child_status *c_status)
{
	trace_option(c_status->pid);
	ignore_signal_number(&c_status->signum);
	start_trace(c_status);
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

void handle_on_syscall(struct child_status *c_status)
{
	// Syscall before & after point. in addtion, exec after point.
	if (is_exec_after(&c_status->syscall)) {
		if (is_in_syscall(&c_status->syscall))
			print_regs_at_end_point(c_status->pid);
		else
			print_regs_at_start_point(c_status->pid);

	} else {
		print_regs_at_after_exec_point(c_status->pid);
	}
}

void handle_on_singlestep(struct child_status *c_status, int post_fd)
{
	print_instruction_on_child(c_status->pid, post_fd);
}

void handle_sigtrap_by_tracing(struct child_status *c_status, int post_fd)
{
	if (is_trace_status_on_syscall(&c_status->tracestep))
		handle_on_syscall(c_status);

	else if (is_trace_status_on_singlestep(&c_status->tracestep)) 
		handle_on_singlestep(c_status, post_fd);

	else {
		fprintf(stderr, "unreachable in handling a sigtrap by tracing.\n");
		exit(1);
	}
}

void handle_sigtrap_by_othter(struct child_status *c_status)
{
	printf("int3 instruction executed.\n");
}

int is_on_tracing(struct child_status *c_status)
{
	return ((is_sigtrap_by_tracing_good(&c_status->signum)) ||
			(is_sigtrap(&c_status->signum) && (is_trace_status_on_singlestep(&c_status->tracestep))));
}

void handle_sigtraps(struct child_status *c_status, int post_fd)
{
	if (is_on_tracing(c_status))
		handle_sigtrap_by_tracing(c_status, post_fd);

	else
		handle_sigtrap_by_othter(c_status);
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

		c_status.pid = pid;
		if (WIFEXITED(wstatus)) {
			break;

		} else if (WIFSIGNALED(wstatus)){
			c_status.signum = WTERMSIG(wstatus);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
			c_status.signum = (wstatus>>8);

			if (is_trace_status_on_singlestep(&c_status.tracestep))
				prepare_singlestep_tracing(pid, pipefd);

			restart_trace(&c_status);

		} else if (wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
			c_status.signum = (wstatus>>8);
			restart_trace(&c_status);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_FORK<<8)) {
			c_status.signum = (wstatus>>8);
			pid_t forked_pid = get_pid_forked_on_child(pid);

			restart_trace(&c_status);
			c_status.pid = forked_pid;
			restart_trace(&c_status);

		} else if (WIFSTOPPED(wstatus)){
			c_status.signum = WSTOPSIG(wstatus);
			handle_sigtraps(&c_status, post_fd);

			restart_trace(&c_status);

		} else if (WIFCONTINUED(wstatus)) {
			c_status.signum = SIGCONT;

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
