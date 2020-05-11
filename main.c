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
		fprintf(stderr, "failed set a trace option at a continue point\n");
		exit(1);
	}
}

int try_trace_option(pid_t child_pid)
{
	int lim = 8;
	while (lim > 0) {
		long res = ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
							PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEEXEC|PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK);
		if (res != -1)
			return 0;
		lim--;
	}
	return -1;
}

void trace_option(pid_t child_pid)
{
	int res = try_trace_option(child_pid);
	if (res == -1) {
		fprintf(stderr, "failed set a trace option: %d, %s\n", child_pid, strerror(errno));
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

void start_trace_on_syscall(struct child_context *c_ctx)
{
	long res = ptrace(PTRACE_SYSCALL, c_ctx->pid, NULL, c_ctx->signum);
	if (res == -1) {
		fprintf(stderr, "failed start a syscall trace (pid:%d)(sig:%d)\n",
				c_ctx->pid, c_ctx->signum);
		exit(1);
	}
}

void start_trace_on_singlestep(struct child_context *c_ctx)
{
	long res = ptrace(PTRACE_SINGLESTEP, c_ctx->pid, NULL, c_ctx->signum);
	if (res == -1) {
		fprintf(stderr, "failed start a trace\n");
		exit(1);
	}
}

void start_trace(struct child_context *c_ctx)
{
	if (is_trace_status_on_syscall(&c_ctx->tracestep))
		start_trace_on_syscall(c_ctx);

	else if (is_trace_status_on_singlestep(&c_ctx->tracestep))
		start_trace_on_singlestep(c_ctx);

	else {
		fprintf(stderr, "unreachable in starting trace.\n");
		exit(1);
	}
}

void restart_trace(struct child_context *c_ctx)
{
	trace_option(c_ctx->pid);
	ignore_signal_number(&c_ctx->signum);
	start_trace(c_ctx);
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

void handle_on_syscall(struct child_context *c_ctx)
{
	// Syscall before & after point. in addtion, exec after point.
	if (is_exec_after(&c_ctx->syscall)) {
		if (is_in_syscall(&c_ctx->syscall))
			print_regs_at_end_point(c_ctx->pid);
		else
			print_regs_at_start_point(c_ctx->pid);

	} else {
		print_regs_at_after_exec_point(c_ctx->pid);
	}
}

void handle_on_singlestep(struct child_context *c_ctx)
{
	print_instruction_on_child(c_ctx->pid);
}

void handle_sigtrap_by_tracing(struct child_context *c_ctx)
{
	if (is_trace_status_on_syscall(&c_ctx->tracestep))
		handle_on_syscall(c_ctx);

	else if (is_trace_status_on_singlestep(&c_ctx->tracestep)) 
		handle_on_singlestep(c_ctx);

	else {
		fprintf(stderr, "unreachable in handling a sigtrap by tracing.\n");
		exit(1);
	}
}

void handle_sigtrap_by_othter(struct child_context *c_ctx)
{
	printf("int3 instruction executed.\n");
}

int is_on_tracing(struct child_context *c_ctx)
{
	return ((is_sigtrap_by_tracing_good(&c_ctx->signum)) ||
			(is_sigtrap(&c_ctx->signum) && (is_trace_status_on_singlestep(&c_ctx->tracestep))));
}

void handle_sigtraps(struct child_context *c_ctx)
{
	if (is_on_tracing(c_ctx))
		handle_sigtrap_by_tracing(c_ctx);

	else
		handle_sigtrap_by_othter(c_ctx);
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
	int pipefd[2];

	pid_t pid = waitpid(child_pid, &wstatus, 0);

	struct child_context *c_ctx = enroll_context(pid);
	set_trace_status_by_mode(&c_ctx->tracestep, mode);

	continue_trace_option(c_ctx->pid);
	continue_child(c_ctx->pid);

	while (1) {
		pid = wait(&wstatus);
		if (pid == -1)
			return 1;

		c_ctx = recept_context(pid);
		if (WIFEXITED(wstatus)) {
			break;

		} else if (WIFSIGNALED(wstatus)){
			c_ctx->signum = WTERMSIG(wstatus);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
			c_ctx->signum = (wstatus>>8);

			if (is_trace_status_on_singlestep(&c_ctx->tracestep))
				prepare_singlestep_tracing(pid, pipefd);

			restart_trace(c_ctx);

		} else if (wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
			c_ctx->signum = (wstatus>>8);
			restart_trace(c_ctx);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_FORK<<8)) {
			c_ctx->signum = (wstatus>>8);
			pid_t forked_pid = get_pid_forked_on_child(pid);

			struct child_context *forked_ctx = enroll_context(forked_pid);
			set_trace_status_by_mode(&forked_ctx->tracestep, mode);
			set_fork_context(forked_ctx);

			restart_trace(c_ctx);
			restart_trace(forked_ctx);

		} else if (WIFSTOPPED(wstatus)){
			c_ctx->signum = WSTOPSIG(wstatus);
			handle_sigtraps(c_ctx);

			restart_trace(c_ctx);

		} else if (WIFCONTINUED(wstatus)) {
			c_ctx->signum = SIGCONT;

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
