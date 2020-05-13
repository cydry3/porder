#include "porder.h"

int confirm_continue()
{
	char yes_or;

	printf("continue? [y/n] ");
	yes_or = getchar();
	getchar();

	return (yes_or == 'y');
}

int debug_loop(pid_t child_pid)
{
	int wstatus = 0;
	struct child_context c_ctx;

	pid_t pid = waitpid(child_pid, &wstatus, 0);
	init_child_context (pid, &c_ctx);
	c_ctx.signum = (wstatus>>8);

	continue_trace_option(c_ctx.pid);
	continue_trace(&c_ctx);

	while (1) {
		pid = wait(&wstatus);
		if (pid == -1) {
			fprintf(stderr, "PID[%d] failed waiting\n", pid);
			return 1;
		}

		c_ctx.pid = pid;
		if (WIFEXITED(wstatus)) {
			fprintf(stderr, "PID:%d exited\n", pid);
			break;

		} else if (WIFSIGNALED(wstatus)){
			c_ctx.signum = WTERMSIG(wstatus);
			fprintf(stderr, "PID:%d signaled(%d)\n", c_ctx.pid, c_ctx.signum);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
			c_ctx.signum = (wstatus>>8);
			fprintf(stderr, "PID:%d exec-ed(%d)\n", c_ctx.pid, c_ctx.signum);

			if (!confirm_continue()) 
				break;
			restart_trace(&c_ctx);

		} else if (wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
			c_ctx.signum = (wstatus>>8);
			fprintf(stderr, "PID:%d clone-ed(%d)\n", c_ctx.pid, c_ctx.signum);
			restart_trace(&c_ctx);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_FORK<<8)) {
			c_ctx.signum = (wstatus>>8);
			pid_t forked_pid = get_pid_forked_on_child(c_ctx.pid);
			fprintf(stderr, "PID:%d fork-ed(%d) -> new(%d)\n", c_ctx.pid, c_ctx.signum, forked_pid);

			restart_trace(&c_ctx);
			c_ctx.pid = forked_pid;
			restart_trace(&c_ctx);

		} else if (WIFSTOPPED(wstatus)){
			c_ctx.signum = WSTOPSIG(wstatus);
			fprintf(stderr, "PID:%d stopped(%d)\n", c_ctx.pid, c_ctx.signum);
			restart_trace(&c_ctx); // instead of handling a signal

		} else if (WIFCONTINUED(wstatus)) {
			c_ctx.signum = SIGCONT;
			fprintf(stderr, "PID:%d resumed(%d)\n", c_ctx.pid, c_ctx.signum);

		} else {
			fprintf(stderr, "PID:%d unexpected signal(%d)\n", pid,c_ctx.signum);
			exit(1);
		}
	}
	stop_child(pid);

	return 0;
}
