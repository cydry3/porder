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
	struct child_status c_status;

	pid_t pid = waitpid(child_pid, &wstatus, 0);
	init_child_status(pid, &c_status);

	continue_trace_option(c_status.pid);
	continue_child(c_status.pid);

	while (1) {
		pid = wait(&wstatus);
		if (pid == -1) {
			fprintf(stderr, "PID[%d] failed waiting\n", pid);
			return 1;
		}

		c_status.pid = pid;
		if (WIFEXITED(wstatus)) {
			fprintf(stderr, "PID:%d exited\n", pid);
			break;

		} else if (WIFSIGNALED(wstatus)){
			c_status.signum = WTERMSIG(wstatus);
			fprintf(stderr, "PID:%d signaled(%d)\n", c_status.pid, c_status.signum);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
			c_status.signum = (wstatus>>8);
			fprintf(stderr, "PID:%d exec-ed(%d)\n", c_status.pid, c_status.signum);

			if (!confirm_continue()) 
				break;
			restart_trace(&c_status);

		} else if (wstatus>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
			c_status.signum = (wstatus>>8);
			fprintf(stderr, "PID:%d clone-ed(%d)\n", c_status.pid, c_status.signum);
			restart_trace(&c_status);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_FORK<<8)) {
			c_status.signum = (wstatus>>8);
			pid_t forked_pid = get_pid_forked_on_child(c_status.pid);
			fprintf(stderr, "PID:%d fork-ed(%d) -> new(%d)\n", c_status.pid, c_status.signum, forked_pid);

			restart_trace(&c_status);
			c_status.pid = forked_pid;
			restart_trace(&c_status);

		} else if (WIFSTOPPED(wstatus)){
			c_status.signum = WSTOPSIG(wstatus);
			fprintf(stderr, "PID:%d stopped(%d)\n", c_status.pid, c_status.signum);
			restart_trace(&c_status); // instead of handling a signal

		} else if (WIFCONTINUED(wstatus)) {
			c_status.signum = SIGCONT;
			fprintf(stderr, "PID:%d resumed(%d)\n", c_status.pid, c_status.signum);

		} else {
			fprintf(stderr, "PID:%d unexpected signal(%d)\n", pid, c_status.signum);
			exit(1);
		}
	}
	stop_child(pid);

	return 0;
}
