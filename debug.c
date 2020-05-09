#include "porder.h"

struct child_status {
	pid_t pid;
	syscall_status syscall;
	trace_step_status_t tracestep;
};

void init_child_status(pid_t pid, struct child_status *c_status)
{
	c_status->pid = pid;
	init_syscall_status(&c_status->syscall);
	trace_status_to_syscall(&c_status->tracestep);
}

void stop_child(pid_t pid)
{
	int ok = kill(pid, SIGKILL);
	if (ok == 1) {
		fprintf(stderr, "failed stop child process(PID:%d) %s", pid, strerror(errno));
		exit(1);
	}
}

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

	int signum = 0;
	while (1) {
		pid = waitpid(pid, &wstatus, 0);
		if (pid == -1) {
			fprintf(stderr, "PID[%d] failed waiting\n", pid);
			return 1;
		}

		if (WIFEXITED(wstatus)) {
			fprintf(stderr, "PID:%d exited\n", pid);
			break;

		} else if (WIFSIGNALED(wstatus)){
			signum = WTERMSIG(wstatus);
			fprintf(stderr, "PID:%d signaled(%d)\n", pid, signum);

		} else if (wstatus>>8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)) {
			signum = (wstatus>>8);
			fprintf(stderr, "PID:%d exec-ed(%d)\n", pid, signum);

			if (!confirm_continue()) 
				break;

			trace_option(pid);
			ignore_signal_number(&signum);
			start_trace(pid, signum, &c_status.tracestep);

		} else if (WIFSTOPPED(wstatus)){
			signum = WSTOPSIG(wstatus);
			fprintf(stderr, "PID:%d stopped(%d)\n", pid, signum);

			trace_option(pid);
			ignore_signal_number(&signum);
			start_trace(pid, signum, &c_status.tracestep);

		} else if (WIFCONTINUED(wstatus)) {
			signum = SIGCONT;
			fprintf(stderr, "PID:%d resumed(%d)\n", pid, signum);

		} else {
			fprintf(stderr, "PID:%d unexpected signal(%d)\n", pid, signum);
			exit(1);
		}
	}
	stop_child(pid);

	return 0;
}
