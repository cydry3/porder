#include "porder.h"

void run_script(char **args)
{
	char *envs[] = { NULL };
	int res = execve(args[0], args, envs);
	if (res == -1) {
		fprintf(stderr, "failed running auxiliary scripts ...\n");
		exit(1);
	}
	fprintf(stderr, "This should be unreachable line\n");
}

pid_t join_script(pid_t pid, char **args)
{
	int wstatus;
	pid = waitpid(pid, &wstatus, 0);
	if (pid == -1) {
		fprintf(stderr, "failed completing a script(%s) on waiting", args[0]);
		exit(1);
	}
	if (WIFEXITED(wstatus) == 0) {
		fprintf(stderr, "failed completing a auxiliary script(%s)", args[0]);
		exit(1);
	}
	return pid;
}

void run_aux_script_on_subprocess(char **args)
{
	pid_t pid = fork();
	if ((pid == -1))
		exit(1);

	if (pid == 0) {
		run_script(args);
	} else {
		join_script(pid, args);
	}
}

void prepare_conv_table(pid_t child_pid)
{
	char pid_str[8];
	sprintf(pid_str, "%d", child_pid);

	char *args[] = {"./gen_asm_table.py", pid_str, NULL};

	run_aux_script_on_subprocess(args);
}

int spawn_post_printer(int *pipefd)
{
	int res = pipe(pipefd);
	if (res == -1) {
		fprintf(stderr, "failed making a pipe to converting process\n");
		exit(1);
	}

	char *args[] = {"./conv_addr2asm.py", NULL};

	pid_t script_pid = fork();
	if ((script_pid == -1))
		exit(1);

	if (script_pid == 0) {
		close(pipefd[1]);
		int ok = dup2(pipefd[0], STDIN_FILENO);
		if (ok == -1) {
			fprintf(stderr, "failed piping read side.\n");
			exit(1);
		}
		close(pipefd[0]);

		run_aux_script_on_subprocess(args);

	} else {
		close(pipefd[0]);
		int ok = dup2(pipefd[1], STDOUT_FILENO);
		if (ok == -1) {
			fprintf(stderr, "failed piping write side.\n");
			exit(1);
		}
		close(pipefd[1]);
	}
	return pipefd[1];
}
