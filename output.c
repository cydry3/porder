#include "porder.h"

void print_pid(pid_t pid)
{
	printf("pid:%d", pid);
}

void print_fork_context(struct child_context *ctx)
{
	printf("\x1b[33m" "[");
	print_pid(ctx->pid);
	printf("]" "\x1b[0m");
}

void print_syscall(struct child_context *ctx)
{
	if (is_fork_context(ctx))
		print_fork_context(ctx);

	print_syscall_name(ctx);

	if (ctx->start)
		printf(" started ");
	else if (ctx->end)
		printf(" ended-> ");

	print_syscall_args_retval(ctx);

	printf("\n");
}

void print_instruction_on_child(pid_t pid)
{
	char rip_addr[41];
	struct user_regs_struct regs;

	printf("\x1b[36m[instruction]\x1b[0m ");
	if (get_user_register(&regs, pid)) {
		sprintf(rip_addr, "%llx\n", regs.rip);
		int ok = write(STDOUT_FILENO, rip_addr, strlen(rip_addr));
		if (ok == -1) {
			fprintf(stderr, "failed writeing to fd post printer\n");
			exit(1);
		}
	}
}

void print_sigtrap_by_other_process(struct child_context *ctx)
{
	if (is_fork_context(ctx))
		print_fork_context(ctx);
	printf("Received signal(%d)\n", ctx->signum);
}
