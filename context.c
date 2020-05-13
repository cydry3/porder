#include "porder.h"

static void *contexts_root = NULL;

struct child_context *ctx_alloc()
{
	struct child_context *ctx = malloc(sizeof(struct child_context));
	if (ctx == NULL) {
		fprintf(stderr, "failed allocating a child_context\n");
		exit(1);
	}
	return ctx;
}

static int compare(const void *pa, const void *pb)
{
	if (((struct child_context *)pa)->pid < ((struct child_context *)pb)->pid)
		return -1;
	if (((struct child_context *)pa)->pid > ((struct child_context *)pb)->pid)
		return 1;
	return 0;
}

struct child_context *enroll_context(pid_t pid)
{
	struct child_context *ctx = ctx_alloc();
	init_child_context(pid, ctx);

	void *res = tsearch((void *)ctx, &contexts_root, compare);
	if (res == NULL) {
		fprintf(stderr, "failed enrolling a child_context\n");
		exit(1);
	}
	return ctx;
}

struct child_context *recept_context(pid_t pid)
{
	struct child_context key_ctx;
	key_ctx.pid = pid;

	void *ctx = tfind((void *)&key_ctx, &contexts_root, compare);
	if (ctx == NULL) {
		fprintf(stderr, "failed finding a child_context:%d\n", pid);
		exit(1);
	}
	return *(struct child_context **)ctx;
}

void set_fork_context(struct child_context *ctx)
{
	ctx->forked = 1;
}

int is_fork_context(struct child_context *ctx)
{
	return (ctx->forked == 1);
}

int is_start_syscall(struct child_context *ctx)
{
	return (!is_in_syscall(&ctx->syscall));

}

int is_end_syscall(struct child_context *ctx)
{
	return (is_in_syscall(&ctx->syscall));
}

void update_syscall_context(struct child_context *ctx)
{
	ctx->start = 0;
	ctx->end = 0;

	if (is_in_syscall(&ctx->syscall))
		ctx->end = 1;
	else
		ctx->start = 1;
}

void set_verbose_context(struct child_context *ctx)
{
	ctx->verbose = 1;
}

int is_verbose(struct child_context *ctx)
{
	return (ctx->verbose == 1);
}

void init_child_context(pid_t pid, struct child_context *c_ctx)
{
	c_ctx->pid = pid;
	c_ctx->signum = 0;
	c_ctx->forked = 0;
	c_ctx->verbose = 0;
	init_syscall_status(&c_ctx->syscall);
	trace_status_to_syscall(&c_ctx->tracestep);
}

void set_verbose_ctx_by_mode(struct child_context *ctx, int mode)
{
	if (is_verbose_mode(mode))
		ctx->verbose = 1;
	else
		ctx->verbose = 0;
}
