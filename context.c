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
