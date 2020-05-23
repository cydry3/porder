#include "porder.h"

void print_sep()
{
	printf(", ");
}

void arg_sep()
{
	print_sep();
}

void paren_open()
{
	printf("(");
}

void paren_close()
{
	printf(")");
}

void int_as(long long unsigned int reg)
{
	printf("%d", (int)reg);   // int iovcnt
}

void print_syscall_retval(struct child_context *ctx)
{
	printf(" = %d", (int)ctx->regs->rax);
	if (ctx->regs->rax == -1)
		printf("(err)");
}

void print_syscall_arg_string(pid_t pid, long long unsigned int next)
{
	int max = 255;
	printf("'");
	for (int j = 0; j < 4; j++) {
		long res = get_child_memory_data(pid, (void *)(next + (4 * j)));
		for (int i = 0; i < 4; i++)  {
			char c = res>>(8*i);
			if ((c=='\0') || (--max<0))
				goto term;
			if (isprint(c) && (!isspace(c)))
				printf("%c", c);
		}
	}
term:
	printf("'");
}

void str_as(pid_t pid, long long unsigned int reg)
{
	print_syscall_arg_string(pid, reg);
}


void print_syscall_argv_string(pid_t pid, char **ptr)
{
		printf("[");
		void *deref_p = deref_child_pointer(pid, (void *)ptr);
		while(deref_p != NULL) {
			print_syscall_arg_string(pid, (long long unsigned int)deref_p);
			ptr++;

			deref_p = deref_child_pointer(pid, (void *)ptr);
			if (deref_p == NULL)
				break;
			else
				printf(", ");
		}
		printf("]");
}

void print_syscall_stat_verbose_retval(struct child_context *ctx)
{
	struct iovec local[1];
	struct iovec remote[1];
	struct stat buf;
	ssize_t nread;
	int statlen = sizeof(struct stat);

	local[0].iov_base = &buf;
	local[0].iov_len = statlen;

	remote[0].iov_base = (void *)ctx->regs->rsi;
	remote[0].iov_len = statlen;

	nread = process_vm_readv(ctx->pid, local, 1, remote, 1, 0);
	if (nread != statlen)
		return;
	else {
		printf("dev:%lx,ino:%lx,mod:%x,uid:%x,gid:%x,siz:%lx,mtime:%lx...",
				buf.st_dev, buf.st_ino, buf.st_mode, buf.st_uid, buf.st_gid,
				buf.st_size, buf.st_mtime);
	}
}

void print_syscall_args_retval_unimplemented(struct child_context *ctx)
{
	printf("(");
	if (ctx->start)
		printf("...");
	if (ctx->end)
		printf("...");
	printf(")");

	if (ctx->end) {
		if (ctx->regs->rax < 0) {
			printf(" = (err:0x%08llx)", ctx->regs->rax);
		} else {
			printf(" = (0x%08llx)", ctx->regs->rax);
		}
	}
}


/* 0 */
void print_syscall_read(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx, ", ctx->regs->rdi);
		printf("..");
		printf(", %d)", (int)ctx->regs->rdx);
	}

	if (ctx->end) {
		printf("(fd:0x%08llx, ", ctx->regs->rdi);
		print_syscall_arg_string(ctx->pid, ctx->regs->rsi);
		printf(", %d)", (int)ctx->regs->rdx); 				// size_t count
		printf(" = %ld", (unsigned long)ctx->regs->rax);    // return value is ssize_t.

		if (ctx->regs->rax == -1)
			printf("(err)");
	}
}

/* 1 */
void print_syscall_write(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx, ", ctx->regs->rdi);
		printf("..");
		printf(", %d)", (int)ctx->regs->rdx);
	}
	if (ctx->end) {
		printf("(fd:0x%08llx, ", ctx->regs->rdi);
		print_syscall_arg_string(ctx->pid, ctx->regs->rsi);
		printf(", %d)", (int)ctx->regs->rdx); 			   // size_t count
		printf(" = %ld", (unsigned long)ctx->regs->rax);   // return value is ssize_t

		if (ctx->regs->rax == -1)
			printf("(err)");
	}
}

/* 2 */
void print_syscall_open(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(");
		print_syscall_arg_string(ctx->pid, ctx->regs->rdi);
		printf(", %d", (int)ctx->regs->rsi);
		printf(", %d", (int)ctx->regs->rdx); // mode_t mode
		printf(")");
	}
	if (ctx->end) {
		print_syscall_retval(ctx);
	}
}

/* 3 */
void print_syscall_close(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx)", ctx->regs->rdi);
	}
	if (ctx->end) {
		print_syscall_retval(ctx);
	}
}

/* 4 */
void print_syscall_stat(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(");
		print_syscall_arg_string(ctx->pid, ctx->regs->rdi);
		printf("0x%08llx)", ctx->regs->rdx);
	}

	if (ctx->end) {
		printf("(.., ");
		if (ctx->verbose) {
			print_syscall_stat_verbose_retval(ctx); // struct stat *statbuf
		} else {
			printf(", 0x%08llx)", ctx->regs->rdx);
		}
		printf(")");

		print_syscall_retval(ctx);
	}
}

/* 5 */
void print_syscall_fstat(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx, ", ctx->regs->rdi);
		printf("0x%08llx)", ctx->regs->rsi);
	}

	if (ctx->end) {
		printf("(.., ");
		if (ctx->verbose) {
			print_syscall_stat_verbose_retval(ctx);
		} else {
			printf("..");
		}
		printf(")");

		print_syscall_retval(ctx);
	}
}

/* 6 */
void print_syscall_lstat(struct child_context *ctx)
{
	print_syscall_stat(ctx);
}

/* 7 */
void print_syscall_poll(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fds:0x%08llx", ctx->regs->rdi); // struct pollfd *fds
		printf(", %ld", (long)ctx->regs->rsi); // nfds_t
		printf(", %d)", (int)ctx->regs->rdx); // timeout
	}
	if (ctx->end) {
		print_syscall_retval(ctx);
	}
}

/* 8 */
void print_syscall_lseek(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx", ctx->regs->rdi);
		printf(", %ld", (long)ctx->regs->rsi); // off_t
		printf(", %d)", (int)ctx->regs->rdx); // whence
	}
	if (ctx->end) {
		print_syscall_retval(ctx);
	}
}

/* 9 */
void print_syscall_mmap(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(0x%08llx", ctx->regs->rdi);
		printf(", %d", (int)ctx->regs->rsi); // size_t length
		printf(", %d", (int)ctx->regs->rdx); // prot
		printf(", %d", (int)ctx->regs->r10); // flags
		printf(", fd:0x%08llx", ctx->regs->r8);
		printf(", %ld)", (long)ctx->regs->r9); // off_t offset
	}
	if (ctx->end) {
		printf(" = %p", (void *)ctx->regs->rax);
		if (ctx->regs->rax == -1)
			printf("(err)");
	}
}

/* 10 */
void print_syscall_mprotect(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(0x%08llx", ctx->regs->rdi);
		printf(", %d", (int)ctx->regs->rsi); // size_t len
		printf(", %d)", (int)ctx->regs->rdx); // prot
	}
	if (ctx->end) {
		print_syscall_retval(ctx);
	}
}

/* 11 */
void print_syscall_munmap(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(0x%08llx", ctx->regs->rdi);
		printf(", %d)", (int)ctx->regs->rsi); // size_t length
	}
	if (ctx->end) {
		print_syscall_retval(ctx);
	}
}

/* 12 */
void print_syscall_brk(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(0x%08llx)", ctx->regs->rdi);
	}
	if (ctx->end) {
		printf(" = %p", (void *)ctx->regs->rax); // program break;
		if (ctx->regs->rax == -1)
			printf("(err)");
	}
}

/* 13 */
void print_syscall_rt_sigaction(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(");
		print_signal_string(ctx->regs->rdi);
		printf(", act, oldact, sigsetsize)");
	}
	if (ctx->end) {
		printf("(..");
		printf(", 0x%08llx", ctx->regs->rsi);
		printf(", 0x%08llx", ctx->regs->rdx);
		printf(", %d)", (int)ctx->regs->r10); // size_t sigsetsize

		print_syscall_retval(ctx);
	}
}

/* 14 */
void print_syscall_rt_sigprocmask(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(%d", (int)ctx->regs->rdi); // how
		printf(", 0x%08llx", ctx->regs->rsi); // sigset_t *set
		printf(", 0x%08llx)", ctx->regs->rdx); // sigset_t *oldset
	}
	if (ctx->end) {
		printf("(.., ..");
		printf(", 0x%08llx)", ctx->regs->rdx); // sigset_t *oldset

		print_syscall_retval(ctx);
	}
}

/* 15 */
void print_syscall_rt_sigreturn(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(...)"); // This system call should never be called.
	}
	if (ctx->end) {
		printf(" = %d", (int)ctx->regs->rax); // never returns.
	}
}

/* 16 */
void print_syscall_ioctl(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx", ctx->regs->rdi);
		printf(", %lu, ", (unsigned long)ctx->regs->rsi); // request
		printf(", %p)", (char *)ctx->regs->rdx); // argp
	}
	if (ctx->end) {
		print_syscall_retval(ctx); // return values vary according to the device question.
	}
}

/* 17 */
void print_syscall_pread64(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx", ctx->regs->rdi);
		printf(", ..");                             // buf
		printf(", %d", (int)ctx->regs->rdx); 		// size_t count
		printf(", %ld)", (long)ctx->regs->r10);   // off_t  offset
	}
	if (ctx->end) {
		printf("(.., ");
		print_syscall_arg_string(ctx->pid, ctx->regs->rsi);
		printf(", .., ..)");
		printf(" = %ld", (unsigned long)ctx->regs->rax);    // return value is ssize_t.
	}
}

/* 18 */
void print_syscall_pwrite64(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx, ", ctx->regs->rdi);
		print_syscall_arg_string(ctx->pid, ctx->regs->rsi); // buf
		printf(", %d", (int)ctx->regs->rdx); 		// size_t count
		printf(", %ld)", (long)ctx->regs->r10);   // off_t  offset
	}
	if (ctx->end) {
		printf("(.., .., ..)");
		printf(" = %ld", (unsigned long)ctx->regs->rax);    // return value is ssize_t.
	}
}

/* 19 */
void print_syscall_readv(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx, ", ctx->regs->rdi);
		printf("%p", (void *)ctx->regs->rsi);			 // struct iovec *iov
		printf(", %d)", (int)ctx->regs->rdx);   // int iovcnt
	}
	if (ctx->end) {
		printf("(.., .., ..)");
		printf(" = %ld", (unsigned long)ctx->regs->rax);    // return value is ssize_t.
	}
}

/* 20 */
void print_syscall_writev(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(fd:0x%08llx, ", ctx->regs->rdi);
		printf("%p", (void *)ctx->regs->rsi);	// struct iovec *iov
		printf(", %d)", (int)ctx->regs->rdx);   // int iovcnt
	}
	if (ctx->end) {
		printf("(.., .., ..)");
		printf(" = %ld", (unsigned long)ctx->regs->rax);    // return value is ssize_t.
	}
}

/* 21 */
void print_syscall_access(struct child_context *ctx)
{
	if (ctx->start) {
		paren_open();
		str_as(ctx->pid, ctx->regs->rdi);
		arg_sep();
		int_as(ctx->regs->rsi);
		paren_close();
	}
	if (ctx->end) {
		print_syscall_retval(ctx);
	}
}

/* 59 */
void print_syscall_execve(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(");
		print_syscall_arg_string(ctx->pid, ctx->regs->rdi);
		print_sep();
		print_syscall_argv_string(ctx->pid, (char **)ctx->regs->rsi);
		print_sep();
		print_syscall_argv_string(ctx->pid, (char **)ctx->regs->rdx);
		printf(")");
	}
	if (ctx->end) {
		print_syscall_retval(ctx);
	}
}

/* 257 */
void print_syscall_openat(struct child_context *ctx)
{
	if (ctx->start) {
		printf("(dir(0x%08llx), ", ctx->regs->rdi);
		print_syscall_arg_string(ctx->pid, ctx->regs->rsi);
		printf(", %d", (int)ctx->regs->rdx);
		printf(", %d)", (int)ctx->regs->r10); // mode_t mode
	}
	if (ctx->end) {
		print_syscall_retval(ctx);
	}
}

void print_syscall_args_retval(struct child_context *ctx)
{
	switch (ctx->regs->orig_rax) {
		case __NR_read /* 0 */: print_syscall_read(ctx); break;
		case __NR_write /* 1 */: print_syscall_write(ctx); break;
		case __NR_open /* 2 */: print_syscall_open(ctx); break;
		case __NR_close /* 3 */: print_syscall_close(ctx); break;
		case __NR_stat /* 4 */: print_syscall_stat(ctx); break;
		case __NR_fstat /* 5 */: print_syscall_fstat(ctx); break;
		case __NR_lstat /* 6 */: print_syscall_lstat(ctx); break;
		case __NR_poll /* 7 */:  print_syscall_poll(ctx); break;
		case __NR_lseek /* 8 */: print_syscall_lseek(ctx); break;
		case __NR_mmap /* 9 */:  print_syscall_mmap(ctx); break;
		case __NR_mprotect /* 10 */: print_syscall_mprotect(ctx); break;
		case __NR_munmap /* 11 */: print_syscall_munmap(ctx); break;
		case __NR_brk /* 12 */: print_syscall_brk(ctx); break;
		case __NR_rt_sigaction /* 13 */: print_syscall_rt_sigaction(ctx); break;
		case __NR_rt_sigprocmask /* 14 */: print_syscall_rt_sigprocmask(ctx); break;
		case __NR_rt_sigreturn /* 15 */: print_syscall_rt_sigreturn(ctx); break;
		case __NR_ioctl /* 16 */: print_syscall_ioctl(ctx); break;
		case __NR_pread64 /* 17 */: print_syscall_pread64(ctx); break;
		case __NR_pwrite64 /* 18 */: print_syscall_pwrite64(ctx); break;
		case __NR_readv /* 19 */: print_syscall_readv(ctx); break;
		case __NR_writev /* 20 */: print_syscall_writev(ctx); break;
		case __NR_access /* 21 */: print_syscall_access(ctx); break;
		case __NR_execve /* 59 */: print_syscall_execve(ctx); break;
		case __NR_openat /* 257 */: print_syscall_openat(ctx); break;
		default: print_syscall_args_retval_unimplemented(ctx); break;
	}
}
