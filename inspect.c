#include "porder.h"

char *pid_to_proc_path(pid_t pid)
{
	static char path_buf[20];

	snprintf(path_buf, 20, "/proc/%d/maps", pid);
	return path_buf;
}

char *get_base_address(char *path_buf)
{
	static char procinfo_buf[16];

	int fd = open(path_buf, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "failed open proc file\n");
		exit(1);
	}

	ssize_t ok;
	char cur;
	int i = 0;
	while (i < 16) {
		if (cur == '-') {
			procinfo_buf[i-1] = '\0';
			break;
		}
		ok = read(fd, (procinfo_buf + i), 1);
		if (ok == -1) {
			fprintf(stderr, "failed reading proc file %s\n",
					path_buf);
			close(fd);
			exit(1);
		}
		cur = procinfo_buf[i];
		i++;
	}
	close(fd);

	return procinfo_buf;
}

long long int
get_child_mem_mapped_base_address(pid_t pid)
{
	char *path_buf = pid_to_proc_path(pid);
	char *proc_info = get_base_address(path_buf);

	char *endptr;
	long long int base_p = strtoll(proc_info, &endptr, 16);
	return base_p;
}

long long int
instruction_address_offset(long long unsigned int *addr, pid_t pid)
{
	static long long int base_p;
	static char once = 1;

	if (once) {
		once = 0;
		base_p = get_child_mem_mapped_base_address(pid);
		return 0;
	}

	return (*addr) - base_p;
}

long get_child_memory_data(pid_t pid, void *addr)
{
	errno = 0;
	long res = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
	if (errno != 0) {
		fprintf(stderr, "failed peeking child process's memory text. %s\n",
				strerror(errno));
		exit(1);
	}
	return res;
}

pid_t try_get_pid_forked_on_child(pid_t child_pid)
{
	unsigned long forked_pid;
	long res = ptrace(PTRACE_GETEVENTMSG, child_pid, NULL, &forked_pid);
	if (res == -1) {
		fprintf(stderr, "failed getting a pid of forked from child process. %s\n",
				strerror(errno));
		exit(1);
	}
	return (pid_t)forked_pid;
}

pid_t get_pid_forked_on_child(pid_t child_pid)
{
	int lim = 8;
	pid_t cc_pid = -1;

	while (lim > 0) {
		if (cc_pid != -1)
			break;
		cc_pid = try_get_pid_forked_on_child(child_pid);
		lim--;
	}
	return cc_pid;
}

int get_user_register(struct user_regs_struct *regs, pid_t pid)
{
	long res = ptrace(PTRACE_GETREGS, pid, NULL, regs);
	if (res == -1) {
		fprintf(stderr, "failed get user regs\n");
		return 0;
	}
	return 1;
}

void *deref_child_pointer(pid_t pid, void *ptr)
{
	return (void *)get_child_memory_data(pid, ptr);
}
