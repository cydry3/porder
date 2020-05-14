#include "porder.h"

void print_syscall_args(struct child_context *ctx);

void print_sig(int sig)
{
	printf("Child received signal %d\n", sig);
}

void print_pid(pid_t pid)
{
	printf("pid: %d ", pid);
}

void print_fork_context(struct child_context *ctx)
{
	printf("[");
	print_pid(ctx->pid);
	printf("] ");
}

void print_syscall_retval(struct child_context *ctx)
{
	if (ctx->regs->rax < 0) {
		printf(" = (err:0x%08llx)", ctx->regs->rax);
	} else {
		printf(" = (0x%08llx)", ctx->regs->rax);
	}
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

	print_syscall_args(ctx);

	if (ctx->end)
		print_syscall_retval(ctx);

	printf("\n");
}

void print_child_memory_data(pid_t pid, void *addr)
{
	long res = get_child_memory_data(pid, addr);
	printf("data: %08lx", res);
}

void print_instruction_on_child(pid_t pid)
{
	char rip_addr[16];
	struct user_regs_struct regs;

	if (get_user_register(&regs, pid)) {
		sprintf(rip_addr, "%llx\n", regs.rip);
		int ok = write(STDOUT_FILENO, rip_addr, strlen(rip_addr));
		if (ok == -1) {
			fprintf(stderr, "failed writeing to fd post printer\n");
			exit(1);
		}
	}
}

void print_syscall_name(struct child_context *ctx)
{
	printf("Syscall (");
	switch (ctx->regs->orig_rax) {
		case __NR_read /* 0 */: printf("read"); break;
		case __NR_write /* 1 */: printf("write"); break;
		case __NR_open /* 2 */: printf("open"); break;
		case __NR_close /* 3 */: printf("close"); break;
		case __NR_stat /* 4 */: printf("stat"); break;
		case __NR_fstat /* 5 */: printf("fstat"); break;
		case __NR_lstat /* 6 */: printf("lstat"); break;
		case __NR_poll /* 7 */: printf("poll"); break;
		case __NR_lseek /* 8 */: printf("lseek"); break;
		case __NR_mmap /* 9 */: printf("mmap"); break;
		case __NR_mprotect /* 10 */: printf("mprotect"); break;
		case __NR_munmap /* 11 */: printf("munmap"); break;
		case __NR_brk /* 12 */: printf("brk"); break;
		case __NR_rt_sigaction /* 13 */: printf("rt_sigaction"); break;
		case __NR_rt_sigprocmask /* 14 */: printf("rt_sigprocmask"); break;
		case __NR_rt_sigreturn /* 15 */: printf("rt_sigreturn"); break;
		case __NR_ioctl /* 16 */: printf("ioctl"); break;
		case __NR_pread64 /* 17 */: printf("pread64"); break;
		case __NR_pwrite64 /* 18 */: printf("pwrite64"); break;
		case __NR_readv /* 19 */: printf("readv"); break;
		case __NR_writev /* 20 */: printf("writev"); break;
		case __NR_access /* 21 */: printf("access"); break;
		case __NR_pipe /* 22 */: printf("pipe"); break;
		case __NR_select /* 23 */: printf("select"); break;
		case __NR_sched_yield /* 24 */: printf("sched_yield"); break;
		case __NR_mremap /* 25 */: printf("mremap"); break;
		case __NR_msync /* 26 */: printf("msync"); break;
		case __NR_mincore /* 27 */: printf("mincore"); break;
		case __NR_madvise /* 28 */: printf("madvise"); break;
		case __NR_shmget /* 29 */: printf("shmget"); break;
		case __NR_shmat /* 30 */: printf("shmat"); break;
		case __NR_shmctl /* 31 */: printf("shmctl"); break;
		case __NR_dup /* 32 */: printf("dup"); break;
		case __NR_dup2 /* 33 */: printf("dup2"); break;
		case __NR_pause /* 34 */: printf("pause"); break;
		case __NR_nanosleep /* 35 */: printf("nanosleep"); break;
		case __NR_getitimer /* 36 */: printf("getitimer"); break;
		case __NR_alarm /* 37 */: printf("alarm"); break;
		case __NR_setitimer /* 38 */: printf("setitimer"); break;
		case __NR_getpid /* 39 */: printf("getpid"); break;
		case __NR_sendfile /* 40 */: printf("sendfile"); break;
		case __NR_socket /* 41 */: printf("socket"); break;
		case __NR_connect /* 42 */: printf("connect"); break;
		case __NR_accept /* 43 */: printf("accept"); break;
		case __NR_sendto /* 44 */: printf("sendto"); break;
		case __NR_recvfrom /* 45 */: printf("recvfrom"); break;
		case __NR_sendmsg /* 46 */: printf("sendmsg"); break;
		case __NR_recvmsg /* 47 */: printf("recvmsg"); break;
		case __NR_shutdown /* 48 */: printf("shutdown"); break;
		case __NR_bind /* 49 */: printf("bind"); break;
		case __NR_listen /* 50 */: printf("listen"); break;
		case __NR_getsockname /* 51 */: printf("getsockname"); break;
		case __NR_getpeername /* 52 */: printf("getpeername"); break;
		case __NR_socketpair /* 53 */: printf("socketpair"); break;
		case __NR_setsockopt /* 54 */: printf("setsockopt"); break;
		case __NR_getsockopt /* 55 */: printf("getsockopt"); break;
		case __NR_clone /* 56 */: printf("clone"); break;
		case __NR_fork /* 57 */: printf("fork"); break;
		case __NR_vfork /* 58 */: printf("vfork"); break;
		case __NR_execve /* 59 */: printf("execve"); break;
		case __NR_exit /* 60 */: printf("exit"); break;
		case __NR_wait4 /* 61 */: printf("wait4"); break;
		case __NR_kill /* 62 */: printf("kill"); break;
		case __NR_uname /* 63 */: printf("uname"); break;
		case __NR_semget /* 64 */: printf("semget"); break;
		case __NR_semop /* 65 */: printf("semop"); break;
		case __NR_semctl /* 66 */: printf("semctl"); break;
		case __NR_shmdt /* 67 */: printf("shmdt"); break;
		case __NR_msgget /* 68 */: printf("msgget"); break;
		case __NR_msgsnd /* 69 */: printf("msgsnd"); break;
		case __NR_msgrcv /* 70 */: printf("msgrcv"); break;
		case __NR_msgctl /* 71 */: printf("msgctl"); break;
		case __NR_fcntl /* 72 */: printf("fcntl"); break;
		case __NR_flock /* 73 */: printf("flock"); break;
		case __NR_fsync /* 74 */: printf("fsync"); break;
		case __NR_fdatasync /* 75 */: printf("fdatasync"); break;
		case __NR_truncate /* 76 */: printf("truncate"); break;
		case __NR_ftruncate /* 77 */: printf("ftruncate"); break;
		case __NR_getdents /* 78 */: printf("getdents"); break;
		case __NR_getcwd /* 79 */: printf("getcwd"); break;
		case __NR_chdir /* 80 */: printf("chdir"); break;
		case __NR_fchdir /* 81 */: printf("fchdir"); break;
		case __NR_rename /* 82 */: printf("rename"); break;
		case __NR_mkdir /* 83 */: printf("mkdir"); break;
		case __NR_rmdir /* 84 */: printf("rmdir"); break;
		case __NR_creat /* 85 */: printf("creat"); break;
		case __NR_link /* 86 */: printf("link"); break;
		case __NR_unlink /* 87 */: printf("unlink"); break;
		case __NR_symlink /* 88 */: printf("symlink"); break;
		case __NR_readlink /* 89 */: printf("readlink"); break;
		case __NR_chmod /* 90 */: printf("chmod"); break;
		case __NR_fchmod /* 91 */: printf("fchmod"); break;
		case __NR_chown /* 92 */: printf("chown"); break;
		case __NR_fchown /* 93 */: printf("fchown"); break;
		case __NR_lchown /* 94 */: printf("lchown"); break;
		case __NR_umask /* 95 */: printf("umask"); break;
		case __NR_gettimeofday /* 96 */: printf("gettimeofday"); break;
		case __NR_getrlimit /* 97 */: printf("getrlimit"); break;
		case __NR_getrusage /* 98 */: printf("getrusage"); break;
		case __NR_sysinfo /* 99 */: printf("sysinfo"); break;
		case __NR_times /* 100 */: printf("times"); break;
		case __NR_ptrace /* 101 */: printf("ptrace"); break;
		case __NR_getuid /* 102 */: printf("getuid"); break;
		case __NR_syslog /* 103 */: printf("syslog"); break;
		case __NR_getgid /* 104 */: printf("getgid"); break;
		case __NR_setuid /* 105 */: printf("setuid"); break;
		case __NR_setgid /* 106 */: printf("setgid"); break;
		case __NR_geteuid /* 107 */: printf("geteuid"); break;
		case __NR_getegid /* 108 */: printf("getegid"); break;
		case __NR_setpgid /* 109 */: printf("setpgid"); break;
		case __NR_getppid /* 110 */: printf("getppid"); break;
		case __NR_getpgrp /* 111 */: printf("getpgrp"); break;
		case __NR_setsid /* 112 */: printf("setsid"); break;
		case __NR_setreuid /* 113 */: printf("setreuid"); break;
		case __NR_setregid /* 114 */: printf("setregid"); break;
		case __NR_getgroups /* 115 */: printf("getgroups"); break;
		case __NR_setgroups /* 116 */: printf("setgroups"); break;
		case __NR_setresuid /* 117 */: printf("setresuid"); break;
		case __NR_getresuid /* 118 */: printf("getresuid"); break;
		case __NR_setresgid /* 119 */: printf("setresgid"); break;
		case __NR_getresgid /* 120 */: printf("getresgid"); break;
		case __NR_getpgid /* 121 */: printf("getpgid"); break;
		case __NR_setfsuid /* 122 */: printf("setfsuid"); break;
		case __NR_setfsgid /* 123 */: printf("setfsgid"); break;
		case __NR_getsid /* 124 */: printf("getsid"); break;
		case __NR_capget /* 125 */: printf("capget"); break;
		case __NR_capset /* 126 */: printf("capset"); break;
		case __NR_rt_sigpending /* 127 */: printf("rt_sigpending"); break;
		case __NR_rt_sigtimedwait /* 128 */: printf("rt_sigtimedwait"); break;
		case __NR_rt_sigqueueinfo /* 129 */: printf("rt_sigqueueinfo"); break;
		case __NR_rt_sigsuspend /* 130 */: printf("rt_sigsuspend"); break;
		case __NR_sigaltstack /* 131 */: printf("sigaltstack"); break;
		case __NR_utime /* 132 */: printf("utime"); break;
		case __NR_mknod /* 133 */: printf("mknod"); break;
		case __NR_uselib /* 134 */: printf("uselib"); break;
		case __NR_personality /* 135 */: printf("personality"); break;
		case __NR_ustat /* 136 */: printf("ustat"); break;
		case __NR_statfs /* 137 */: printf("statfs"); break;
		case __NR_fstatfs /* 138 */: printf("fstatfs"); break;
		case __NR_sysfs /* 139 */: printf("sysfs"); break;
		case __NR_getpriority /* 140 */: printf("getpriority"); break;
		case __NR_setpriority /* 141 */: printf("setpriority"); break;
		case __NR_sched_setparam /* 142 */: printf("sched_setparam"); break;
		case __NR_sched_getparam /* 143 */: printf("sched_getparam"); break;
		case __NR_sched_setscheduler /* 144 */: printf("sched_setscheduler"); break;
		case __NR_sched_getscheduler /* 145 */: printf("sched_getscheduler"); break;
		case __NR_sched_get_priority_max /* 146 */: printf("sched_get_priority_max"); break;
		case __NR_sched_get_priority_min /* 147 */: printf("sched_get_priority_min"); break;
		case __NR_sched_rr_get_interval /* 148 */: printf("sched_rr_get_interval"); break;
		case __NR_mlock /* 149 */: printf("mlock"); break;
		case __NR_munlock /* 150 */: printf("munlock"); break;
		case __NR_mlockall /* 151 */: printf("mlockall"); break;
		case __NR_munlockall /* 152 */: printf("munlockall"); break;
		case __NR_vhangup /* 153 */: printf("vhangup"); break;
		case __NR_modify_ldt /* 154 */: printf("modify_ldt"); break;
		case __NR_pivot_root /* 155 */: printf("pivot_root"); break;
		case __NR__sysctl /* 156 */: printf("_sysctl"); break;
		case __NR_prctl /* 157 */: printf("prctl"); break;
		case __NR_arch_prctl /* 158 */: printf("arch_prctl"); break;
		case __NR_adjtimex /* 159 */: printf("adjtimex"); break;
		case __NR_setrlimit /* 160 */: printf("setrlimit"); break;
		case __NR_chroot /* 161 */: printf("chroot"); break;
		case __NR_sync /* 162 */: printf("sync"); break;
		case __NR_acct /* 163 */: printf("acct"); break;
		case __NR_settimeofday /* 164 */: printf("settimeofday"); break;
		case __NR_mount /* 165 */: printf("mount"); break;
		case __NR_umount2 /* 166 */: printf("umount2"); break;
		case __NR_swapon /* 167 */: printf("swapon"); break;
		case __NR_swapoff /* 168 */: printf("swapoff"); break;
		case __NR_reboot /* 169 */: printf("reboot"); break;
		case __NR_sethostname /* 170 */: printf("sethostname"); break;
		case __NR_setdomainname /* 171 */: printf("setdomainname"); break;
		case __NR_iopl /* 172 */: printf("iopl"); break;
		case __NR_ioperm /* 173 */: printf("ioperm"); break;
		case __NR_create_module /* 174 */: printf("create_module"); break;
		case __NR_init_module /* 175 */: printf("init_module"); break;
		case __NR_delete_module /* 176 */: printf("delete_module"); break;
		case __NR_get_kernel_syms /* 177 */: printf("get_kernel_syms"); break;
		case __NR_query_module /* 178 */: printf("query_module"); break;
		case __NR_quotactl /* 179 */: printf("quotactl"); break;
		case __NR_nfsservctl /* 180 */: printf("nfsservctl"); break;
		case __NR_getpmsg /* 181 */: printf("getpmsg"); break;
		case __NR_putpmsg /* 182 */: printf("putpmsg"); break;
		case __NR_afs_syscall /* 183 */: printf("afs_syscall"); break;
		case __NR_tuxcall /* 184 */: printf("tuxcall"); break;
		case __NR_security /* 185 */: printf("security"); break;
		case __NR_gettid /* 186 */: printf("gettid"); break;
		case __NR_readahead /* 187 */: printf("readahead"); break;
		case __NR_setxattr /* 188 */: printf("setxattr"); break;
		case __NR_lsetxattr /* 189 */: printf("lsetxattr"); break;
		case __NR_fsetxattr /* 190 */: printf("fsetxattr"); break;
		case __NR_getxattr /* 191 */: printf("getxattr"); break;
		case __NR_lgetxattr /* 192 */: printf("lgetxattr"); break;
		case __NR_fgetxattr /* 193 */: printf("fgetxattr"); break;
		case __NR_listxattr /* 194 */: printf("listxattr"); break;
		case __NR_llistxattr /* 195 */: printf("llistxattr"); break;
		case __NR_flistxattr /* 196 */: printf("flistxattr"); break;
		case __NR_removexattr /* 197 */: printf("removexattr"); break;
		case __NR_lremovexattr /* 198 */: printf("lremovexattr"); break;
		case __NR_fremovexattr /* 199 */: printf("fremovexattr"); break;
		case __NR_tkill /* 200 */: printf("tkill"); break;
		case __NR_time /* 201 */: printf("time"); break;
		case __NR_futex /* 202 */: printf("futex"); break;
		case __NR_sched_setaffinity /* 203 */: printf("sched_setaffinity"); break;
		case __NR_sched_getaffinity /* 204 */: printf("sched_getaffinity"); break;
		case __NR_set_thread_area /* 205 */: printf("set_thread_area"); break;
		case __NR_io_setup /* 206 */: printf("io_setup"); break;
		case __NR_io_destroy /* 207 */: printf("io_destroy"); break;
		case __NR_io_getevents /* 208 */: printf("io_getevents"); break;
		case __NR_io_submit /* 209 */: printf("io_submit"); break;
		case __NR_io_cancel /* 210 */: printf("io_cancel"); break;
		case __NR_get_thread_area /* 211 */: printf("get_thread_area"); break;
		case __NR_lookup_dcookie /* 212 */: printf("lookup_dcookie"); break;
		case __NR_epoll_create /* 213 */: printf("epoll_create"); break;
		case __NR_epoll_ctl_old /* 214 */: printf("epoll_ctl_old"); break;
		case __NR_epoll_wait_old /* 215 */: printf("epoll_wait_old"); break;
		case __NR_remap_file_pages /* 216 */: printf("remap_file_pages"); break;
		case __NR_getdents64 /* 217 */: printf("getdents64"); break;
		case __NR_set_tid_address /* 218 */: printf("set_tid_address"); break;
		case __NR_restart_syscall /* 219 */: printf("restart_syscall"); break;
		case __NR_semtimedop /* 220 */: printf("semtimedop"); break;
		case __NR_fadvise64 /* 221 */: printf("fadvise64"); break;
		case __NR_timer_create /* 222 */: printf("timer_create"); break;
		case __NR_timer_settime /* 223 */: printf("timer_settime"); break;
		case __NR_timer_gettime /* 224 */: printf("timer_gettime"); break;
		case __NR_timer_getoverrun /* 225 */: printf("timer_getoverrun"); break;
		case __NR_timer_delete /* 226 */: printf("timer_delete"); break;
		case __NR_clock_settime /* 227 */: printf("clock_settime"); break;
		case __NR_clock_gettime /* 228 */: printf("clock_gettime"); break;
		case __NR_clock_getres /* 229 */: printf("clock_getres"); break;
		case __NR_clock_nanosleep /* 230 */: printf("clock_nanosleep"); break;
		case __NR_exit_group /* 231 */: printf("exit_group"); break;
		case __NR_epoll_wait /* 232 */: printf("epoll_wait"); break;
		case __NR_epoll_ctl /* 233 */: printf("epoll_ctl"); break;
		case __NR_tgkill /* 234 */: printf("tgkill"); break;
		case __NR_utimes /* 235 */: printf("utimes"); break;
		case __NR_vserver /* 236 */: printf("vserver"); break;
		case __NR_mbind /* 237 */: printf("mbind"); break;
		case __NR_set_mempolicy /* 238 */: printf("set_mempolicy"); break;
		case __NR_get_mempolicy /* 239 */: printf("get_mempolicy"); break;
		case __NR_mq_open /* 240 */: printf("mq_open"); break;
		case __NR_mq_unlink /* 241 */: printf("mq_unlink"); break;
		case __NR_mq_timedsend /* 242 */: printf("mq_timedsend"); break;
		case __NR_mq_timedreceive /* 243 */: printf("mq_timedreceive"); break;
		case __NR_mq_notify /* 244 */: printf("mq_notify"); break;
		case __NR_mq_getsetattr /* 245 */: printf("mq_getsetattr"); break;
		case __NR_kexec_load /* 246 */: printf("kexec_load"); break;
		case __NR_waitid /* 247 */: printf("waitid"); break;
		case __NR_add_key /* 248 */: printf("add_key"); break;
		case __NR_request_key /* 249 */: printf("request_key"); break;
		case __NR_keyctl /* 250 */: printf("keyctl"); break;
		case __NR_ioprio_set /* 251 */: printf("ioprio_set"); break;
		case __NR_ioprio_get /* 252 */: printf("ioprio_get"); break;
		case __NR_inotify_init /* 253 */: printf("inotify_init"); break;
		case __NR_inotify_add_watch /* 254 */: printf("inotify_add_watch"); break;
		case __NR_inotify_rm_watch /* 255 */: printf("inotify_rm_watch"); break;
		case __NR_migrate_pages /* 256 */: printf("migrate_pages"); break;
		case __NR_openat /* 257 */: printf("openat"); break;
		case __NR_mkdirat /* 258 */: printf("mkdirat"); break;
		case __NR_mknodat /* 259 */: printf("mknodat"); break;
		case __NR_fchownat /* 260 */: printf("fchownat"); break;
		case __NR_futimesat /* 261 */: printf("futimesat"); break;
		case __NR_newfstatat /* 262 */: printf("newfstatat"); break;
		case __NR_unlinkat /* 263 */: printf("unlinkat"); break;
		case __NR_renameat /* 264 */: printf("renameat"); break;
		case __NR_linkat /* 265 */: printf("linkat"); break;
		case __NR_symlinkat /* 266 */: printf("symlinkat"); break;
		case __NR_readlinkat /* 267 */: printf("readlinkat"); break;
		case __NR_fchmodat /* 268 */: printf("fchmodat"); break;
		case __NR_faccessat /* 269 */: printf("faccessat"); break;
		case __NR_pselect6 /* 270 */: printf("pselect6"); break;
		case __NR_ppoll /* 271 */: printf("ppoll"); break;
		case __NR_unshare /* 272 */: printf("unshare"); break;
		case __NR_set_robust_list /* 273 */: printf("set_robust_list"); break;
		case __NR_get_robust_list /* 274 */: printf("get_robust_list"); break;
		case __NR_splice /* 275 */: printf("splice"); break;
		case __NR_tee /* 276 */: printf("tee"); break;
		case __NR_sync_file_range /* 277 */: printf("sync_file_range"); break;
		case __NR_vmsplice /* 278 */: printf("vmsplice"); break;
		case __NR_move_pages /* 279 */: printf("move_pages"); break;
		case __NR_utimensat /* 280 */: printf("utimensat"); break;
		case __NR_epoll_pwait /* 281 */: printf("epoll_pwait"); break;
		case __NR_signalfd /* 282 */: printf("signalfd"); break;
		case __NR_timerfd_create /* 283 */: printf("timerfd_create"); break;
		case __NR_eventfd /* 284 */: printf("eventfd"); break;
		case __NR_fallocate /* 285 */: printf("fallocate"); break;
		case __NR_timerfd_settime /* 286 */: printf("timerfd_settime"); break;
		case __NR_timerfd_gettime /* 287 */: printf("timerfd_gettime"); break;
		case __NR_accept4 /* 288 */: printf("accept4"); break;
		case __NR_signalfd4 /* 289 */: printf("signalfd4"); break;
		case __NR_eventfd2 /* 290 */: printf("eventfd2"); break;
		case __NR_epoll_create1 /* 291 */: printf("epoll_create1"); break;
		case __NR_dup3 /* 292 */: printf("dup3"); break;
		case __NR_pipe2 /* 293 */: printf("pipe2"); break;
		case __NR_inotify_init1 /* 294 */: printf("inotify_init1"); break;
		case __NR_preadv /* 295 */: printf("preadv"); break;
		case __NR_pwritev /* 296 */: printf("pwritev"); break;
		case __NR_rt_tgsigqueueinfo /* 297 */: printf("rt_tgsigqueueinfo"); break;
		case __NR_perf_event_open /* 298 */: printf("perf_event_open"); break;
		case __NR_recvmmsg /* 299 */: printf("recvmmsg"); break;
		case __NR_fanotify_init /* 300 */: printf("fanotify_init"); break;
		case __NR_fanotify_mark /* 301 */: printf("fanotify_mark"); break;
		case __NR_prlimit64 /* 302 */: printf("prlimit64"); break;
		case __NR_name_to_handle_at /* 303 */: printf("name_to_handle_at"); break;
		case __NR_open_by_handle_at /* 304 */: printf("open_by_handle_at"); break;
		case __NR_clock_adjtime /* 305 */: printf("clock_adjtime"); break;
		case __NR_syncfs /* 306 */: printf("syncfs"); break;
		case __NR_sendmmsg /* 307 */: printf("sendmmsg"); break;
		case __NR_setns /* 308 */: printf("setns"); break;
		case __NR_getcpu /* 309 */: printf("getcpu"); break;
		case __NR_process_vm_readv /* 310 */: printf("process_vm_readv"); break;
		case __NR_process_vm_writev /* 311 */: printf("process_vm_writev"); break;
		case __NR_kcmp /* 312 */: printf("kcmp"); break;
		case __NR_finit_module /* 313 */: printf("finit_module"); break;
		case __NR_sched_setattr /* 314 */: printf("sched_setattr"); break;
		case __NR_sched_getattr /* 315 */: printf("sched_getattr"); break;
		case __NR_renameat2 /* 316 */: printf("renameat2"); break;
		case __NR_seccomp /* 317 */: printf("seccomp"); break;
		case __NR_getrandom /* 318 */: printf("getrandom"); break;
		case __NR_memfd_create /* 319 */: printf("memfd_create"); break;
		case __NR_kexec_file_load /* 320 */: printf("kexec_file_load"); break;
		case __NR_bpf /* 321 */: printf("bpf"); break;
		case __NR_execveat /* 322 */: printf("execveat"); break;
		case __NR_userfaultfd /* 323 */: printf("userfaultfd"); break;
		case __NR_membarrier /* 324 */: printf("membarrier"); break;
		case __NR_mlock2 /* 325 */: printf("mlock2"); break;
		case __NR_copy_file_range /* 326 */: printf("copy_file_range"); break;
		case __NR_preadv2 /* 327 */: printf("preadv2"); break;
		case __NR_pwritev2 /* 328 */: printf("pwritev2"); break;
		case __NR_pkey_mprotect /* 329 */: printf("pkey_mprotect"); break;
		case __NR_pkey_alloc /* 330 */: printf("pkey_alloc"); break;
		case __NR_pkey_free /* 331 */: printf("pkey_free"); break;
		case __NR_statx /* 332 */: printf("statx"); break;
		case __NR_io_pgetevents /* 333 */: printf("io_pgetevents"); break;
		case __NR_rseq /* 334 */: printf("rseq"); break;
		default: break;
	}
	printf(")");
}

void print_syscall_args_default(struct child_context *ctx)
{
	printf("0x%08llx, 0x%08llx, 0x%08llx",
			ctx->regs->rdi, ctx->regs->rsi, ctx->regs->rdx);
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

void print_syscall_argv_string(pid_t pid, char **ptr)
{
		printf(", [");
		while (*ptr != NULL) {
			print_syscall_arg_string(pid, (long long unsigned int)*ptr);
			ptr++;
			if (*ptr == NULL)
				break;
			else
				printf(", ");
		}
		printf("], ");
}

void print_syscall_openat(struct child_context *ctx)
{
	if (ctx->start) {
		printf("0x%08llx, ", ctx->regs->rdi);
		print_syscall_arg_string(ctx->pid, ctx->regs->rsi);
		printf(", 0x%08llx", ctx->regs->rdx);
	}
}

void print_syscall_open(struct child_context *ctx)
{
	if (ctx->start) {
		print_syscall_arg_string(ctx->pid, ctx->regs->rdi);
		printf(", 0x%08llx", ctx->regs->rsi);
		printf(", 0x%08llx", ctx->regs->rdx);
	}
}

void print_syscall_execve(struct child_context *ctx)
{
	if (ctx->start) {
		print_syscall_arg_string(ctx->pid, ctx->regs->rdi);
		print_syscall_argv_string(ctx->pid, (char **)ctx->regs->rsi);
		printf("0x%08llx", ctx->regs->rdx);
	}
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

void print_syscall_fstat(struct child_context *ctx)
{
	if (ctx->end) {
		if (ctx->verbose) {
			print_syscall_stat_verbose_retval(ctx);
		} else {
			printf("0x%08llx", ctx->regs->rsi);
		}
	}
}

void print_syscall_stat(struct child_context *ctx)
{
	if (ctx->start) {
		print_syscall_arg_string(ctx->pid, ctx->regs->rdi);
		printf("0x%08llx", ctx->regs->rdx);
	}
	print_syscall_fstat(ctx);
}

void print_syscall_lstat(struct child_context *ctx)
{
	print_syscall_stat(ctx);
}

void print_syscall_write(struct child_context *ctx)
{
	if (ctx->start) {
		printf("0x%08llx, ", ctx->regs->rdi);
		print_syscall_arg_string(ctx->pid, ctx->regs->rsi);
		printf(", 0x%08llx", ctx->regs->rdx);
	}
}

void print_syscall_read(struct child_context *ctx)
{
	if (ctx->end) {
		printf("0x%08llx, ", ctx->regs->rdi);
		print_syscall_arg_string(ctx->pid, ctx->regs->rsi);
		printf(", 0x%08llx", ctx->regs->rdx);
	}
}

void print_syscall_args(struct child_context *ctx)
{
	printf("(");
	switch (ctx->regs->orig_rax) {
		case __NR_read /* 0 */: print_syscall_read(ctx); break;
		case __NR_write /* 1 */: print_syscall_write(ctx); break;
		case __NR_open /* 2 */: print_syscall_open(ctx); break;
		case __NR_stat /* 4 */: print_syscall_stat(ctx); break;
		case __NR_fstat /* 5 */: print_syscall_fstat(ctx); break;
		case __NR_lstat /* 6 */: print_syscall_lstat(ctx); break;
		case __NR_execve /* 59 */: print_syscall_execve(ctx); break;
		case __NR_openat /* 257 */: print_syscall_openat(ctx); break;
		default: print_syscall_args_default(ctx); break;
	}
	printf(")");
}

void print_sigtrap_by_other_process(struct child_context *ctx)
{
	if (is_fork_context(ctx))
		print_fork_context(ctx);
	printf("Received signal(%d)\n", ctx->signum);
}
