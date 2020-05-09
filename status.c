#include "porder.h"

void init_syscall_status(syscall_status *s_status)
{
	s_status->exec_after = 0;
	s_status->in_syscall = 0;
}

void once_toggle_exec_status(syscall_status *s_status)
{
	if (s_status->exec_after == 0) 
		s_status->exec_after = 1;
}

int is_exec_after(syscall_status *s_status)
{
	int current_status = s_status->exec_after;

	once_toggle_exec_status(s_status);
	return current_status;
}

void toggle_syscall_status(syscall_status *s_status)
{
	if (s_status->in_syscall)
		s_status->in_syscall = 0;
	else
		s_status->in_syscall = 1;
}

int in_syscall(syscall_status *s_status)
{
	int current_status = s_status->in_syscall;

	toggle_syscall_status(s_status);
	return current_status;
}

int is_in_syscall(syscall_status *s_status)
{
	if (is_exec_after(s_status))
		return in_syscall(s_status);
	else
		return 0;
}

void trace_status_to_syscall(trace_step_status_t *ts_status)
{
	*ts_status = -1;
}

void trace_status_to_singlestep(trace_step_status_t *ts_status)
{
	*ts_status = 0;
}

int is_trace_status_on_syscall(trace_step_status_t *ts_status)
{
	return (*ts_status == -1);
}

int is_trace_status_on_singlestep(trace_step_status_t *ts_status)
{
	return (*ts_status == 0);
}
