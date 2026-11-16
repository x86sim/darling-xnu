// Syscall 416 (waitid_nocancel, XNU syscalls.master) through __bsd_syscall_table, into waitid.c, on Linux.
// Built with Darling's headers: siginfo_t and the W* options are Darwin's.
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include "check.h"

extern void* __bsd_syscall_table[600];
int host_spawn_gated(int* gate);
void host_release(int gate);
void* memset(void*, int, unsigned long);

typedef long (*waitid_f)(int idtype, int id, siginfo_t* si, int options);

int main(void)
{
	waitid_f nocancel = (waitid_f) __bsd_syscall_table[416], waitid = (waitid_f) __bsd_syscall_table[173];
	siginfo_t si;
	int gate;
	long ret;

	CHECK(waitid != 0, "syscall 173 (waitid) is in the table");
	CHECK(nocancel != 0, "syscall 416 (waitid_nocancel) is in the table");
	if (!nocancel)
		DONE();

	int child = host_spawn_gated(&gate);
	memset(&si, 0x5a, sizeof(si));
	ret = nocancel(P_PID, child, &si, WEXITED | WNOHANG | WNOWAIT);
	CHECK(ret == 0 && si.si_pid == 0, "WNOHANG, child running: 0 and si_pid 0 (ret %ld si_pid %d)", ret, si.si_pid);

	host_release(gate);
	memset(&si, 0x5a, sizeof(si));
	ret = nocancel(P_PID, child, &si, WEXITED | WNOWAIT);
	CHECK(ret == 0 && si.si_pid == child && si.si_signo == SIGCHLD && si.si_code == CLD_EXITED && si.si_status == 42,
		"WNOWAIT: pid %d signo %d code %d status %d", si.si_pid, si.si_signo, si.si_code, si.si_status);

	ret = waitid(P_PID, child, &si, WEXITED);
	CHECK(ret == 0 && si.si_pid == child && si.si_status == 42, "waitid (173) reaps it");
	ret = nocancel(P_PID, child, &si, WEXITED | WNOHANG);
	CHECK(ret == -ECHILD, "reaped: -ECHILD (%ld)", ret);
	DONE();
}
