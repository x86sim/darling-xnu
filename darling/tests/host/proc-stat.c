// sysctl_proc.c's /proc/<pid>/stat parsing: next_stat_elem()/skip_stat_elems() and load_proc()'s field walk, as
// run.sh extracts them from the source (proc-stat-extract.h, load-proc-body.inc), with a stand-in kinfo_proc.
// Linux prints comm raw between parentheses (fs/proc/array.c): it may hold spaces and ')' itself, so it ends at the
// line's LAST ')'. Fields after tty_nr: tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime (10),
// then priority and nice.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "check.h"

#define SRUN 2
#define SSLEEP 3
#define SSTOP 4
#define SZOMB 5
#define P_CONTROLT 0x2
#define KERN_PROC_SESSION 3
#define __simple_atoi(s, end) atoi(s)
#define darling_proc_name(pid, comm, dst, len) 0

struct kinfo_proc_chain {
	struct {
		struct { char p_comm[17]; int p_pid, p_stat, p_flag, p_priority, p_nice; } kp_proc;
		struct { int e_ppid, e_pgid, e_tdev; } kp_eproc;
	} kinfo;
};

#include "proc-stat-extract.h"

static int load(const char* line, struct kinfo_proc_chain* kinfo)
{
	static char stat[1024];
	char* statptr;
	const char* elem;
	int what = 0, flag = 0;

	memset(kinfo, 0, sizeof(*kinfo));
	strcpy(stat, line);
#include "load-proc-body.inc"
	return 0;
retnull:
	return -1;
}

int main(void)
{
	struct kinfo_proc_chain k;
	setvbuf(stdout, NULL, _IONBF, 0); // the lines before an AddressSanitizer abort
	const char* tail = " 4194560 11 0 0 0 5 3 0 0 21 -4 1 0 98765 1000 200";

	char line[512];
	snprintf(line, sizeof(line), "%s%s", "1234 (a) b (c)) S 1 1234 1234 34817 -1", tail);
	int r = load(line, &k);
	CHECK(r == 0, "comm with ') ' and '(': parsed (%d)", r);
	CHECK(strcmp(k.kinfo.kp_proc.p_comm, "a) b (c)") == 0, "comm is \"a) b (c)\" (got \"%s\")", k.kinfo.kp_proc.p_comm);
	CHECK(k.kinfo.kp_proc.p_stat == SSLEEP, "state S (got %d)", k.kinfo.kp_proc.p_stat);
	CHECK(k.kinfo.kp_eproc.e_ppid == 1, "ppid 1 (got %d)", k.kinfo.kp_eproc.e_ppid);
	CHECK(k.kinfo.kp_eproc.e_tdev == 34817, "tty_nr 34817 (got %d)", k.kinfo.kp_eproc.e_tdev);
	CHECK(k.kinfo.kp_proc.p_priority == 21, "priority 21, field 18 (got %d)", k.kinfo.kp_proc.p_priority);
	CHECK(k.kinfo.kp_proc.p_nice == -4, "nice -4, field 19 (got %d)", k.kinfo.kp_proc.p_nice);

	snprintf(line, sizeof(line), "%s%s", "77 (plain) R 5 77 77 0 -1", tail);
	r = load(line, &k);
	CHECK(r == 0 && strcmp(k.kinfo.kp_proc.p_comm, "plain") == 0 && k.kinfo.kp_proc.p_stat == SRUN
		&& k.kinfo.kp_eproc.e_ppid == 5 && k.kinfo.kp_proc.p_priority == 21,
		"plain comm: comm %s state %d ppid %d priority %d", k.kinfo.kp_proc.p_comm, k.kinfo.kp_proc.p_stat,
		k.kinfo.kp_eproc.e_ppid, k.kinfo.kp_proc.p_priority);

	snprintf(line, sizeof(line), "%s%s", "9 (a-name-longer-than-16) R 5 9 9 0 -1", tail);
	load(line, &k);
	CHECK(memchr(k.kinfo.kp_proc.p_comm, 0, sizeof(k.kinfo.kp_proc.p_comm)) != NULL,
		"long comm: p_comm NUL-terminated (\"%.17s\")", k.kinfo.kp_proc.p_comm);

	// the end of the line: the last field, then NULL, never past the NUL
	{
		char buf[] = "1 (x) Z";
		char* p = buf;
		const char *a = next_stat_elem(&p), *b = next_stat_elem(&p), *c = next_stat_elem(&p);
		const char* d = next_stat_elem(&p);
		CHECK(a && b && c && !strcmp(a, "1") && !strcmp(b, "x") && !strcmp(c, "Z") && d == NULL && p <= buf + 7,
			"\"1 (x) Z\": 1, x, Z, then NULL at the end");
	}
	{
		char buf[] = "1 (x)";
		char* p = buf;
		next_stat_elem(&p);
		const char* b = next_stat_elem(&p);
		const char* c = next_stat_elem(&p);
		CHECK(b && !strcmp(b, "x") && c == NULL && p <= buf + 5, "\"1 (x)\" (comm last): x, then NULL");
	}
	{
		// heap, exact size, so AddressSanitizer catches a read past the NUL
		char* buf = strdup("1 (unterminated");
		char* p = buf;
		next_stat_elem(&p);
		const char* b = next_stat_elem(&p);
		const char* c = b ? NULL : next_stat_elem(&p);
		CHECK(b == NULL && c == NULL && p <= buf + strlen("1 (unterminated"), "comm without ')': NULL, not past the NUL");
		free(buf);
	}
	DONE();
}
