#ifndef _SYSCTL_PROC_H
#define _SYSCTL_PROC_H

#include <stdbool.h>
#include <stdint.h>

// Utility functions for parsing Linux procfs /proc/XX/stat
bool read_string(const char* path, char* dst, int maxlen);
const char* next_stat_elem(char** buf);
void skip_stat_elems(char** buf, int count);
// x86Sim: the Darwin process name (p_comm/pbi_name) of a Darling process
bool darling_proc_name(int pid, const char* comm, char* dst, int maxlen);
bool proc_start_time(uint64_t starttime, uint64_t* sec, uint64_t* usec);

#endif // _SYSCTL_PROC_H
