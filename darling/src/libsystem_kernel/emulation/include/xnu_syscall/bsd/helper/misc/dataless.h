#ifndef X86SIM_DATALESS_H
#define X86SIM_DATALESS_H
// x86Sim: APFS dataless files and directories (SF_DATALESS) and their materialization (see helper/misc/dataless.c).
#include <stdint.h>

#define X86SIM_SF_DATALESS 0x40000000u

// After a successful open of Linux descriptor lfd (BSD open flags oflags): if the object is dataless and this thread
// materializes dataless files, have it materialized. 0 = nothing to do, 1 = materialized (open it again), or a negative
// BSD errno for the open to fail with.
long x86sim_dataless_fault_fd(int lfd, int oflags);

// An open failed ENOENT for Linux path lpath (relative to Linux descriptor ldfd unless absolute): if its parent
// directory is dataless and this thread materializes, have the directory materialized. 1 = materialized (retry the
// lookup), 0 = nothing to do, or a negative BSD errno.
long x86sim_dataless_fault_parent(int ldfd, const char* lpath);

// iopolicysys.c: whether the calling thread materializes dataless objects (IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES
// of the thread, else of the process); posix_spawn's child: the policy its spawn attributes gave it
int x86sim_dataless_policy_materializes(void);
void x86sim_dataless_spawned(int policy);

#endif
