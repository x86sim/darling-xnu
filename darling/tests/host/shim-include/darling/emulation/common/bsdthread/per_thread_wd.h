// Host-test stand-in: the real one reads the working directory from Darwin TSD (%gs), which Linux doesn't have.
// shim.c's get_perthread_wd() returns the directory the test chose.
#ifndef _PER_THREAD_WD_H
#define _PER_THREAD_WD_H

#include <darling/emulation/conversion/common_at.h>

int get_perthread_wd(void);

#endif
