#!/bin/sh
# Host tests for libsystem_kernel emulation fixes. Each builds the emulation's own sources for Linux, with Darling's
# headers (the flags libsystem_kernel builds with, minus the Darwin target) and shim.c standing in for what lies
# outside the files under test, and runs them against the real Linux kernel. proc-stat builds the parsing code
# extracted from sysctl_proc.c with the host's headers instead (load_proc() can't be built alone).
#
#   run.sh [rev] [test...]
#
# With a git revision (e.g. HEAD), that revision's emulation sources are tested instead of the working tree's: run
# both to see a fix fail before and pass after. Builds go to $XNU_HOST_TEST_DIR (default ${TMPDIR:-/tmp}/xnu-host-
# tests). Needs clang and Darling's SDK headers (external/darling/Developer/...), not a Darling build.

set -u
here=$(cd "$(dirname "$0")" && pwd)
xnu=$(cd "$here/../../.." && pwd)
darling=$(cd "$xnu/../../.." && pwd)
CC=${CC:-clang}

rev=
if [ $# -gt 0 ] && git -C "$xnu" rev-parse -q --verify "$1^{commit}" >/dev/null 2>&1; then
	rev=$1
	shift
fi
tests=${*:-proc-stat rlimit symlinkat waitid iflist2}

out=${XNU_HOST_TEST_DIR:-${TMPDIR:-/tmp}/xnu-host-tests}/${rev:-worktree}
rm -rf "$out"
mkdir -p "$out/inc/darling"
if [ -n "$rev" ]; then
	git -C "$xnu" archive "$rev" darling/src/libsystem_kernel/emulation | tar -x -C "$out"
	emu=$out/darling/src/libsystem_kernel/emulation
else
	emu=$xnu/darling/src/libsystem_kernel/emulation
fi
ln -s "$emu/include" "$out/inc/darling/emulation"
src=$emu/src

sdk=Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include
DFLAGS="-nostdinc -DDARLING -DDARWIN -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE -D__APPLE__ -D__APPLE_CC__=6000 -D__MACH__ \
	-I$here -I$here/shim-include -I$out/inc -I$darling/build/src/include -I$darling/src/include \
	-I$darling/basic-headers -I$darling/$sdk -I$darling/build/$sdk -I$xnu/darling/src/libsystem_kernel \
	-isystem $($CC -print-resource-dir)/include -Ulinux -Wno-error=implicit-function-declaration \
	-Wno-error=int-conversion -std=gnu99 -fno-builtin -fno-stack-protector -w -O1 -g"

# darling_cc <output.o> <source.c>: a source built as libsystem_kernel builds it, for Linux
darling_cc() {
	$CC $DFLAGS -c "$2" -o "$1"
}

build_proc_stat() {
	f=$src/xnu_syscall/bsd/helper/misc/sysctl_proc.c
	awk '/^const char\* next_stat_elem\(char\*\* buf\)/,0' "$f" | awk '{print} /^}/ {n++} n==2 {exit}' \
		>"$out/proc-stat-extract.h"
	awk '/^static struct kinfo_proc_chain\* load_proc\(/ {in_fn=1}
		in_fn && /statptr = stat;/ {p=1}
		p {print}
		p && /p_nice = / {exit}' "$f" >"$out/load-proc-body.inc"
	$CC -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -Wno-int-conversion -I"$out" -I"$here" \
		"$here/proc-stat.c" -o "$out/proc-stat"
}

build_rlimit() {
	darling_cc "$out/rlimit.o" "$here/rlimit.c" &&
	darling_cc "$out/getrlimit.o" "$src/xnu_syscall/bsd/impl/misc/getrlimit.c" &&
	darling_cc "$out/setrlimit.o" "$src/xnu_syscall/bsd/impl/misc/setrlimit.c" &&
	$CC -o "$out/rlimit" "$out/rlimit.o" "$out/getrlimit.o" "$out/setrlimit.o" "$out/errno.o" "$out/shim.o"
}

build_symlinkat() {
	darling_cc "$out/symlinkat-test.o" "$here/symlinkat.c" &&
	darling_cc "$out/symlinkat.o" "$src/xnu_syscall/bsd/impl/unistd/symlinkat.c" &&
	darling_cc "$out/common_at.o" "$src/xnu_syscall/bsd/helper/misc/common_at.c" &&
	$CC -o "$out/symlinkat" "$out/symlinkat-test.o" "$out/symlinkat.o" "$out/common_at.o" "$out/errno.o" \
		"$out/shim.o"
}

build_waitid() {
	darling_cc "$out/waitid-test.o" "$here/waitid.c" &&
	darling_cc "$out/waitid.o" "$src/xnu_syscall/bsd/impl/process/waitid.c" &&
	darling_cc "$out/wait4conv.o" "$src/conversion/process/wait4.c" &&
	darling_cc "$out/duct_signals.o" "$src/conversion/signal/duct_signals.c" &&
	darling_cc "$out/table.o" "$src/xnu_syscall/bsd/bsd_syscall_table.c" || return 1
	# every other syscall in the table: an empty stand-in
	objs="$out/waitid-test.o $out/waitid.o $out/wait4conv.o $out/duct_signals.o $out/table.o $out/errno.o $out/shim.o"
	nm --defined-only -j $objs 2>/dev/null | sort -u >"$out/defined"
	nm -u -j "$out/table.o" | sort -u | comm -23 - "$out/defined" | sed 's/.*/void &(void) {}/' >"$out/stubs.c"
	$CC -c "$out/stubs.c" -o "$out/stubs.o" &&
	$CC -o "$out/waitid" $objs "$out/stubs.o"
}

build_iflist2() {
	darling_cc "$out/iflist2.o" "$here/iflist2.c" &&
	darling_cc "$out/sysctl_net.o" "$src/xnu_syscall/bsd/helper/misc/sysctl_net.c" &&
	darling_cc "$out/ifinfo.o" "$src/xnu_syscall/bsd/helper/network/ifinfo.c" &&
	darling_cc "$out/rtnetlink.o" "$src/xnu_syscall/bsd/helper/network/rtnetlink.c" &&
	$CC -o "$out/iflist2" "$out/iflist2.o" "$out/sysctl_net.o" "$out/ifinfo.o" "$out/rtnetlink.o" "$out/errno.o" \
		"$out/shim.o"
}

$CC -g -O1 -c "$here/shim.c" -o "$out/shim.o" || exit 2
darling_cc "$out/errno.o" "$src/conversion/errno.c" || exit 2

failed=0
for t in $tests; do
	echo "== $t (${rev:-working tree})"
	fn=build_$(echo "$t" | tr - _)
	if ! $fn >"$out/$t.build.log" 2>&1; then
		echo "FAIL $t: build"
		sed 's/^/    /' "$out/$t.build.log" | head -20
		failed=1
		continue
	fi
	case $t in
		symlinkat) set -- "$out/symlinkat-dirs" ;;
		*) set -- ;;
	esac
	"$out/$t" "$@" 2>&1
	status=$?
	echo "-- $t: exit $status"
	[ $status -eq 0 ] || failed=1
done
exit $failed
