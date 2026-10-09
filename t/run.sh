#!/bin/sh
# corex test suite. gdb is the oracle: for every fact corex prints about a
# core, gdb is asked the same question about the same core and the two answers
# are compared. readelf is the oracle for the ELF container itself.
set -u
cd "$(dirname "$0")/.." || exit 1
COREX=${COREX:-./corex}
S=scratch
mkdir -p $S || exit 1

pass=0; fail=0; skip=0
ok()   { printf 'ok    %s\n' "$1"; pass=$((pass+1)); }
no()   { printf 'FAIL  %s\n' "$1"; fail=$((fail+1)); }
skip() { printf 'skip  %s\n' "$1"; skip=$((skip+1)); }
nz()   { sed 's/0x0*\([0-9a-f]\)/0x\1/g'; }   # 0x0000ab -> 0xab, so hex widths do not matter
chk()  { if [ "$2" = "$3" ]; then ok "$1"; else no "$1: got [$2] want [$3]"; fi; }

CFL="-O0 -g -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -fno-inline"
gdbb() { gdb --batch -nx -iex 'set debuginfod enabled off' "$@"; }

# Generate a core from t/$1.c by letting it die under gdb and calling gcore on
# the stopped inferior. /proc/sys/kernel/core_pattern pipes to systemd-coredump
# here and cannot be changed without root, so gcore is the only way to get a
# core at all; see README.
gen() {
	n=$1; shift
	gcc $CFL $@ -o $S/$n t/$n.c || { no "build t/$n.c"; return 1; }
	rm -f $S/core.$n
	gdbb -ex run -ex "gcore $S/core.$n" $S/$n >$S/gen.$n.log 2>&1
	[ -s $S/core.$n ] || { no "gcore produced no core for $n"; return 1; }
	return 0
}

gen seg || exit 1
ok "gcore: wrote a core for t/seg.c ($(stat -c%s $S/core.seg) bytes)"

# -- the ELF container, against readelf ------------------------------------
want=$(readelf -lW $S/core.seg | sed -n 's/^There are \([0-9]*\) program headers.*/\1/p')
got=$($COREX --phdrs $S/core.seg | sed -n 's/^core:.* \([0-9]*\) program headers.*/\1/p')
chk "phdr count agrees with readelf ($want)" "$got" "$want"

readelf -lW $S/core.seg | awk '$1=="LOAD"{print $3,$5,$6}' | nz | sort > $S/re.load
$COREX --phdrs $S/core.seg | awk '$3=="PT_LOAD"{print $7,$9,$11}' | nz | sort > $S/cx.load
if cmp -s $S/re.load $S/cx.load; then
	ok "every PT_LOAD vaddr/filesz/memsz agrees with readelf ($(wc -l <$S/re.load | tr -d ' ') segments)"
else
	no "PT_LOAD table disagrees with readelf"; diff $S/re.load $S/cx.load | head -5
fi

# -- rejecting what is not a core ------------------------------------------
$COREX corex.c >/dev/null 2>$S/err; rc=$?
chk "a C source file is rejected (exit 1)" "$rc" "1"
grep -q 'not an ELF file' $S/err && ok "and says why" || no "no diagnostic for non-ELF input"
$COREX $S/seg >/dev/null 2>$S/err; rc=$?
chk "a live executable is rejected, it is not a core (exit 1)" "$rc" "1"

printf '\n%d passed, %d failed, %d skipped\n' $pass $fail $skip
[ $fail -eq 0 ]
