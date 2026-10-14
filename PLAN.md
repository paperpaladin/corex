# PLAN

## Contract

`corex [SECTION...] CORE` reads an ELF core dump for x86-64 Linux and reports
the state of the dead process:

- the signal that killed it, its `si_code` and the faulting address
  (`NT_SIGINFO`, with `NT_PRSTATUS.pr_info`/`pr_cursig` as the fallback)
- the 27 general-purpose registers of every thread (`NT_PRSTATUS`, one note
  per thread, in file order)
- process and thread ids, parent, process group, session, uid/gid, the
  command name and the process state (`NT_PRPSINFO`)
- the memory map: every `PT_LOAD` with its address range, permissions,
  whether its contents are present in the file, and which mapped file backs
  it (`NT_FILE`)
- the auxiliary vector (`NT_AUXV`), decoded
- the command line and the environment, recovered from the initial process
  stack
- a backtrace per thread from the frame-pointer chain
- `-x ADDR,LEN` hexdumps process memory out of the `PT_LOAD` segments

Sections: `--signal --proc --regs --threads --maps --files --auxv --cmdline
--notes --bt`, or all of them by default.

Pure C11 + gcc. No libelf, no libbfd, no libunwind, no libdwarf: the bytes are
parsed here. gdb is the test oracle and is never linked, called or required by
the program.

## Hard invariant

**Nothing corex prints may disagree with gdb reading the same core, and no
input may make corex crash, hang or read out of bounds.**

The first half is checked fact by fact: all 27 registers of every thread,
every backtrace frame address, the signal, the `si_code`, the faulting
address, the mapping list, the thread count and the thread ids. A single
register that gdb reads differently means corex is wrong.

The second half is checked by cutting a valid core at ~120 offsets, by a byte
mutation sweep, and by running the whole suite again under
`-fsanitize=address,undefined -fno-sanitize-recover=all`.

## Oracle

Ranked by how little we control them:

1. gdb (16.3, independent implementation, decades old) reading the same
   core file: `info registers`, `bt`, `info threads`, `info proc mappings`,
   `p $_siginfo`, `info auxv`, `x/` on memory, `info symbol` for naming our
   frame addresses. Authoritative for everything about process state.
2. readelf for the ELF container: program header count, and the vaddr /
   filesz / memsz of every `PT_LOAD`.
3. The source of the test programs. `t/seg.c` is a call chain exactly four
   deep; `t/buf.c` plants a 64 KiB buffer of known bytes on the stack and
   prints its address; `t/threads.c` parks three threads in three named
   functions. The right answer is known before any tool runs.
4. The kernel, for the thread ids: `t/threads.c` prints its own
   `gettid()` values, so the tid set in the core is checked against what the
   process itself said.

## Non-goals

- No DWARF. `dbginfo` (sibling repo) already parses debug info. Corex does
  not read it, so there are no source lines, no local variables, no inlined
  frames and no CFI-based unwinding.
- No symbol table reading. `prof` (sibling repo) already resolves addresses
  to names out of `.symtab`/`.dynsym`. Corex deliberately stops at
  `file+0xoffset`, which is what `NT_FILE` can tell you without opening
  another file. See README.
- x86-64 only, little-endian only, Linux only.
- No floating point / vector registers (`NT_FPREGSET`, `NT_X86_XSTATE` are
  listed by `--notes` and not decoded).
- Not a debugger: no reading a live process, no `ptrace`, no writing cores.

## Commit sequence

- [x] ELF header validation and the program header walk, against `readelf`
      - why: nothing else can be reached without the segment table, and
        `readelf -lW` settles it independently on commit one.
- [x] the PT_NOTE iterator and its 4-byte alignment rule
      - why: the single most common core-parsing bug is padding the name
        field wrong, and every remaining fact lives behind this loop.
- [x] NT_PRPSINFO: command, state, pid/ppid/pgrp/sid, uid/gid
      - why: the smallest fixed-layout note, so the struct offsets get a
        cheap first test before the 27-register one.
- [x] NT_PRSTATUS: registers and signal, compared with gdb register by register
      - why: the register set is the core's reason for existing. All 27 agree.
- [x] multiple threads: one NT_PRSTATUS per thread, count and order
      - why: getting the thread count or order wrong is easy and silent.
        This is where the oracle caught the pr_cursig assumption.
- [x] NT_AUXV, decoded
      - why: needed on its own, and it is the anchor that locates argv/envp.
- [x] NT_FILE: the mapped file list
      - why: this is what turns an address into a file and an offset.
- [x] the PT_LOAD map, p_filesz == 0 handling, and -x to read memory
      - why: memory that was mapped but not stored must read as absent, not
        as zeros.
- [x] the frame-pointer backtrace
      - why: the deliverable that makes the rest useful.
- [x] the command line and environment from the initial stack
      - why: no note carries them; they have to be found in memory.
- [x] a SIGABRT core: a signal with no faulting address
      - why: si_code SI_TKILL means the siginfo union holds a sender, not an
        address, and printing si_addr anyway gives a plausible lie. This is
        where the oracle caught the prefix-vs-subsequence assumption.
- [x] a 1000-frame stack: the unwinder terminates and agrees on the count
- [x] the truncation sweep and the byte mutation sweep
- [x] synthesised fixtures: p_filesz == 0, PN_XNUM, note name padding 1..8
- [x] `make test-asan`, `make valgrind`, exhaustive header bit flips
- [x] --all, the report order, and the exit codes
- [x] README and PLAN

Next, in order:

- [ ] run corex on a core this kernel wrote
      - why: the one gap the suite cannot close here. Every core in the suite
        comes from `gdb gcore`; `core_pattern` pipes to systemd-coredump,
        writing it needs real root (`unshare -r` does not help, it is not
        namespaced) and `coredumpctl` is absent. The p_filesz == 0 and
        PN_XNUM shapes are therefore synthesised, not observed. On a machine
        with root: `echo core > /proc/sys/kernel/core_pattern`, `ulimit -c
        unlimited`, and compare against the fixtures.
- [ ] decode NT_FPREGSET and NT_X86_XSTATE
      - why: `--notes` already lists them with their sizes, and gdb's `info
        all-registers` is sitting right there as the oracle for xmm/ymm. The
        x87 tag word and the XSAVE component offsets are the interesting part.
- [ ] a 32-bit (ELFCLASS32) core
      - why: currently rejected at the header, which is honest but narrow.
        `gcc -m32` plus a second `pr_reg` layout; the note format is identical,
        so this is mostly a second register map.
- [ ] sort the segment table once and binary-search it
      - why: the `shortcut:` comment in `seg_of()`. Only matters at PN_XNUM
        scale, which is also the only shape that cannot be tested here yet.
- [ ] report the thread whose `si_code` and `pr_info` disagree with
      `NT_SIGINFO`
      - why: a core where the two notes tell different stories is either a
        producer bug or a tampered file, and corex currently silently prefers
        NT_SIGINFO without saying the other said otherwise.
