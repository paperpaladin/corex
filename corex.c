/* corex -- read an ELF core dump: signal, registers, memory map, threads,
 * command line, auxiliary vector, backtrace.
 *
 * Everything is parsed from the raw bytes. No libelf, no libbfd, no
 * libunwind. x86-64 little-endian cores only, read on an x86-64
 * little-endian host, which is what lets the integer loads below be plain
 * memcpy of native words.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* ELF constants, spelled out so that <elf.h> is not needed. */
#define ET_CORE		4
#define EM_X86_64	62
#define PT_LOAD		1
#define PT_NOTE		4
#define PF_X		1
#define PF_W		2
#define PF_R		4
#define PN_XNUM		0xffff

#define EHDR_SZ		64
#define PHDR_SZ		56
#define SHDR_SZ		64

static const uint8_t *B;	/* the whole core file, mapped read-only */
static size_t N;		/* its length in bytes */
static const char *cpath;

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "corex: %s: ", cpath ? cpath : "?");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

/* Every read of the core file goes through in_file()/at(). An offset or a
 * length out of the mapping is a malformed core, never a segfault: this is
 * the single place that decides it, so there is one rule rather than a
 * bounds check per call site. The subtraction form cannot overflow. */
static int in_file(uint64_t off, uint64_t len)
{
	return len <= N && off <= (uint64_t)N - len;
}

static const uint8_t *at(uint64_t off, uint64_t len)
{
	return in_file(off, len) ? B + off : NULL;
}

static uint64_t u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static uint32_t u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint16_t u16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }

/* ---- program headers ---------------------------------------------------- */

struct seg {
	uint32_t type, flags;
	uint64_t off, vaddr, filesz, memsz, align;
};

static struct seg *segs;
static unsigned nsegs;

static void load_phdrs(void)
{
	const uint8_t *e = at(0, EHDR_SZ);
	if (!e)
		die("too short to be an ELF file (%zu bytes)", N);
	if (memcmp(e, "\177ELF", 4))
		die("not an ELF file (bad magic)");
	if (e[4] != 2)
		die("not ELFCLASS64 (EI_CLASS=%u)", e[4]);
	if (e[5] != 1)
		die("not little-endian (EI_DATA=%u)", e[5]);
	if (u16(e + 16) != ET_CORE)
		die("not a core file (e_type=%u, want %u)", u16(e + 16), ET_CORE);
	if (u16(e + 18) != EM_X86_64)
		die("not x86-64 (e_machine=%u)", u16(e + 18));

	uint64_t phoff = u64(e + 32);
	unsigned phentsize = u16(e + 54), phnum = u16(e + 56);
	if (phentsize != PHDR_SZ)
		die("e_phentsize is %u, want %u", phentsize, PHDR_SZ);

	/* A core with more than 65534 mappings sets e_phnum to PN_XNUM and
	 * keeps the real count in section header 0's sh_info. Kernel cores of
	 * a process with a huge map really do this. */
	uint64_t count = phnum;
	if (phnum == PN_XNUM) {
		uint64_t shoff = u64(e + 40);
		if (u16(e + 58) != SHDR_SZ)
			die("e_phnum is PN_XNUM but e_shentsize is %u", u16(e + 58));
		const uint8_t *s = at(shoff, SHDR_SZ);
		if (!s)
			die("e_phnum is PN_XNUM but section header 0 is out of range");
		count = u32(s + 44);		/* sh_info */
	}
	if (count == 0)
		die("no program headers");
	if (!in_file(phoff, count * PHDR_SZ))
		die("program header table (%" PRIu64 " entries at 0x%" PRIx64
		    ") runs past end of file (%zu bytes)", count, phoff, N);

	nsegs = count;
	segs = calloc(nsegs, sizeof *segs);
	if (!segs)
		die("out of memory");
	for (unsigned i = 0; i < nsegs; i++) {
		const uint8_t *p = B + phoff + (uint64_t)i * PHDR_SZ;
		segs[i].type = u32(p);
		segs[i].flags = u32(p + 4);
		segs[i].off = u64(p + 8);
		segs[i].vaddr = u64(p + 16);
		segs[i].filesz = u64(p + 32);
		segs[i].memsz = u64(p + 40);
		segs[i].align = u64(p + 48);
	}
}

static const char *perms(uint32_t f, char *b)
{
	b[0] = (f & PF_R) ? 'r' : '-';
	b[1] = (f & PF_W) ? 'w' : '-';
	b[2] = (f & PF_X) ? 'x' : '-';
	b[3] = 0;
	return b;
}

static void show_segs(void)
{
	unsigned nload = 0, nnote = 0;
	for (unsigned i = 0; i < nsegs; i++) {
		if (segs[i].type == PT_LOAD) nload++;
		if (segs[i].type == PT_NOTE) nnote++;
	}
	printf("core: %s %zu bytes, %u program headers (%u PT_LOAD, %u PT_NOTE)\n",
	       cpath, N, nsegs, nload, nnote);
	char p[4];
	for (unsigned i = 0; i < nsegs; i++)
		printf("phdr %u %s off 0x%" PRIx64 " vaddr 0x%" PRIx64
		       " filesz 0x%" PRIx64 " memsz 0x%" PRIx64 " %s\n",
		       i,
		       segs[i].type == PT_LOAD ? "PT_LOAD" :
		       segs[i].type == PT_NOTE ? "PT_NOTE" : "other",
		       segs[i].off, segs[i].vaddr, segs[i].filesz, segs[i].memsz,
		       perms(segs[i].flags, p));
}

/* ---- the PT_NOTE iterator ----------------------------------------------
 *
 * A note is three 32-bit words (namesz, descsz, type), then the name padded
 * to a 4-byte boundary, then the descriptor padded to a 4-byte boundary. The
 * padding is the trap: it is 4 bytes in a 64-bit core even though the PT_NOTE
 * segment's p_align may say 8, and the pad after the *name* is the field
 * everyone forgets. Get it wrong and the first note still parses, which is
 * why the bug survives -- the notes after it decode as garbage or vanish.
 * The test for this is the whole note list compared against readelf -n: a
 * desynced iterator cannot reach the last note.
 */

#define NT_PRSTATUS	1
#define NT_PRFPREG	2
#define NT_PRPSINFO	3
#define NT_TASKSTRUCT	4
#define NT_AUXV		6
#define NT_SIGINFO	0x53494749
#define NT_FILE		0x46494c45
#define NT_PRXFPREG	0x46e62b7f
#define NT_X86_XSTATE	0x202
#define NT_GDB_TDESC	0xff000000

struct note {
	uint32_t type;
	const char *name;	/* not necessarily NUL-terminated: use namesz */
	uint32_t namesz;
	const uint8_t *desc;
	uint64_t descsz;
};

static struct note *notes;
static unsigned nnotes;

static uint64_t align4(uint64_t v)
{
	return (v + 3) & ~(uint64_t)3;
}

static int nameis(const struct note *n, const char *s)
{
	size_t l = strlen(s);
	/* namesz counts the NUL when there is one, and some producers omit it */
	return (n->namesz == l || n->namesz == l + 1) && !memcmp(n->name, s, l);
}

static void load_notes(void)
{
	for (unsigned i = 0; i < nsegs; i++) {
		if (segs[i].type != PT_NOTE)
			continue;
		if (!in_file(segs[i].off, segs[i].filesz))
			die("PT_NOTE segment %u (0x%" PRIx64 " bytes at 0x%" PRIx64
			    ") runs past end of file (%zu bytes)",
			    i, segs[i].filesz, segs[i].off, N);
		uint64_t p = segs[i].off, end = p + segs[i].filesz;
		while (p + 12 <= end) {
			uint32_t namesz = u32(B + p);
			uint32_t descsz = u32(B + p + 4);
			uint32_t type = u32(B + p + 8);
			uint64_t npad = align4(namesz), dpad = align4(descsz);
			/* 12 + npad + dpad cannot overflow: both are u32 widened */
			if (p + 12 + npad + dpad > end)
				die("note %u at 0x%" PRIx64 " (namesz %u descsz %u) "
				    "runs past the end of its PT_NOTE segment",
				    nnotes, p, namesz, descsz);
			notes = realloc(notes, (nnotes + 1) * sizeof *notes);
			if (!notes)
				die("out of memory");
			notes[nnotes].type = type;
			notes[nnotes].name = (const char *)B + p + 12;
			notes[nnotes].namesz = namesz;
			notes[nnotes].desc = B + p + 12 + npad;
			notes[nnotes].descsz = descsz;
			nnotes++;
			p += 12 + npad + dpad;
		}
		if (p != end)
			die("PT_NOTE segment %u has %" PRIu64 " trailing bytes",
			    i, end - p);
	}
	if (!nnotes)
		die("no notes: a core without PT_NOTE has no process state in it");
}

static const char *ntype(uint32_t t)
{
	switch (t) {
	case NT_PRSTATUS:	return "NT_PRSTATUS";
	case NT_PRFPREG:	return "NT_FPREGSET";
	case NT_PRPSINFO:	return "NT_PRPSINFO";
	case NT_TASKSTRUCT:	return "NT_TASKSTRUCT";
	case NT_AUXV:		return "NT_AUXV";
	case NT_SIGINFO:	return "NT_SIGINFO";
	case NT_FILE:		return "NT_FILE";
	case NT_PRXFPREG:	return "NT_PRXFPREG";
	case NT_X86_XSTATE:	return "NT_X86_XSTATE";
	case NT_GDB_TDESC:	return "NT_GDB_TDESC";
	default:		return NULL;
	}
}

static void show_notes(void)
{
	for (unsigned i = 0; i < nnotes; i++) {
		const char *t = ntype(notes[i].type);
		printf("note %.*s 0x%" PRIx64 " ", (int)notes[i].namesz,
		       notes[i].name, notes[i].descsz);
		if (t)
			printf("%s\n", t);
		else
			printf("0x%" PRIx32 "\n", notes[i].type);
	}
}

/* ---- NT_PRPSINFO: the process, as ps would describe it ------------------
 *
 * struct elf_prpsinfo, 136 bytes, the same layout the kernel writes and gdb
 * writes. Read by explicit offset rather than by casting to a struct, because
 * the point of this program is to not depend on a header agreeing with the
 * producer of the file.
 */
#define PRPSINFO_SZ	136

static const struct note *find_note(uint32_t type, unsigned skip)
{
	for (unsigned i = 0; i < nnotes; i++)
		if (notes[i].type == type && nameis(&notes[i], "CORE"))
			if (skip-- == 0)
				return &notes[i];
	return NULL;
}

/* A fixed-size char array in a note is not required to be NUL-terminated:
 * print at most n bytes and stop at the first NUL. */
static void put_fixed(const char *tag, const uint8_t *p, size_t n)
{
	size_t l = 0;
	while (l < n && p[l])
		l++;
	printf("%s %.*s\n", tag, (int)l, (const char *)p);
}

static const char *state_name(char c)
{
	switch (c) {
	case 'R': return "running";
	case 'S': return "sleeping";
	case 'D': return "disk sleep";
	case 'T': return "stopped";
	case 't': return "tracing stop";
	case 'Z': return "zombie";
	case 'X': return "dead";
	case 'I': return "idle";
	default:  return "unknown";
	}
}

static void show_prpsinfo(void)
{
	const struct note *n = find_note(NT_PRPSINFO, 0);
	if (!n) {
		printf("proc: no NT_PRPSINFO note\n");
		return;
	}
	if (n->descsz < PRPSINFO_SZ)
		die("NT_PRPSINFO is %" PRIu64 " bytes, want at least %u",
		    n->descsz, PRPSINFO_SZ);
	const uint8_t *d = n->desc;
	printf("proc: pid %" PRId32 " ppid %" PRId32 " pgrp %" PRId32
	       " sid %" PRId32 " uid %" PRIu32 " gid %" PRIu32 "\n",
	       (int32_t)u32(d + 24), (int32_t)u32(d + 28), (int32_t)u32(d + 32),
	       (int32_t)u32(d + 36), u32(d + 16), u32(d + 20));
	printf("state: %c (%s) nice %d\n", d[1] ? d[1] : '?',
	       state_name((char)d[1]), (int)(int8_t)d[3]);
	put_fixed("cmd:", d + 40, 16);
	put_fixed("psargs:", d + 56, 80);
}

/* ---- NT_PRSTATUS: registers, one note per thread -------------------------
 *
 * struct elf_prstatus, 336 bytes:
 *
 *   0  struct elf_siginfo pr_info  { int si_signo, si_code, si_errno; }
 *   12 short pr_cursig            (then 2 bytes of padding)
 *   16 unsigned long pr_sigpend
 *   24 unsigned long pr_sighold
 *   32 pid_t pr_pid, pr_ppid, pr_pgrp, pr_sid
 *   48 struct timeval pr_utime, pr_stime, pr_cutime, pr_cstime  (4 x 16)
 *   112 elf_gregset_t pr_reg      (27 x 8 = 216 bytes)
 *   328 int pr_fpvalid
 *
 * pr_pid is really the *thread* id (the kernel writes task->pid, which is the
 * tid); the thread-group id is NT_PRPSINFO's pr_pid. One NT_PRSTATUS per
 * thread, in the order the kernel walked the thread list, with the thread
 * that took the signal first.
 */
#define PRSTATUS_SZ	336
#define NGREG		27

struct thread {
	int32_t pid, ppid, pgrp, sid;
	int32_t cursig, si_signo, si_code, si_errno;
	uint64_t reg[NGREG];
};

static struct thread *threads;
static unsigned nthreads;

/* pr_reg is a struct user_regs_struct, whose field order is neither
 * alphabetical nor the DWARF register order. Index into it by name, in the
 * order gdb's "info registers" prints, so the two dumps line up. */
static const struct { const char *name; int i; } REGMAP[NGREG] = {
	{ "rax", 10 }, { "rbx", 5 },  { "rcx", 11 }, { "rdx", 12 },
	{ "rsi", 13 }, { "rdi", 14 }, { "rbp", 4 },  { "rsp", 19 },
	{ "r8", 9 },   { "r9", 8 },   { "r10", 7 },  { "r11", 6 },
	{ "r12", 3 },  { "r13", 2 },  { "r14", 1 },  { "r15", 0 },
	{ "rip", 16 }, { "eflags", 18 }, { "cs", 17 }, { "ss", 20 },
	{ "ds", 23 },  { "es", 24 },  { "fs", 25 },  { "gs", 26 },
	{ "fs_base", 21 }, { "gs_base", 22 }, { "orig_rax", 15 },
};

static uint64_t reg_by_name(const struct thread *t, const char *n)
{
	for (int i = 0; i < NGREG; i++)
		if (!strcmp(REGMAP[i].name, n))
			return t->reg[REGMAP[i].i];
	die("no register named %s", n);
	return 0;
}

static void load_threads(void)
{
	for (unsigned i = 0; i < nnotes; i++) {
		if (notes[i].type != NT_PRSTATUS || !nameis(&notes[i], "CORE"))
			continue;
		if (notes[i].descsz < PRSTATUS_SZ)
			die("NT_PRSTATUS note %u is %" PRIu64 " bytes, want %u",
			    nthreads, notes[i].descsz, PRSTATUS_SZ);
		threads = realloc(threads, (nthreads + 1) * sizeof *threads);
		if (!threads)
			die("out of memory");
		struct thread *t = &threads[nthreads++];
		const uint8_t *d = notes[i].desc;
		t->si_signo = (int32_t)u32(d);
		t->si_code = (int32_t)u32(d + 4);
		t->si_errno = (int32_t)u32(d + 8);
		t->cursig = (int16_t)u16(d + 12);
		t->pid = (int32_t)u32(d + 32);
		t->ppid = (int32_t)u32(d + 36);
		t->pgrp = (int32_t)u32(d + 40);
		t->sid = (int32_t)u32(d + 44);
		for (int r = 0; r < NGREG; r++)
			t->reg[r] = u64(d + 112 + 8 * r);
	}
	if (!nthreads)
		die("no NT_PRSTATUS note: no thread state in this core");
}

static const char *signame(int s)
{
	static const char *n[] = {
		NULL, "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP",
		"SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV",
		"SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT",
		"SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN",
		"SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM",
		"SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS",
	};
	return (s > 0 && s < (int)(sizeof n / sizeof *n)) ? n[s] : "?";
}

/* si_code is interpreted relative to si_signo for the fault signals, and
 * absolutely for the rest (negative codes mean a sender, not a fault). */
static const char *sigcode(int signo, int code)
{
	switch (code) {
	case 0:    return "SI_USER";
	case 0x80: return "SI_KERNEL";
	case -1:   return "SI_QUEUE";
	case -2:   return "SI_TIMER";
	case -3:   return "SI_MESGQ";
	case -4:   return "SI_ASYNCIO";
	case -5:   return "SI_SIGIO";
	case -6:   return "SI_TKILL";
	}
	switch (signo) {
	case 11: return code == 1 ? "SEGV_MAPERR" : code == 2 ? "SEGV_ACCERR" :
			code == 3 ? "SEGV_BNDERR" : code == 4 ? "SEGV_PKUERR" : "?";
	case 7:  return code == 1 ? "BUS_ADRALN" : code == 2 ? "BUS_ADRERR" :
			code == 3 ? "BUS_OBJERR" : "?";
	case 4:  return code == 1 ? "ILL_ILLOPC" : code == 2 ? "ILL_ILLOPN" :
			code == 3 ? "ILL_ILLADR" : code == 4 ? "ILL_ILLTRP" :
			code == 5 ? "ILL_PRVOPC" : code == 8 ? "ILL_BADSTK" : "?";
	case 8:  return code == 1 ? "FPE_INTDIV" : code == 2 ? "FPE_INTOVF" :
			code == 3 ? "FPE_FLTDIV" : code == 4 ? "FPE_FLTOVF" :
			code == 5 ? "FPE_FLTUND" : code == 6 ? "FPE_FLTRES" :
			code == 7 ? "FPE_FLTINV" : code == 8 ? "FPE_FLTSUB" : "?";
	case 5:  return code == 1 ? "TRAP_BRKPT" : code == 2 ? "TRAP_TRACE" : "?";
	}
	return "?";
}

/* True for the signals whose siginfo carries a faulting address. */
static int has_fault_addr(int s)
{
	return s == 4 || s == 5 || s == 7 || s == 8 || s == 11;
}

/* The thread that took the signal: the one with a non-zero pr_cursig. */
static const struct thread *killed_thread(void)
{
	for (unsigned i = 0; i < nthreads; i++)
		if (threads[i].cursig)
			return &threads[i];
	return &threads[0];
}

/* NT_SIGINFO is the kernel's siginfo_t as written to the core:
 *   0 si_signo, 4 si_errno, 8 si_code, 16 the union.
 * Note the field order differs from elf_siginfo in NT_PRSTATUS, which is
 * si_signo, si_code, si_errno. Mixing the two up swaps code and errno, and
 * since errno is almost always 0 the result looks like code 0 == SI_USER:
 * a NULL dereference reported as "someone sent you a signal".
 */
static void show_signal(void)
{
	const struct thread *t = killed_thread();
	const struct note *n = find_note(NT_SIGINFO, 0);
	int signo = t->cursig, code = t->si_code;
	const uint8_t *d = NULL;

	if (n && n->descsz >= 24) {
		d = n->desc;
		signo = (int32_t)u32(d);
		code = (int32_t)u32(d + 8);
	}
	if (!signo) {
		printf("signal: none (this core was not made by a fatal signal)\n");
		return;
	}
	printf("signal: %s (%d) code %d (%s) thread %" PRId32 "\n",
	       signame(signo), signo, code, sigcode(signo, code), t->pid);
	if (!d) {
		printf("fault: unknown (no NT_SIGINFO note in this core)\n");
	} else if (has_fault_addr(signo) && code > 0) {
		printf("fault: address 0x%" PRIx64 "\n", u64(d + 16));
	} else if (code <= 0 || code == 0x80) {
		printf("fault: sent by pid %" PRId32 " uid %" PRIu32 "\n",
		       (int32_t)u32(d + 16), u32(d + 20));
	}
}

static void show_threads(int regs)
{
	printf("threads: %u\n", nthreads);
	for (unsigned i = 0; i < nthreads; i++) {
		const struct thread *t = &threads[i];
		printf("thread %u tid %" PRId32 " cursig %" PRId32 " (%s)\n",
		       i + 1, t->pid, t->cursig,
		       t->cursig ? signame(t->cursig) : "none");
		if (!regs)
			continue;
		for (int r = 0; r < NGREG; r++)
			printf("reg %s 0x%" PRIx64 "\n", REGMAP[r].name,
			       t->reg[REGMAP[r].i]);
	}
}

/* ---- NT_AUXV: the auxiliary vector --------------------------------------
 *
 * An array of (uint64 key, uint64 value) ending at key AT_NULL. This is the
 * same block the kernel pushed onto the process stack at exec, which is what
 * makes it useful twice: for what it says, and as a landmark for finding the
 * initial stack frame (see show_cmdline).
 */
static const char *auxv_name(uint64_t k)
{
	switch (k) {
	case 0:  return "AT_NULL";
	case 1:  return "AT_IGNORE";
	case 2:  return "AT_EXECFD";
	case 3:  return "AT_PHDR";
	case 4:  return "AT_PHENT";
	case 5:  return "AT_PHNUM";
	case 6:  return "AT_PAGESZ";
	case 7:  return "AT_BASE";
	case 8:  return "AT_FLAGS";
	case 9:  return "AT_ENTRY";
	case 10: return "AT_NOTELF";
	case 11: return "AT_UID";
	case 12: return "AT_EUID";
	case 13: return "AT_GID";
	case 14: return "AT_EGID";
	case 15: return "AT_PLATFORM";
	case 16: return "AT_HWCAP";
	case 17: return "AT_CLKTCK";
	case 23: return "AT_SECURE";
	case 24: return "AT_BASE_PLATFORM";
	case 25: return "AT_RANDOM";
	case 26: return "AT_HWCAP2";
	case 27: return "AT_RSEQ_FEATURE_SIZE";
	case 28: return "AT_RSEQ_ALIGN";
	case 29: return "AT_HWCAP3";
	case 30: return "AT_HWCAP4";
	case 31: return "AT_EXECFN";
	case 32: return "AT_SYSINFO";
	case 33: return "AT_SYSINFO_EHDR";
	case 51: return "AT_MINSIGSTKSZ";
	default: return "AT_?";
	}
}

static void show_auxv(void)
{
	const struct note *n = find_note(NT_AUXV, 0);
	if (!n) {
		printf("auxv: no NT_AUXV note\n");
		return;
	}
	uint64_t o = 0;
	for (; o + 16 <= n->descsz; o += 16) {
		uint64_t k = u64(n->desc + o), v = u64(n->desc + o + 8);
		printf("auxv %" PRIu64 " %s 0x%" PRIx64 "\n", k, auxv_name(k), v);
		if (k == 0)
			break;
	}
}

/* ---- NT_FILE: the mapped file list ---------------------------------------
 *
 *   u64 count
 *   u64 page_size
 *   count x { u64 start, u64 end, u64 file_ofs }
 *   count x NUL-terminated file name, in the same order
 *
 * file_ofs is in units of page_size, which is the detail that bites: the
 * kernel writes page_size 4096 and offsets in pages, while gdb's gcore writes
 * page_size 1 and offsets in bytes. Both are legal. Multiply, never assume.
 *
 * This is the note that turns an address into a file and an offset, and it is
 * the only place in the core where the names of the mapped files appear.
 */
struct fmap {
	uint64_t start, end, off;	/* off is in bytes, already multiplied */
	const char *name;
};

static struct fmap *fmaps;
static unsigned nfmaps;

static void load_files(void)
{
	const struct note *n = find_note(NT_FILE, 0);
	if (!n)
		return;
	if (n->descsz < 16)
		die("NT_FILE note is %" PRIu64 " bytes, too short for its header",
		    n->descsz);
	uint64_t count = u64(n->desc), psz = u64(n->desc + 8);
	if (count > (n->descsz - 16) / 24)
		die("NT_FILE claims %" PRIu64 " mappings but the note holds "
		    "%" PRIu64 " bytes", count, n->descsz);
	if (psz == 0)
		die("NT_FILE page size is 0");
	fmaps = calloc(count ? count : 1, sizeof *fmaps);
	if (!fmaps)
		die("out of memory");

	/* The names follow the table, one NUL-terminated string per entry, in
	 * order. A name whose NUL is missing means the note is truncated. */
	uint64_t p = 16 + count * 24;
	for (uint64_t i = 0; i < count; i++) {
		const uint8_t *e = n->desc + 16 + i * 24;
		fmaps[i].start = u64(e);
		fmaps[i].end = u64(e + 8);
		fmaps[i].off = u64(e + 16) * psz;
		uint64_t q = p;
		while (q < n->descsz && n->desc[q])
			q++;
		if (q >= n->descsz)
			die("NT_FILE name %" PRIu64 " is not terminated inside "
			    "the note", i);
		fmaps[i].name = (const char *)n->desc + p;
		p = q + 1;
	}
	nfmaps = count;
}

/* Which mapped file, if any, backs this address. */
static const struct fmap *fmap_of(uint64_t addr)
{
	for (unsigned i = 0; i < nfmaps; i++)
		if (addr >= fmaps[i].start && addr < fmaps[i].end)
			return &fmaps[i];
	return NULL;
}

static void show_files(void)
{
	if (!nfmaps) {
		printf("files: no NT_FILE note\n");
		return;
	}
	for (unsigned i = 0; i < nfmaps; i++)
		printf("file 0x%" PRIx64 " 0x%" PRIx64 " off 0x%" PRIx64 " %s\n",
		       fmaps[i].start, fmaps[i].end, fmaps[i].off, fmaps[i].name);
}

/* ---- the PT_LOAD map, and reading memory out of it -----------------------
 *
 * Each PT_LOAD is one mapping of the dead process. p_memsz is how much
 * address space it covered; p_filesz is how much of its contents the core
 * actually stores. These differ, and the difference is not a corruption:
 *
 *   p_filesz == 0          the mapping existed and none of it was saved. The
 *                          kernel's default /proc/PID/coredump_filter (0x33)
 *                          omits file-backed private pages exactly this way,
 *                          so every shared library's text segment in a real
 *                          kernel core looks like this.
 *   0 < p_filesz < p_memsz the tail was not saved (a sparse or partly
 *                          unreadable mapping).
 *
 * Reporting absent memory as zeros is the bug this distinction exists to
 * prevent: a backtrace through a NULL-filled stack invents frames, and a
 * hexdump of pages that were never saved looks exactly like a page of real
 * zeros. corex says "absent" and reads nothing.
 */
static const struct seg *seg_of(uint64_t addr)
{
	for (unsigned i = 0; i < nsegs; i++)
		if (segs[i].type == PT_LOAD && segs[i].memsz &&
		    addr >= segs[i].vaddr && addr - segs[i].vaddr < segs[i].memsz)
			return &segs[i];
	return NULL;
}

/* A pointer to len bytes of process memory at addr, or NULL if that range is
 * not stored in this core. Never returns a short read and never substitutes
 * zeros for missing pages. */
static const uint8_t *mem(uint64_t addr, uint64_t len)
{
	const struct seg *s = seg_of(addr);
	if (!s || len == 0)
		return NULL;
	uint64_t d = addr - s->vaddr;
	if (d >= s->filesz || len > s->filesz - d)
		return NULL;		/* mapped, but not saved in the core */
	return at(s->off + d, len);
}

static int mem_u64(uint64_t addr, uint64_t *out)
{
	const uint8_t *p = mem(addr, 8);
	if (!p)
		return 0;
	*out = u64(p);
	return 1;
}

static void show_maps(void)
{
	char pb[4];
	for (unsigned i = 0; i < nsegs; i++) {
		if (segs[i].type != PT_LOAD)
			continue;
		const struct seg *s = &segs[i];
		const char *present = s->filesz == 0 ? "absent" :
				      s->filesz < s->memsz ? "partial" : "present";
		const struct fmap *f = fmap_of(s->vaddr);
		printf("map 0x%" PRIx64 " 0x%" PRIx64 " %s memsz 0x%" PRIx64
		       " filesz 0x%" PRIx64 " %s",
		       s->vaddr, s->vaddr + s->memsz, perms(s->flags, pb),
		       s->memsz, s->filesz, present);
		if (f)
			printf(" %s+0x%" PRIx64, f->name,
			       f->off + (s->vaddr - f->start));
		else
			printf(" anon");
		printf("\n");
	}
}

/* -x ADDR[,LEN] */
static void hexdump(uint64_t addr, uint64_t len)
{
	const struct seg *s = seg_of(addr);
	if (!s) {
		printf("x 0x%" PRIx64 ": unmapped, no PT_LOAD covers it\n", addr);
		exit(1);
	}
	for (uint64_t o = 0; o < len; o += 16) {
		uint64_t k = len - o < 16 ? len - o : 16;
		const uint8_t *p = mem(addr + o, k);
		if (!p) {
			char pb[4];
			printf("x 0x%" PRIx64 ": absent -- mapped %s, memsz "
			       "0x%" PRIx64 ", but only 0x%" PRIx64 " bytes of it "
			       "are in this core\n", addr + o,
			       perms(s->flags, pb), s->memsz, s->filesz);
			exit(1);
		}
		printf("x 0x%" PRIx64, addr + o);
		for (uint64_t j = 0; j < k; j++)
			printf(" %02x", p[j]);
		for (uint64_t j = k; j < 16; j++)
			printf("   ");
		printf(" |");
		for (uint64_t j = 0; j < k; j++)
			putchar(p[j] >= 32 && p[j] < 127 ? p[j] : '.');
		printf("|\n");
	}
}

/* ---- the backtrace ------------------------------------------------------
 *
 * Frame pointers only. At -O0 with -fno-omit-frame-pointer every function
 * starts with push %rbp / mov %rsp,%rbp, so [rbp] is the caller's rbp and
 * [rbp+8] is the return address, and the chain is a linked list up the stack.
 * This is the same mechanism prof (sibling repo) uses on live samples, and it
 * carries the same precondition: an optimised binary that reuses rbp as a
 * general register has no chain to walk and the backtrace stops at depth 1.
 * Nothing here reads DWARF, so there is no CFI-based unwinding and no inlined
 * frames. Both are stated in the README.
 *
 * The unwinder must terminate on garbage, because a corrupt or hostile core
 * can point rbp anywhere. Four rules do it, and all four are necessary:
 *   - the frame pointer must stay inside the one PT_LOAD that holds this
 *     thread's rsp, so the chain cannot wander off into another mapping
 *   - it must be 8-byte aligned
 *   - it must strictly increase, so a self-referential or cyclic chain ends
 *   - a zero return address or a frame whose two words are not stored in the
 *     core ends the walk
 * plus a hard cap, so even a chain that satisfies all four cannot run forever
 * on a core with a very large stack segment.
 */
#define MAXFRAMES 8192

static void backtrace_thread(const struct thread *t, unsigned idx)
{
	uint64_t pc = reg_by_name(t, "rip");
	uint64_t bp = reg_by_name(t, "rbp");
	uint64_t sp = reg_by_name(t, "rsp");
	const struct seg *stack = seg_of(sp);
	const char *why = "reached the outermost frame";
	unsigned n = 0;

	printf("bt thread %u tid %" PRId32 "\n", idx + 1, t->pid);
	for (;;) {
		const struct fmap *f = fmap_of(pc);
		printf("#%u 0x%" PRIx64, n, pc);
		if (f)
			printf(" %s+0x%" PRIx64, f->name, pc - f->start + f->off);
		else
			printf(" (no mapped file)");
		printf("\n");
		if (++n >= MAXFRAMES) { why = "hit the frame cap"; break; }

		if (!stack || seg_of(bp) != stack) {
			why = "frame pointer left the stack mapping";
			break;
		}
		if (bp & 7) { why = "frame pointer is misaligned"; break; }
		uint64_t nbp, ret;
		if (!mem_u64(bp, &nbp) || !mem_u64(bp + 8, &ret)) {
			why = "frame is not stored in this core";
			break;
		}
		if (ret == 0) { why = "return address is 0"; break; }
		if (nbp <= bp) { why = "frame pointer did not increase"; break; }
		pc = ret;
		bp = nbp;
	}
	printf("bt thread %u: %u frames (%s)\n", idx + 1, n, why);
}

static void show_bt(void)
{
	for (unsigned i = 0; i < nthreads; i++)
		backtrace_thread(&threads[i], i);
}

/* ---- main --------------------------------------------------------------- */

static void usage(void)
{
	fputs("usage: corex [--phdrs] [--notes] [--proc] [--signal] [--threads]\n             [--regs] [--auxv] [--files] [--maps] [--bt]\n             [-x ADDR[,LEN]] CORE\n", stderr);
	exit(2);
}

int main(int argc, char **argv)
{
	int want_phdrs = 0, want_notes = 0, want_proc = 0;
	int want_sig = 0, want_threads = 0, want_regs = 0, want_auxv = 0;
	int want_files = 0, want_maps = 0, want_bt = 0, any = 0;
	uint64_t xaddr = 0, xlen = 64;
	int want_x = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--phdrs")) { want_phdrs = any = 1; }
		else if (!strcmp(argv[i], "--notes")) { want_notes = any = 1; }
		else if (!strcmp(argv[i], "--proc")) { want_proc = any = 1; }
		else if (!strcmp(argv[i], "--signal")) { want_sig = any = 1; }
		else if (!strcmp(argv[i], "--threads")) { want_threads = any = 1; }
		else if (!strcmp(argv[i], "--regs")) { want_regs = want_threads = any = 1; }
		else if (!strcmp(argv[i], "--auxv")) { want_auxv = any = 1; }
		else if (!strcmp(argv[i], "--files")) { want_files = any = 1; }
		else if (!strcmp(argv[i], "--maps")) { want_maps = any = 1; }
		else if (!strcmp(argv[i], "--bt")) { want_bt = any = 1; }
		else if (!strcmp(argv[i], "-x") && i + 1 < argc) {
			char *end;
			xaddr = strtoull(argv[++i], &end, 0);
			if (*end == ',')
				xlen = strtoull(end + 1, &end, 0);
			if (*end)
				usage();
			want_x = any = 1;
		}
		else if (argv[i][0] == '-' && argv[i][1]) usage();
		else if (cpath) usage();
		else cpath = argv[i];
	}
	if (!cpath) usage();
	if (!any) want_phdrs = want_notes = want_proc = want_sig =
			want_threads = want_regs = want_auxv = want_files =
			want_maps = want_bt = 1;

	int fd = open(cpath, O_RDONLY);
	if (fd < 0) { perror(cpath); return 3; }
	struct stat st;
	if (fstat(fd, &st) < 0) { perror(cpath); return 3; }
	if (!S_ISREG(st.st_mode)) die("not a regular file");
	N = st.st_size;
	if (N == 0) die("empty file");
	void *m = mmap(NULL, N, PROT_READ, MAP_PRIVATE, fd, 0);
	if (m == MAP_FAILED) { perror("mmap"); return 3; }
	close(fd);
	B = m;

	load_phdrs();
	load_notes();
	load_threads();
	load_files();
	if (want_phdrs)
		show_segs();
	if (want_notes)
		show_notes();
	if (want_proc)
		show_prpsinfo();
	if (want_sig)
		show_signal();
	if (want_threads)
		show_threads(want_regs);
	if (want_auxv)
		show_auxv();
	if (want_files)
		show_files();
	if (want_maps)
		show_maps();
	if (want_bt)
		show_bt();
	if (want_x)
		hexdump(xaddr, xlen);
	return 0;
}
