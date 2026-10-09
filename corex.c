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

/* ---- main --------------------------------------------------------------- */

static void usage(void)
{
	fputs("usage: corex [--phdrs] CORE\n", stderr);
	exit(2);
}

int main(int argc, char **argv)
{
	int want_phdrs = 0, any = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--phdrs")) { want_phdrs = any = 1; }
		else if (argv[i][0] == '-' && argv[i][1]) usage();
		else if (cpath) usage();
		else cpath = argv[i];
	}
	if (!cpath) usage();
	if (!any) want_phdrs = 1;

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
	if (want_phdrs)
		show_segs();
	return 0;
}
