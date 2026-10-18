/* A core whose floating-point state is not all zeros.
 *
 * Every other fixture here leaves xmm, the x87 stack and mxcsr at
 * their startup values, and those are zero or constant. A decoder
 * reading the wrong offset inside a 512-byte block of zeros produces
 * exactly the right answer, so a comparison against gdb on such a
 * core would pass with two registers swapped, with the whole note
 * read from the wrong place, or with the decoder returning a zero it
 * never looked up. That is the vacuous-test shape this collection
 * keeps finding, and it is the only reason this file exists.
 *
 * Every value below is distinct, and distinct in both halves, so a
 * decoder that reads 8 bytes where it needs 16 cannot pass either.
 *
 * Straight-line on purpose: anything between the loads and the fault,
 * including a library call the compiler inserts, is free to use xmm.
 */
#include <stdint.h>

static const uint64_t xv[16][2] = {
	{ 0x1011121314151617ULL, 0x0001020304050607ULL },
	{ 0x3031323334353637ULL, 0x2021222324252627ULL },
	{ 0x5051525354555657ULL, 0x4041424344454647ULL },
	{ 0x7071727374757677ULL, 0x6061626364656667ULL },
	{ 0x9091929394959697ULL, 0x8081828384858687ULL },
	{ 0xb0b1b2b3b4b5b6b7ULL, 0xa0a1a2a3a4a5a6a7ULL },
	{ 0xd0d1d2d3d4d5d6d7ULL, 0xc0c1c2c3c4c5c6c7ULL },
	{ 0xf0f1f2f3f4f5f6f7ULL, 0xe0e1e2e3e4e5e6e7ULL },
	{ 0x1112131415161718ULL, 0x0102030405060708ULL },
	{ 0x3132333435363738ULL, 0x2122232425262728ULL },
	{ 0x5152535455565758ULL, 0x4142434445464748ULL },
	{ 0x7172737475767778ULL, 0x6162636465666768ULL },
	{ 0x9192939495969798ULL, 0x8182838485868788ULL },
	{ 0xb1b2b3b4b5b6b7b8ULL, 0xa1a2a3a4a5a6a7a8ULL },
	{ 0xd1d2d3d4d5d6d7d8ULL, 0xc1c2c3c4c5c6c7c8ULL },
	{ 0xf1f2f3f4f5f6f7f8ULL, 0xe1e2e3e4e5e6e7e8ULL },
};

/* Eight distinct long doubles, pushed in reverse so st0 ends up the
 * first of them. Values a human can recognise in gdb's output. */
static const long double sv[8] = {
	1.5L, 2.25L, 3.125L, 4.0625L, 5.03125L, 6.015625L, 7.0078125L, 8.00390625L,
};

/* A mxcsr with a bit set that the default does not have, so a decoder
 * returning the constant 0x1f80 is caught. 0x1fa0 is the default plus
 * FZ, flush to zero. */
static const uint32_t mx = 0x1fa0;

int main(void)
{
	/* x87 first: pushing onto the stack moves everything, so it must
	 * not happen after the SSE registers are set. */
	__asm__ volatile("fninit");
	__asm__ volatile("fldt %0" :: "m"(sv[7]));
	__asm__ volatile("fldt %0" :: "m"(sv[6]));
	__asm__ volatile("fldt %0" :: "m"(sv[5]));
	__asm__ volatile("fldt %0" :: "m"(sv[4]));
	__asm__ volatile("fldt %0" :: "m"(sv[3]));
	__asm__ volatile("fldt %0" :: "m"(sv[2]));
	__asm__ volatile("fldt %0" :: "m"(sv[1]));
	__asm__ volatile("fldt %0" :: "m"(sv[0]));

	__asm__ volatile("ldmxcsr %0" :: "m"(mx));

	__asm__ volatile("movdqu %0, %%xmm0"  :: "m"(xv[0])  : "xmm0");
	__asm__ volatile("movdqu %0, %%xmm1"  :: "m"(xv[1])  : "xmm1");
	__asm__ volatile("movdqu %0, %%xmm2"  :: "m"(xv[2])  : "xmm2");
	__asm__ volatile("movdqu %0, %%xmm3"  :: "m"(xv[3])  : "xmm3");
	__asm__ volatile("movdqu %0, %%xmm4"  :: "m"(xv[4])  : "xmm4");
	__asm__ volatile("movdqu %0, %%xmm5"  :: "m"(xv[5])  : "xmm5");
	__asm__ volatile("movdqu %0, %%xmm6"  :: "m"(xv[6])  : "xmm6");
	__asm__ volatile("movdqu %0, %%xmm7"  :: "m"(xv[7])  : "xmm7");
	__asm__ volatile("movdqu %0, %%xmm8"  :: "m"(xv[8])  : "xmm8");
	__asm__ volatile("movdqu %0, %%xmm9"  :: "m"(xv[9])  : "xmm9");
	__asm__ volatile("movdqu %0, %%xmm10" :: "m"(xv[10]) : "xmm10");
	__asm__ volatile("movdqu %0, %%xmm11" :: "m"(xv[11]) : "xmm11");
	__asm__ volatile("movdqu %0, %%xmm12" :: "m"(xv[12]) : "xmm12");
	__asm__ volatile("movdqu %0, %%xmm13" :: "m"(xv[13]) : "xmm13");
	__asm__ volatile("movdqu %0, %%xmm14" :: "m"(xv[14]) : "xmm14");
	__asm__ volatile("movdqu %0, %%xmm15" :: "m"(xv[15]) : "xmm15");

	*(volatile int *)0 = 0;
	return 0;
}
