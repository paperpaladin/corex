/* A 64 KiB buffer of known bytes on the stack, whose address this program
 * prints before it dies. buf[i] == (i * 31 + 7) & 0xff, which the test
 * recomputes: the expected contents of the core come from the source, not
 * from any tool.
 */
#include <stdio.h>

#define LEN (64 * 1024)

static void fill(void)
{
	volatile unsigned char buf[LEN];
	for (int i = 0; i < LEN; i++)
		buf[i] = (unsigned char)(i * 31 + 7);
	printf("buf %p %d\n", (void *)buf, LEN);
	fflush(stdout);
	volatile int *p = 0;
	*p = buf[0];
}

int main(void) { fill(); return 0; }
