/* A 1000-frame stack, so the unwinder has to terminate by running out of
 * chain and not by running out of patience. The depth is known, so the frame
 * count is known: 1001 calls to rec() plus main.
 */
#define DEPTH 1000
static int rec(int n)
{
	if (n == 0) {
		volatile int *p = 0;
		*p = 1;
	}
	return rec(n - 1) + 1;
}
int main(void) { return rec(DEPTH); }
