/* A call chain exactly four deep, then a NULL write. The correct backtrace is
 * fixed by the source: d <- c <- b <- a <- main. */
static int d(int x) { volatile int *p = 0; *p = x; return x; }
static int c(int x) { return d(x + 1); }
static int b(int x) { return c(x + 1); }
static int a(int x) { return b(x + 1); }
int main(void) { return a(1); }
