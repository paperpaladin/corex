/* Three threads, each spinning inside a function of its own, plus a main
 * thread that dies on a NULL write. The core must therefore hold four
 * NT_PRSTATUS notes, one per thread, with four distinct tids -- which this
 * program prints on stdout before crashing, so the right answer comes from
 * the kernel and not from the core reader.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile int ready, stop;

static void announce(void)
{
	printf("tid %ld\n", (long)syscall(SYS_gettid));
	fflush(stdout);
}

static void *th_alpha(void *a) { (void)a; announce(); __atomic_add_fetch(&ready, 1, 5); while (!stop) ; return 0; }
static void *th_beta(void *a)  { (void)a; announce(); __atomic_add_fetch(&ready, 1, 5); while (!stop) ; return 0; }
static void *th_gamma(void *a) { (void)a; announce(); __atomic_add_fetch(&ready, 1, 5); while (!stop) ; return 0; }

int main(void)
{
	pthread_t t[3];
	announce();
	pthread_create(&t[0], 0, th_alpha, 0);
	pthread_create(&t[1], 0, th_beta, 0);
	pthread_create(&t[2], 0, th_gamma, 0);
	while (__atomic_load_n(&ready, 5) != 3)
		;
	volatile int *p = 0;
	*p = 1;
	return 0;
}
