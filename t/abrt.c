/* Dies on SIGABRT rather than SIGSEGV: a signal with no faulting address,
 * raised by the process against itself, so si_code is SI_TKILL and the
 * siginfo carries a sender pid and uid instead.
 */
#include <stdlib.h>
static void boom(void) { abort(); }
int main(void) { boom(); return 0; }
