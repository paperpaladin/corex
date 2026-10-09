CC = gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -g -ffile-prefix-map=$(CURDIR)=.

all: corex

corex: corex.c
	$(CC) $(CFLAGS) -o $@ $<

test: corex
	t/run.sh

# The core file is untrusted binary with attacker-controlled offsets and sizes,
# so the whole suite is run again under the sanitisers.
test-asan:
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-sanitize-recover=all \
	    -o corex-asan corex.c
	COREX=./corex-asan t/run.sh

# Also clean under valgrind, on a real core and on the synthesised fixtures.
valgrind: corex
	t/run.sh >/dev/null
	for c in scratch/core.seg scratch/core.pad scratch/core.filesz0 \
	         scratch/core.threads scratch/core.xnum; do \
	    valgrind -q --error-exitcode=9 ./corex $$c >/dev/null || exit 1; \
	done
	@echo "valgrind: clean"

clean:
	rm -f corex corex-asan
	rm -rf scratch

.PHONY: all test test-asan valgrind clean
