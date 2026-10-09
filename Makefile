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

clean:
	rm -f corex corex-asan
	rm -rf scratch

.PHONY: all test test-asan clean
