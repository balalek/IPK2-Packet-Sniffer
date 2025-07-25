CC=gcc
CFLAGS= -std=gnu99 -pedantic -Wall -Wextra -lpcap
all:
	$(CC) $(CFLAGS) ipk-sniffer.c -o  ipk-sniffer -lpcap

clean:
	rm -f ipk-sniffer