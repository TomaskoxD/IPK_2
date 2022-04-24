CC=g++
CFLAGS=-std=c++17 -Wall -Wno-unused-variable -Wno-unused-parameter -Wextra -pedantic

all:
	$(CC) $(CFLAGS) ipk-sniffer.cpp -lpcap -o ipk-sniffer
clean:
	rm -f ipk-sniffer xondru18.tar
pack:
	tar -czvf xondru18.tar ipk-sniffer.cpp manual.pdf Makefile Readme.md