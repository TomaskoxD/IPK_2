CC=g++
CFLAGS=-std=c++17 -Wall -Wno-unused-variable -Wno-unused-parameter -Wextra -pedantic

all:
	$(CC) $(CFLAGS) ipk-sniffer.cpp -lpcap -o ipk-sniffer