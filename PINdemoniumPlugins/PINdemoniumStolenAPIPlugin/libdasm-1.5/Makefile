
#
# makefile for compiling libdasm and examples
#

CC     = gcc
CFLAGS = -Wall -O3 -fPIC
PREFIX = /usr/local


all: libdasm.o
	$(CC) $(CFLAGS) -shared -o libdasm.so libdasm.c
	ar rc libdasm.a libdasm.o && ranlib libdasm.a
	cd examples && make

install:
	cp libdasm.h  $(PREFIX)/include/
	cp libdasm.a  $(PREFIX)/lib/
	cp libdasm.so $(PREFIX)/lib/
	cp libdasm.so $(PREFIX)/lib/libdasm.so.1.0

uninstall:
	rm -f $(PREFIX)/include/libdasm.h
	rm -f $(PREFIX)/lib/libdasm.a
	rm -f $(PREFIX)/lib/libdasm.so.1.0 $(PREFIX)/lib/libdasm.so

clean:
	rm -f libdasm.o libdasm.so libdasm.a
	cd examples && make clean

