/*
 * simple.c -- very simple 32-bit example disassembler program
 * (c) 2004  jt / nologin.org
 *
 * How to compile in MSVC environment:
 *   cl das.c ../libdasm.c
 *
 * In Unix environment, use the supplied Makefile
 *
 *
 * Check out "das.c" for more featured example.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

// step 0: include libdasm
#include "../libdasm.h"


// disassembled data buffer
unsigned char data[] = "\x01\x02";

int main() {
	// step 1: declare struct INSTRUCTION
	INSTRUCTION inst;
	char string[256];

	// step 2: fetch instruction
	get_instruction(&inst, data, MODE_32);

	// step 3: print it
	get_instruction_string(&inst, FORMAT_ATT, 0, string, sizeof(string));
	printf("%s\n", string);

	return 0;
}

