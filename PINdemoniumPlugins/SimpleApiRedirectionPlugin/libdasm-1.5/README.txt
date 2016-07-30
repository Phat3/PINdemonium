
libdasm -- simple x86 disassembly library
=========================================
(c) 2004 - 2006  jt / nologin.org 


1. Acknowledgements
===================

Thanks to skape, thief, spoonm and fine folks @nologin for bug
reports, ideas and support. Special thanks to ero for creating
and contributing pydasm and to skape for rbdasm.


2. What is libdasm?
===================

libdasm is a C-library that tries to provide simple and convenient
way to disassemble Intel x86 raw opcode bytes (machine code).
It can parse and print out opcodes in AT&T and Intel syntax.

The opcodes are based on IA-32 Intel Architecture Software Developer's
Manual Volume 2: Instruction Set Reference, order number 243667,
year 2004.  Non-Intel instructions are not supported atm (also,
non-Intel but Intel-compatible cpu extensions, like AMD 3DNow! are
not supported).

libdasm should compile with all decent C-compilers (only gcc and
MSVC tested).


3. How to use libdasm?
======================

Compiling your application with libdasm is very easy. As usual, there are
several ways to do it:

- Include "libdasm.c" and compile as usual. Remember to copy "libdasm.h"
  and "opcode_tables.h" in the same directory as they are included by the
  main c-file.
- Include "libdasm.h" and compile with "libdasm.c" (and remember to copy
  also "opcode_tables.h").
- Compile libdasm as library and link against it statically or dynamically,
  depending on the system and your needs. Win32 DLL and Unix static/dynamic
  libraries can be built with the supplied makefiles. See the file LIB.txt
  for more information.
- Compile pydasm and use libdasm as a python module (see directory "pydasm"
  for more information).
- Compile rbdasm and use libdasm as a ruby module (see directory "rbdasm"
  for more information).

For basic disassembling, there are are only one or two libdasm functions
you will need. First and the most important function is get_instruction.

3.1. get_instruction
====================

get_instruction analyzes data stream and fills in a structure presenting
the instruction. This structure, defined as struct INSTRUCTION, can be
later used for formatting the instruction to printable form or for
analyzing the instruction contents. It is defined as follows:

int get_instruction(
      INSTRUCTION *inst,      // pointer to INSTRUCTION structure
      BYTE *addr,             // data buffer
      enum Mode mode          // mode: MODE_32 or MODE_16
);

First argument is a refence to INSTRUCTION structure. There is no
need to initialize the structure prior to function call, get_instruction
will take care of filling it.

Second argument is an address of code buffer. get_instruction will
read data starting from that address and parse a single instruction.
INSTRUCTION structure is filled with the components of the returned
instruction. Normally you don't need to know about the contents of the
structure, but if you need to, read the next chapter.

Third argument, the mode is either 32-bit (MODE_32) or 16-bit (MODE_16).
This is the desired addressing mode. Note that the instruction might
override the mode.

get_instruction returns the instruction length. If the returned value
is zero, it indicates illegal instruction.

When get_instruction returns, you can print the instruction with
get_instruction_string or do analysis of the instruction members. When
ready, increment data buffer pointer to next instruction and call
get_instruction again. Here is pseudocode presenting this procedure:

	INSTRUCTION inst;
	int len, buflen, c = 0;
	BYTE *buf;

	do {
		len = get_instruction(&inst, buf+c, MODE_32);

		// do something with the instruction

		c  += len;

	} while (c < buflen);



3.2. get_instruction_string
===========================

get_instruction_string parses the instruction structure and fills in
a string presenting the instruction in given format. Currently,
ATT and Intel formats are supported. The function is defined as:

int get_instruction_string(
        INSTRUCTION *instr,     // pointer to INSTRUCTION structure
        enum Format format,     // format: FORMAT_ATT or FORMAT_INTEL
        DWORD offset,           // instruction absolute address
        char *string,           // string buffer
        int length              // string length
);

The offset is needed only if you need to make relational offsets look
nice (jmp/call/loop etc.). If you are parsing instructions in known 
virtual address, use the virtual address. Otherwise, you can use zero.
DWORD is defined in libdasm.h as unsigned 32-bit number (libdasm only
supports IA-32 atm). string is the pointer to instruction buffer, length
is the size of the buffer. Note that the text is truncated if it doesn't
fit in buffer.

get_instruction_string will initialize the string and terminate it
correctly for convenience. It returns zero if the operation is not
successful.

That's it! Check out sample disassembler programs "simple.c" and "das.c"
for examples.


3.3 Other libdasm functions
===========================

libdasm uses internally lot of useful functions that might help in
instruction formatting etc. For example, get_instruction_string calls
get_mnemonic_string and get_operand_string for simple instruction
formatting. These functions are defined as:

int get_mnemonic_string(
	INSTRUCTION *inst,
	enum Format format,
	char *string,
	int length
);

int get_operand_string(
	INSTRUCTION *inst,
	OPERAND *op,
	enum Format format,
	DWORD offset,
	char *string,
	int length
);

Both functions initialize and terminate the string buffer and return
data formatted as defined in member "format". There are also many
useful helper functions defined in libdasm.h for analyzing instruction
contents.


4. INSTRUCTION structure
========================

If all you need is to fetch and print out instructions in the data buffer,
you can skip this chapter. But if you need to inspect the individual
components that make up an instruction, you will need this information.

All libdasm functions inspect and/or manipulate INSTRUCTION structure.
It is defined as follows:

typedef struct _INSTRUCTION {
        int length;             // Instruction length
        enum Instruction type;  // Instruction type
	enum Mode mode;         // Addressing mode
        BYTE opcode;            // Actual opcode
        BYTE modrm;             // MODRM byte
        BYTE sib;               // SIB byte
	int extindex;           // Extension table index
	int fpuindex;           // FPU table index
        int dispbytes;          // Displacement bytes (0 = no displacement)
        int immbytes;           // Immediate bytes (0 = no immediate)
        int sectionbytes;       // Section prefix bytes (0 = no section prefix)
        OPERAND op1;            // First operand (if any)
        OPERAND op2;            // Second operand (if any)
        OPERAND op3;            // Additional operand (if any)
        int flags;		// Instruction flags
} INSTRUCTION, *PINSTRUCTION;

Most important members are probably "length", "opcode", and the operands.
"length" is the instruction size, also returned by get_instruction.
If the instruction size is zero, the instruction is illegal. "opcode" is the
instruction opcode byte. Some of the most common instructions also have a
meaningful "type" member. This member can have one of the following values:

	INSTRUCTION_TYPE_MOV,
        INSTRUCTION_TYPE_ADD,
        INSTRUCTION_TYPE_SUB,
        INSTRUCTION_TYPE_INC,
        INSTRUCTION_TYPE_DEC,
        INSTRUCTION_TYPE_DIV,
        INSTRUCTION_TYPE_MUL,
        INSTRUCTION_TYPE_IMUL,
        INSTRUCTION_TYPE_XOR,
        INSTRUCTION_TYPE_LEA,
        INSTRUCTION_TYPE_XCHG,
        INSTRUCTION_TYPE_CMP,
        INSTRUCTION_TYPE_TEST,
        INSTRUCTION_TYPE_PUSH,	// includes enter, pusha and pushf
        INSTRUCTION_TYPE_AND,
        INSTRUCTION_TYPE_OR,
        INSTRUCTION_TYPE_POP,	// includes popa and popf
        INSTRUCTION_TYPE_JMP,	// includes jmpf
        INSTRUCTION_TYPE_JMPC,  // conditional jump
        INSTRUCTION_TYPE_LOOP,
        INSTRUCTION_TYPE_CALL,	// includes callf
        INSTRUCTION_TYPE_RET,	// includes leave, retn and retf
        INSTRUCTION_TYPE_INT,   // interrupt
        INSTRUCTION_TYPE_FPU,   // FPU-related instruction
        INSTRUCTION_TYPE_OTHER, // Other instructions :-)

The list above is not complete, check out libdasm.h for complete listing of
all possible instruction types.

Individual operands can be accessed by the OPERAND structures. All instructions
have 0-3 operands which are ordered in INTEL order (op1 is the first operand in
INTEL syntax). struct OPERAND is defined as:

typedef struct _OPERAND {
        enum Operand type;      // Operand type (register, memory, etc)
        int reg;                // Register (if any)
        int basereg;            // Base register (if any)
        int indexreg;           // Index register (if any)
        int scale;              // Scale (if any)
        int dispbytes;          // Displacement bytes (0 = no displacement)
        int dispoffset;         // Displacement offset (0 = no diplacement)
        int immbytes;           // Immediate bytes (0 = no immediate)
        int immoffset;          // Immediate offset (0 = no immediate)
        int sectionbytes;       // Section prefix bytes (0 = no section prefix)
        WORD section;           // Section prefix value
        DWORD displacement;     // Displacement value
        DWORD immediate;        // Immediate value
        int flags;		// Operand flags
} OPERAND, *POPERAND;

Operand type is always defined in member "type". This member can have one
of the following values:

        OPERAND_TYPE_NONE
        OPERAND_TYPE_MEMORY
        OPERAND_TYPE_REGISTER
        OPERAND_TYPE_IMMEDIATE

If the type is OPERAND_TYPE_NONE, operand is not present in the instruction.

If the type is OPERAND_TYPE_REGISTER, OPERAND member "reg" is present.

If the type is OPERAND_TYPE_MEMORY, some combination of the members
"basereg", "indexreg", "scale", "dispbytes" and "displacement" is present.
These members form the memory operand as follows:

	[ basereg + scale * indexreg + displacement ] (INTEL)
	displacement(basereg, indexreg, scale)        (ATT)

If the type is OPERAND_TYPE_IMMEDIATE, some combination of the members
"immbytes", "sectionbytes", "section" and "immediate" is present.
Section-specific members are used only in far type call/jmp. Member
"immediate" is filled with the actual immediate value.
Example: in "mov eax, 0x11" second operand "immediate" value is 0x11.

If present, register members "reg", "basereg" and "indexreg" can have one
of the following values:

	REGISTER_EAX
	REGISTER_ECX
	REGISTER_EDX
	REGISTER_EBX
	REGISTER_ESP
	REGISTER_EBP
	REGISTER_ESI
	REGISTER_EDI

If registers are not present, they are defined as REGISTER_NOP. Note that
the register is not necessarily general purpose register. Only way to
detect this is to inspect operand flags. You can also use helper function
get_register_type for determining the register type. Register type can
be one of the following:

	REGISTER_TYPE_GEN
	REGISTER_TYPE_SEGMENT 
	REGISTER_TYPE_DEBUG 
	REGISTER_TYPE_CONTROL 
	REGISTER_TYPE_TEST
	REGISTER_TYPE_XMM
	REGISTER_TYPE_MMX
	REGISTER_TYPE_FPU

get_register_type returns some of the values only if the operand type
is OPERAND_TYPE_REGISTER. If the operand is OPERAND_TYPE_MEMORY, the
registers are always general purpose and for immediate operands, there
are of course no registers involved.


5. Miscellaneous notes
======================

5.1. General output formatting

get_instruction_string tries to follow INTEL/ATT conventions but not
too strictly. There are some compromises that are made to keep the
implementation simple (or because the current implementation is already
too complex..).

5.2. Segment prefix formatting

Libdasm is modelled after the assumption that there is only one memory
operand at maximum in the instruction. If there is segment register override,
the segment register is placed in front of the memory operand, like this:

  mov eax, fs:[0x30]

If there are no memory operands, the segment prefix is placed in front of
the instruction:

  fs mov eax, 0x30

Some string instructions are also considered containing no memory operands,
like cmps. In reality, it contains two memory operands. So the following:

  fs cmpsd 

is equivalent to:

  cmpsd fs:[esi], es:[edi]

And btw, if you are wondering what are those weird "(bt)" and "(bnt)"
prefixes in front of conditional jumps, they are branch hint prefixes 
("branch taken" and "branch not taken").


5.3. Instruction correctness

There is not too much sanity checking in current code. So if you feed libdasm
enough with random data or illegally constructed instructions it probably
gives wrong disassembly at some point. But libdasm should always disassemble
correctly "real" code.


5.4. Boundary checks

Libdasm will not check for read buffer boundaries. It means that if the
opcode requires additional data to be read and that data cannot be accessed,
libdasm might access violate, depending on the implementation. There is no
platform-independent way of checking this condition, so you better make
sure of it by youself. If the data is real machine code, there is no
problem (unless of course there is a bug in libdasm) because libdasm needs
to read exactly what the instruction requires and of course the full
instruction is in buffer, right? But in some rare cases when disassembling
random data this could cause some troubles.

5.5. Endianness

Endianess might not be identified correctly on all platforms
(see libdasm.h for definition of __LITTLE_ENDIAN__). If you encounter
endianness related problems, please report the system and possible workaround
for the problem.


5.6. Inline functions

Some functions are defined as inline, this might not work for all compilers.
Only gcc and msvc are tested by the author.


5.7. Other issues

There are probably MANY unknown bugs in code and in instruction tables.
Some known issues are listed in file TODO.txt.


6. Licensing
============

libdasm is public domain software. You can do whatever you like with it.


7. How to contact the author
============================

If you have bug report or some improvement ideas or want to harass the author
for some other reason, you can try to send email to

  jt[at]klake.org

If you have questions about pydasm and rbdasm, check out directories
"pydasm" and "rbdasm" for contact information.



