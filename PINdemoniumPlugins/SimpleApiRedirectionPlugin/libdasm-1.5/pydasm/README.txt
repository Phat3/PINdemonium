
pydasm -- python module wrapping libdasm
========================================
(c) 2005  ero / dkbza.org


0. Acknowledgements
===================

Thanks to jt and all the folks responsible for libdasm!

1. What is pydasm?
==================

pydasm is a python wrapper for libdasm. It attempts to capture all the
functionality of libdasm and bring its versatility to Python. To the
best of my knowledge there's no Python module for easily disassembling
code. (Some monstrosities parsing objdump's output are the closest to it)
So, now there's one, and a pretty fine one I hope :)


2. How to use pydasm?
=====================

You'll need first to compile the module:

 python setup.py build_ext

The resulting pydasm.so can be imported into Python and the disassembling
madness may then begin.

The main libdasm function have been wrapped and have docstrings documenting
their parameters.

A small example script disassembling data from a buffer named, originally,
'buffer' containing code follows:

>>>>>>>>>EXAMPLE>>>>>>>>>

import pydasm

# Very silly, nop and some xor's
buffer = '\x90\x31\xc9\x31\xca\x31\xcb'

offset = 0
while offset < len(buffer):
   i = pydasm.get_instruction(buffer[offset:], pydasm.MODE_32)
   print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)
   if not i:
     break
   offset += i.length

<<<<<<<<<EXAMPLE<<<<<<<<<

Yes, that easy... even easier than the already straightforward C counterpart.
For a more elaborate example, please check "das.py", the Python counterpart
to das.c

