#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN    

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>



// Dll header and data structures


/* Important note:
 *
 * If you write a plugin for the x86 (32-Bit) edition: DWORD_PTR address has 32 bit (4 byte)
 * If you write a plugin for the x64 (64-Bit) edition: DWORD_PTR address has 64 bit (8 byte)
 */
typedef struct _UNRESOLVED_IMPORT {       // Scylla Plugin exchange format
	DWORD_PTR ImportTableAddressPointer;  //in VA, address in IAT which points to an invalid api address
	DWORD_PTR InvalidApiAddress;          //in VA, invalid api address that needs to be resolved
} UNRESOLVED_IMPORT, *PUNRESOLVED_IMPORT;