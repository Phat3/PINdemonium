#pragma once
#include "stdafx.h"

// Helper classs that provides common API very useful when you are dealing with IAT fixing

// read memory from the process specified
//
// hProcess : Handle of the process we want to read memory from
// address : the starting reading address
// size : how many bytes we want to read
// dataBuffer : pointer to the destination buffer (where the read bytes will be saved)
bool readMemoryFromProcess(static HANDLE hProcess, DWORD_PTR address, SIZE_T size, LPVOID dataBuffer);

// write buffer to the process memory
//
// hProcess : Handle of the process we want to write the memory
// address : the starting writing address 
// size : how many bytes we want to write
// dataBuffer : pointer to the source buffer (it contains the bytes we want to write)
bool writeMemoryToProcess(static HANDLE hProcess, DWORD_PTR address, SIZE_T size, LPVOID dataBuffer);
