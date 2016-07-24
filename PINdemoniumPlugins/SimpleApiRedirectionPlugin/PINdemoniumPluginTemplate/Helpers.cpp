#include "Helpers.h"
#include "stdafx.h"

// read memory from the process specified
//
// hProcess : Handle of the process we want to read memory from
// address : the starting reading address
// size : how many bytes we want to read
// dataBuffer : pointer to the destination buffer (where the read bytes will be saved)
bool readMemoryFromProcess(static HANDLE hProcess, DWORD_PTR address, SIZE_T size, LPVOID dataBuffer)
{
	SIZE_T lpNumberOfBytesRead = 0;
	DWORD dwProtect = 0;
	bool returnValue = false;

	if (!hProcess)
	{
		return returnValue;
	}

	if (!ReadProcessMemory(hProcess, (LPVOID)address, dataBuffer, size, &lpNumberOfBytesRead))
	{
		if (!VirtualProtectEx(hProcess, (LPVOID)address, size, PAGE_READWRITE, &dwProtect))
		{
			returnValue = false;
		}
		else
		{
			if (!ReadProcessMemory(hProcess, (LPVOID)address, dataBuffer, size, &lpNumberOfBytesRead))
			{
				returnValue = false;
			}
			else
			{
				returnValue = true;
			}
			VirtualProtectEx(hProcess, (LPVOID)address, size, dwProtect, &dwProtect);
		}
	}
	else
	{
		returnValue = true;
	}

	if (returnValue)
	{
		if (size != lpNumberOfBytesRead)
		{
			returnValue = false;
		}
		else
		{
			returnValue = true;
		}
	}
	
	return returnValue;
}


// write buffer to the process memory
//
// hProcess : Handle of the process we want to write the memory
// address : the starting writing address 
// size : how many bytes we want to write
// dataBuffer : pointer to the source buffer (it contains the bytes we want to write)
bool writeMemoryToProcess(static HANDLE hProcess, DWORD_PTR address, SIZE_T size, LPVOID dataBuffer)
{
	SIZE_T lpNumberOfBytesWritten = 0;
	if (!hProcess)
	{
		return false;
	}

	return (WriteProcessMemory(hProcess,(LPVOID)address, dataBuffer, size,&lpNumberOfBytesWritten) != FALSE);
}