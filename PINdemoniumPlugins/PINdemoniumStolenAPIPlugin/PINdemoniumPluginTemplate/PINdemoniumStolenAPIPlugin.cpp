#include "stdafx.h"
#include "PINdemoniumStolenAPIPlugin.h"
#include "Helpers.h"
#include "libdasm.h"

// Entry point of the plugin
// This function will be called PINdemonium
void runPlugin(static HANDLE hProcess, PUNRESOLVED_IMPORT unresolvedImport, unsigned int eip){
	
	//local variable
	int max_instruction_size = sizeof(UINT8)*15;
	int insDelta;
	char buffer[2048];
	int j,instruction_size;
	INSTRUCTION inst;
	DWORD_PTR invalidApiAddress = 0;
	MEMORY_BASIC_INFORMATION memBasic = {0};
	LPVOID instruction_buffer = (LPVOID)malloc(max_instruction_size);
		
	while (unresolvedImport->ImportTableAddressPointer != 0) //last element is a nulled struct
	{

		bool resolved = false;

		insDelta = 0;
		invalidApiAddress = unresolvedImport->InvalidApiAddress;
		//get the starting IAT address to be analyzed yet
		
		for (j = 0; j <  1000; j++)
		{
			//if we cannot query the invalidApiAddress then bypass the analysis of this address
			SIZE_T result = VirtualQueryEx(hProcess,(LPVOID)invalidApiAddress, &memBasic, sizeof(MEMORY_BASIC_INFORMATION));
			if (!result || memBasic.State != MEM_COMMIT || memBasic.Protect == PAGE_NOACCESS)
			{
				//if the memory region pointed by invalidApiAddress isn't mapped break the for loop and check the next unresolved import
				break;
			}
			//read the memory pointed by invalidApiAddress of the external process in order to disassembke the first instruction found
			//we read 15 bytes because in the x86varchitectures the instructions are guaranteed to fit in 15 bytes
			readMemoryFromProcess(hProcess, invalidApiAddress, max_instruction_size, instruction_buffer);
			//disassemble the first instruction in the buffer
			//instruction_size will contains the length of the disassembled instruction (0 if fails)
			instruction_size = get_instruction(&inst, (BYTE *)instruction_buffer, MODE_32);
			//if libdasm fails to recognize the insruction bypass this instruction
			if(instruction_size == 0){
				invalidApiAddress = invalidApiAddress + 1;
				insDelta = insDelta + 1;
				continue;
			}
			get_instruction_string(&inst, FORMAT_ATT, 0, buffer, sizeof(buffer));
			//check if it is a jump		
			if (strstr(buffer, "jmp"))
			{				
				//calculate the correct answer (add the invalidApiAddress to the destination of the jmp because it is a short jump)
				unsigned int correct_address = ( (unsigned int)std::strtoul(strstr(buffer, "jmp") + 4 + 2, NULL, 16)) + invalidApiAddress;
				/*	
				printf("\n\n---------------- MINI REP --------------\n");
				printf("INST %s: \n", buffer);
				printf("INVALID API :  %08x \n", invalidApiAddress);
				printf("INST DELTA %d \n", insDelta);
				printf("IAT POINTER : %p\n", unresolvedImport->ImportTableAddressPointer);
				printf("CORRECT ADDR : %08x\n", correct_address);
				//printf("SIZE OF CORRECT ADDR: %d\n", sizeof(correct_address));
				printf("---------------- END MINI REP --------------\n\n");
				*/
				//if the target address is in a memory space dedicated to dlls we have finished our check
				if(correct_address >= 0x50000000 && correct_address <= 0x7f000000){
					//subtract the stolen API executed
					correct_address = correct_address - insDelta;
					writeMemoryToProcess(hProcess, (DWORD_PTR)(unresolvedImport->ImportTableAddressPointer), sizeof(correct_address), &correct_address);
					//unresolved import probably resolved
					resolved = true;
					break;
				}
				//follow the target address of the jmp and continue the search
				//we don't have to increase the INSDelta beccause the jmp itself is not a stolen API (instruction belonging to the dll)
				else{
					invalidApiAddress = correct_address;
					continue;
				}
				
			}
			//if not increment the delta for the next fix (es : if we have encountered 4 instruction before the correct jmp we have to decrement the correct_address by 16 byte)
			insDelta = insDelta + instruction_size;
			//check the next row inthe IAT
			invalidApiAddress = invalidApiAddress + instruction_size;
		}
		/*
		//if we cannot resolve the import fix it with a dummy address so scylla isn't able to resolve the API and it will remove the unresolved import
		// this functionality is optional (set the flag nullify_unknown_iat_entry_flag as true with command line) because it can break the program
 		if(!resolved){
			unsigned int correct_address = 0x0;
			writeMemoryToProcess(hProcess, (DWORD_PTR)(unresolvedImport->ImportTableAddressPointer), sizeof(correct_address), &correct_address);
 			resolved = false;
 		}
		*/
		unresolvedImport++; //next pointer to struct
	}
	
}