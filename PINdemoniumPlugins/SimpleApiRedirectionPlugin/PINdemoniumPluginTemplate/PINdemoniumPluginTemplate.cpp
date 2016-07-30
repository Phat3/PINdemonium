#include "stdafx.h"
#include "PINdemoniumPluginTemplate.h"
#include "Helpers.h"
#include "libdasm.h"
#include <string.h>


void runPlugin(static HANDLE hProcess, PUNRESOLVED_IMPORT unresolvedImport, unsigned int eip){

	DWORD_PTR invalidApiAddress = 0;
	INSTRUCTION inst;
	int max_instruction_size = sizeof(UINT8)*15;
	LPVOID instruction_buffer = (LPVOID)malloc(max_instruction_size);
	int instruction_size;
	char buffer[200];

	while (unresolvedImport->ImportTableAddressPointer != 0){ //last element is a nulled struct
		
		printf("Unresolved : 0x%08x\n", unresolvedImport->InvalidApiAddress);

		invalidApiAddress = unresolvedImport->InvalidApiAddress;
		readMemoryFromProcess(hProcess, invalidApiAddress, max_instruction_size, instruction_buffer);

		instruction_size = get_instruction(&inst, (BYTE *)instruction_buffer, MODE_32);
		get_instruction_string(&inst, FORMAT_ATT, 0, buffer, sizeof(buffer));
		printf("INS: %s\n",buffer);

		if(inst.type == INSTRUCTION_TYPE_PUSH){
			    //pushl $0x770fdfa4 
			 char *pch = strstr (buffer,"0x");
			 //printf("ADDRESS: %s\n",pch);
			 unsigned int correct_address = (unsigned int)strtoul(pch,NULL,16);
			 printf("ADDRESS: %08x\n",correct_address);
			 bool res = writeMemoryToProcess(hProcess, (DWORD_PTR)(unresolvedImport->ImportTableAddressPointer), sizeof(correct_address), &correct_address);
			 printf("writeMemoryToProcess result %d\n" , res);
		}else{
			if(inst.type == INSTRUCTION_TYPE_JMP){
				// jmp 0x73d3673d
			    //printf("ADDRESS: %s\n",pch);

			   unsigned int correct_address = ( (unsigned int)strtoul(strstr(buffer, "jmp") + 4 + 2, NULL, 16)) + invalidApiAddress;
			
			  //printf("ADDRESS: %08x\n",correct_address);
			  bool res =  writeMemoryToProcess(hProcess, (DWORD_PTR)(unresolvedImport->ImportTableAddressPointer), sizeof(correct_address), &correct_address);
			  //printf("writeMemoryToProcess result %d\n" , res);
			}
		}

		//if libdasm fails to recognize the insruction bypass this instruction
		if(instruction_size == 0){
			invalidApiAddress = invalidApiAddress + 1;
			continue;
		}

		unresolvedImport++; //next pointer to struct
	
	}
	
}