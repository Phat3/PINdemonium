#include "HookSyscalls.h"


//----------------------------- SYSCALL HOOKS -----------------------------//

static int testing = 0;

void HookSyscalls::syscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
	//get the syscall number
	unsigned long syscall_number = PIN_GetSyscallNumber(ctx, std);
	// int 0x2e probably leaves ctx in a corrupted state and we have an undefined behavior here, 
	// the syscall_number will result in a 0 and this isn't correct, the crash is inside the function PIN_GetSyscallArguments.
	// According to PIN documentation: Applying PIN_GetSyscallArguments() to an inappropriate context results in undefined behavior and even may cause 
	// crash on systems in which system call arguments are located in memory.
	// The incriminated syscall is executed after the int 0x2e, before the next instruction, just for now filter out the 0 syscall since we don't use it at all...
	if(syscall_number == 0){
		MYINFO("Number of syscall is %d\n", syscall_number);
		return;
	}
	//fill the structure with the provided info
	syscall_t *sc = &((syscall_t *) v)[thread_id];	
	sc->syscall_number = syscall_number;
	//get the arguments pointer
	// 8 = number of the argument to be passed
	// 0 .. 7 -> &sc->arg0 .. &sc->arg7 = correspondence between the index of the argument and the struct field to be loaded
	HookSyscalls::syscallGetArguments(ctx, std, 8, 0, &sc->arg0, 1, &sc->arg1, 2, &sc->arg2, 3, &sc->arg3, 4, &sc->arg4, 5, &sc->arg5, 6, &sc->arg6, 7, &sc->arg7);
	//HookSyscalls::printArgs(sc);
	std::map<unsigned long, string>::iterator syscallMapItem = syscallsMap.find(sc->syscall_number);
	//search for an hook on entry
	if(syscallMapItem !=  syscallsMap.end()){
		//search if we have an hook for the syscall
		std::map<string, syscall_hook>::iterator syscallHookItem = syscallsHooks.find(syscallMapItem->second + "_entry");
		if(syscallHookItem != syscallsHooks.end()){
			//if so call the hook
			syscallHookItem->second(sc, ctx, std);
		}
	}
}

void HookSyscalls::syscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
	//get the structure with the informations on the systemcall
	syscall_t *sc = &((syscall_t *) v)[thread_id];
	//search forn an hook on exit
	std::map<unsigned long, string>::iterator syscallMapItem = syscallsMap.find(sc->syscall_number);

	if(syscallMapItem !=  syscallsMap.end()){
		//serch if we have an hook for the syscall
		std::map<string, syscall_hook>::iterator syscallHookItem = syscallsHooks.find(syscallMapItem->second + "_exit");
		if(syscallHookItem != syscallsHooks.end()){
			//if so call the hook
			syscallHookItem->second(sc, ctx, std);
		}
	}	
}

//Avoid Pin detection based on NtSystemQueryInformation 
void HookSyscalls::NtQuerySystemInformationHookExit(syscall_t *sc, CONTEXT *ctx, SYSCALL_STANDARD std){
	if(sc->arg0 == SYSTEM_PROCESS_INFORMATION){
		//cast to our structure in order to retrieve the information returned from the NtSystemQueryInformation function
		PSYSTEM_PROCESS_INFO spi;
		spi = (PSYSTEM_PROCESS_INFO)sc->arg1;
		//iterate through all processes 
		while(spi->NextEntryOffset){
			//if the process is pin change it's name in cmd.exe in order to avoid evasion
			if(spi->ImageName.Buffer && ( (wcscmp(spi->ImageName.Buffer, L"pin.exe") == 0))){
				wcscpy(spi->ImageName.Buffer, L"cmd.exe");
			}
			spi=(PSYSTEM_PROCESS_INFO)((W::LPBYTE)spi+spi->NextEntryOffset); // Calculate the address of the next entry.
		} 
	}
}






void HookSyscalls::NtAllocateVirtualMemoryHook(syscall_t *sc , CONTEXT *ctx , SYSCALL_STANDARD std){
	W::PVOID base_address_pointer = (W::PVOID) sc->arg1;
	W::PSIZE_T region_size_address = (W::PSIZE_T) sc->arg3;
	ADDRINT heap_address = *(ADDRINT *)base_address_pointer;
	W::SIZE_T region_size = *(W::SIZE_T *)region_size_address;
    ProcInfo *proc_info = ProcInfo::getInstance();
	HeapZone hz;
	hz.begin = heap_address;
	hz.size = region_size;
    hz.end = region_size+heap_address;
	hz.version = 0; // version 0 of this heap

	std::string heap_key =  std::to_string((_ULonglong)hz.begin) + std::to_string((_ULonglong)hz.end);

	std::string hz_md5 = md5(heap_key);

	//MYINFO("NtAllocateVirtualMemoryHook insert in Heap Zone %08x -> %08x MD5(begin_addr+end_addr): %s",hz.begin,hz.end,hz_md5.c_str());
	//saving this heap zone in the map inside ProcInfo
	proc_info->insertHeapZone(hz_md5,hz); 
}


// Avoid PIN detection through NtQueryInformationProcessHook
void HookSyscalls::NtQueryInformationProcessHook(syscall_t *sc , CONTEXT *ctx , SYSCALL_STANDARD std){
	if( sc->arg1 == 0x1f){
		unsigned int  * pdebug_flag = (unsigned int *)sc->arg2;
		memset(pdebug_flag,0x00000001,1);
	}
}

void HookSyscalls::NtMapViewOfSectionHook(syscall_t *sc , CONTEXT *ctx , SYSCALL_STANDARD std){
	W::HANDLE process = (W::HANDLE)sc->arg1;
	W::PVOID *BaseAddress = (W::PVOID *) sc->arg2;
	W::PSIZE_T ViewSize = (W::PSIZE_T) sc->arg6;
	W::DWORD pid = W::GetProcessId(process);

	// MYINFO("-------------------- Write Injection through NtMapViewOfSectionHook pid %d  baseAddr %08x Size %08x",pid,*BaseAddress,*ViewSize);
	if(pid != W::GetCurrentProcessId()){
		MYINFO("Write Injection through NtMapViewOfSectionHook pid %d  baseAddr %08x Size %08x",pid,*BaseAddress,*ViewSize);
		ProcessInjectionModule::getInstance()->AddInjectedWrite((ADDRINT)*BaseAddress, *ViewSize,  pid );
	}
	
}


void HookSyscalls::NtWriteVirtualMemoryHook(syscall_t *sc , CONTEXT *ctx, SYSCALL_STANDARD std){
	W::HANDLE process = (W::HANDLE)sc->arg0;
	W::PVOID address_to_write = (W::PVOID)sc->arg1; // get the address where the syscall is writing 
	W::ULONG number_of_bytes_to_write = (W::ULONG)sc->arg3; // get how many bytes it is trying to write 
	W::DWORD injected_pid = W::GetProcessId(process);
	if(injected_pid != W::GetCurrentProcessId()){
		MYINFO("Write Injection through NtWriteVirtualMemoryHook pid %d  baseAddr %08x Size %08x",injected_pid,address_to_write,number_of_bytes_to_write);
		ProcessInjectionModule::getInstance()->AddInjectedWrite((ADDRINT)address_to_write, number_of_bytes_to_write,  injected_pid );
	}
}

void HookSyscalls::NtCreateThreadExHook(syscall_t *sc , CONTEXT *ctx , SYSCALL_STANDARD std){
	W::HANDLE process = (W::HANDLE)sc->arg3;
	W::DWORD injected_pid = W::GetProcessId(process);
	if(injected_pid != W::GetCurrentProcessId()){
		ProcessInjectionModule::getInstance()->CheckInjectedExecution(injected_pid );
	}
}

void HookSyscalls::NtResumeThreadHook(syscall_t *sc , CONTEXT *ctx , SYSCALL_STANDARD std){
	W::HANDLE thread = (W::HANDLE)sc->arg0;
	W::DWORD injected_pid = W::GetProcessIdOfThread(thread);
	if(injected_pid != W::GetCurrentProcessId()){
		ProcessInjectionModule::getInstance()->CheckInjectedExecution(injected_pid );
	}
}

void HookSyscalls::NtQueueApcThreadHook(syscall_t *sc , CONTEXT *ctx , SYSCALL_STANDARD std){
	W::HANDLE thread = (W::HANDLE)sc->arg0;
	W::DWORD injected_pid = W::GetProcessIdOfThread(thread);
	if(injected_pid != W::GetCurrentProcessId()){
		ProcessInjectionModule::getInstance()->CheckInjectedExecution(injected_pid );
	}
}





//----------------------------- END HOOKS -----------------------------//


//----------------------------- HELPER METHODS -----------------------------//

// stole this lovely source code from godware from the rreat library.
void HookSyscalls::enumSyscalls()
{
    // no boundary checking at all, I assume ntdll is not malicious..
    // besides that, we are in our own process, _should_ be fine..
    unsigned char *image = (unsigned char *) W::GetModuleHandle("ntdll");
    W::IMAGE_DOS_HEADER *dos_header = (W::IMAGE_DOS_HEADER *) image;
    W::IMAGE_NT_HEADERS *nt_headers = (W::IMAGE_NT_HEADERS *)(image +
        dos_header->e_lfanew);
    W::IMAGE_DATA_DIRECTORY *data_directory = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    W::IMAGE_EXPORT_DIRECTORY *export_directory =(W::IMAGE_EXPORT_DIRECTORY *)(image + data_directory->VirtualAddress);
    unsigned long *address_of_names = (unsigned long *)(image + export_directory->AddressOfNames);
    unsigned long *address_of_functions = (unsigned long *)(image + export_directory->AddressOfFunctions);
    unsigned short *address_of_name_ordinals = (unsigned short *)(image + export_directory->AddressOfNameOrdinals);
    unsigned long number_of_names = MIN(export_directory->NumberOfFunctions, export_directory->NumberOfNames);
    for (unsigned long i = 0; i < number_of_names; i++) {
        const char *name = (const char *)(image + address_of_names[i]);
        unsigned char *addr = image + address_of_functions[address_of_name_ordinals[i]];
        if(!memcmp(name, "Zw", 2) || !memcmp(name, "Nt", 2)) {
            // does the signature match?
            // either:   mov eax, syscall_number ; mov ecx, some_value
            // or:       mov eax, syscall_number ; xor ecx, ecx
            // or:       mov eax, syscall_number ; mov edx, 0x7ffe0300
            if(*addr == 0xb8 && (addr[5] == 0xb9 || addr[5] == 0x33 || addr[5] == 0xba)) {
                unsigned long syscall_number = *(unsigned long *)(addr + 1);
				string syscall_name = string(name);
				syscallsMap.insert(std::pair<unsigned long,string>(syscall_number,syscall_name));				
            }
        }
    }
}

void HookSyscalls::initHooks(){

	syscallsHooks.insert(std::pair<string,syscall_hook>("NtQuerySystemInformation_exit",&HookSyscalls::NtQuerySystemInformationHookExit));

	syscallsHooks.insert(std::pair<string,syscall_hook>("NtAllocateVirtualMemory_exit",&HookSyscalls::NtAllocateVirtualMemoryHook));
	//hxxp://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html
	
	syscallsHooks.insert(std::pair<string,syscall_hook>("NtQueryInformationProcess_exit",&HookSyscalls::NtQueryInformationProcessHook));
	
	syscallsHooks.insert(std::pair<string,syscall_hook>("NtWriteVirtualMemory_entry",&HookSyscalls::NtWriteVirtualMemoryHook));
	syscallsHooks.insert(std::pair<string,syscall_hook>("NtMapViewOfSection_exit",&HookSyscalls::NtMapViewOfSectionHook));
	syscallsHooks.insert(std::pair<string,syscall_hook>("NtCreateThreadEx_entry",&HookSyscalls::NtCreateThreadExHook));
	syscallsHooks.insert(std::pair<string,syscall_hook>("NtQueueApcThread_entry",&HookSyscalls::NtQueueApcThreadHook));
	syscallsHooks.insert(std::pair<string,syscall_hook>("NtResumeThread_entry",&HookSyscalls::NtResumeThreadHook));


	


	
	// allocate syscall information struct
	static syscall_t sc[256] = {0};
	PIN_AddSyscallEntryFunction(&HookSyscalls::syscallEntry,&sc);
    PIN_AddSyscallExitFunction(&HookSyscalls::syscallExit,&sc);

}

//get the pointer to the syscall arguments
//stole this lovely source code from godware
void HookSyscalls::syscallGetArguments(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...)
{
    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        int index = va_arg(args, int);
        ADDRINT *ptr = va_arg(args, ADDRINT *);
        *ptr = PIN_GetSyscallArgument(ctx, std, index);
    }
    va_end(args);
}

void HookSyscalls::printArgs(syscall_t * sc){
	printf("arg0 : %08x\n", sc->arg0);
	printf("arg1 : %08x\n", sc->arg1);
	printf("arg2 : %08x\n", sc->arg2);
	printf("arg3 : %08x\n", sc->arg3);
	printf("arg4 : %08x\n", sc->arg4);
	printf("arg5 : %08x\n", sc->arg5);
	printf("arg6 : %08x\n", sc->arg6);
	printf("arg7 : %08x\n", sc->arg7);
}

void HookSyscalls::printRegs(CONTEXT *ctx){
	printf("EAX : %08x\n", PIN_GetContextReg(ctx, REG_EAX));
	printf("EBX : %08x\n", PIN_GetContextReg(ctx, REG_EBX));
	printf("ECX : %08x\n", PIN_GetContextReg(ctx, REG_ECX));
	printf("EDX : %08x\n", PIN_GetContextReg(ctx, REG_EDX));
}

