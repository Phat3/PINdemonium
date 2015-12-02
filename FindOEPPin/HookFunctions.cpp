#include "HookFunctions.h"

typedef struct _syscall_t {
    ADDRINT syscall_number;
    union {
        ADDRINT args[16];
        struct {
            ADDRINT arg0, arg1, arg2, arg3;
            ADDRINT arg4, arg5, arg6, arg7;
        };
    };
} syscall_t;

void syscall_get_arguments(CONTEXT *ctx, SYSCALL_STANDARD std, int count, ...)
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

void syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
	unsigned long syscall_number = PIN_GetSyscallNumber(ctx, std);
	//printf("%d\n", syscall_number);
	 if(syscall_number == 261){
		 syscall_t *sc = &((syscall_t *) v)[thread_id];
		 syscall_get_arguments(ctx, std, 8, 0, &sc->arg0, 1, &sc->arg1, 2, &sc->arg2, 3, &sc->arg3, 4, &sc->arg4, 5, &sc->arg5, 6, &sc->arg6, 7, &sc->arg7);
		 printf("ARG %d : %08x\n", 0, sc->arg0);
		 printf("ARG %d : %08x\n", 1, sc->arg1);
		 printf("ARG %d : %08x\n", 2, sc->arg2);
		 printf("ARG %d : %08x\n", 3, sc->arg3);
		 printf("ARG %d : %08x\n", 4, sc->arg4);
		 printf("ARG %d : %08x\n", 5, sc->arg5);
		 printf("ARG %d : %08x\n", 6, sc->arg6);
		 printf("ARG %d : %08x\n", 7, sc->arg7);
	 }
}

void syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v){
  
	 

}

void prova(){
	printf("BINDING OF ISAAC\n");
}

HookFunctions::HookFunctions(void)
{
	this->functionsMap.insert( std::pair<string,int>("VirtualAlloc",VIRTUALALLOC_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("RtlAllocateHeap",RTLALLOCATEHEAP_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("IsDebuggerPresent",ISDEBUGGERPRESENT_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("credere",3) );

	this->enumSyscalls();
	//this->printSyscalls();


	this->syscallsHooks.insert(std::pair<string,AFUNPTR>("NtQuerySystemInformation",&prova));

	static syscall_t sc[256] = {0};
	PIN_AddSyscallEntryFunction(&syscall_entry,&sc);
    PIN_AddSyscallExitFunction(&syscall_exit,&sc);
}


HookFunctions::~HookFunctions(void)
{
}


//----------------------------- HOOKED FUNCTIONS -----------------------------//

//hook the VirtualAlloc() in order to retrieve the memory range allocated and build ours data structures
VOID VirtualAllocHook(UINT32 virtual_alloc_size , UINT32 ret_heap_address ){
  
  ProcInfo *proc_info = ProcInfo::getInstance();

  HeapZone hz;
  hz.begin = ret_heap_address;
  hz.size = virtual_alloc_size;
  hz.end = ret_heap_address + virtual_alloc_size;

  //saving this heap zone in the map inside ProcInfo
  proc_info->insertHeapZone(hz); 

}

//hook the  HeapAllocHook() in order to retrieve the memory range allocated and build ours data structures
VOID HeapAllocHook(UINT32 heap_alloc_size , UINT32 ret_heap_address ){
	
	if (heap_alloc_size == 0){
		return;
	}

	ProcInfo *proc_info = ProcInfo::getInstance();

	HeapZone hz;
	hz.begin = ret_heap_address;
	hz.size = heap_alloc_size;
	hz.end = ret_heap_address + heap_alloc_size;

	//saving this heap zone in the map inside ProcInfo
	proc_info->insertHeapZone(hz); 

}

//REMEMBER!!! : PIN wants a function pointer in the AFUNCPTR agument!!!
//avoid the detection of the debugger replacing the function IsDebuggerPresent() with a new one that returns always false
//very basic way to avoid this anti-debugging technique
bool * IsDebuggerPresentHook(){
	return false;
}

//----------------------------- HOOKED DISPATCHER -----------------------------//

//scan the image and try to hook all the function specified above
void HookFunctions::hookDispatcher(IMG img){
	//for each function that we want to hook or replace
	for (std::map<string,int>::iterator item = this->functionsMap.begin(); item != this->functionsMap.end(); ++item){
		//get the pointer to the specified function
		const char * func_name = item->first.c_str();
		RTN rtn = RTN_FindByName( img, func_name);
		//if we found a valid routine
		if(rtn != RTN_Invalid()){
			
			ADDRINT va_address = RTN_Address(rtn);
			MYINFO("Address of %s: %08x\n" ,func_name, va_address);

			RTN_Open(rtn); 	
			int index = item->second;
			MYINFO("index of %s is %d",func_name,index);
			//decide what to do based on the function hooked
			//Different arguments are passed to the hooking routine based on the function
			switch(index){
				case(VIRTUALALLOC_INDEX):
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)VirtualAllocHook , IARG_G_ARG1_CALLEE , IARG_G_RESULT0, IARG_END);
					break;
				case(RTLALLOCATEHEAP_INDEX):
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)HeapAllocHook , IARG_G_ARG2_CALLEE, IARG_G_RESULT0, IARG_END);
					break;
				case(ISDEBUGGERPRESENT_INDEX):
					RTN_Replace(rtn, AFUNPTR(IsDebuggerPresentHook));
					break;

			}			
			RTN_Close(rtn);
		}
	}
}


//----------------------------- HOOKING OF SYSCALLS -----------------------------//

// stole this lovely source code from godware from the rreat library.
void HookFunctions::enumSyscalls()
{
    // no boundary checking at all, I assume ntdll is not malicious..
    // besides that, we are in our own process, _should_ be fine..
    unsigned char *image = (unsigned char *) W::GetModuleHandle("ntdll");

    W::IMAGE_DOS_HEADER *dos_header = (W::IMAGE_DOS_HEADER *) image;

    W::IMAGE_NT_HEADERS *nt_headers = (W::IMAGE_NT_HEADERS *)(image +
        dos_header->e_lfanew);

    W::IMAGE_DATA_DIRECTORY *data_directory = &nt_headers->
        OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    W::IMAGE_EXPORT_DIRECTORY *export_directory =
        (W::IMAGE_EXPORT_DIRECTORY *)(image + data_directory->VirtualAddress);

    unsigned long *address_of_names = (unsigned long *)(image +
        export_directory->AddressOfNames);

    unsigned long *address_of_functions = (unsigned long *)(image +
        export_directory->AddressOfFunctions);

    unsigned short *address_of_name_ordinals = (unsigned short *)(image +
        export_directory->AddressOfNameOrdinals);

    unsigned long number_of_names = MIN(export_directory->NumberOfFunctions,
        export_directory->NumberOfNames);

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
				this->syscallsMap.insert(std::pair<unsigned long,string>(syscall_number,syscall_name));
				
            }
        }
    }
}


void HookFunctions::printSyscalls(){

for(map<unsigned long, string >::const_iterator it = this->syscallsMap.begin(); it !=this->syscallsMap.end(); ++it)
{
    printf("SYSCALL NUMBER %d : %s\n" , it->first , it->second.c_str());

}

}