#include "HookFunctions.h"


HookFunctions::HookFunctions(void)
{
	this->functionsMap.insert( std::pair<string,int>("VirtualAlloc",VIRTUALALLOC_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("RtlAllocateHeap",RTLALLOCATEHEAP_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("IsDebuggerPresent",ISDEBUGGERPRESENT_INDEX) );
	this->functionsMap.insert( std::pair<string,int>("GetTickCount",3) );

	this->enumSyscalls();
	//this->printSyscalls();
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


VOID GetTickCountHook(UINT32 ticks , CONTEXT *ctx){
	
	if(flag_time==0){
	
		flag_time = 1;
		first_cc = (ticks * frequency)/ms;
		first_ticks = first_cc * 1/frequency * ms;

		MYINFO("Memorized %I64d CC\n" , first_cc);
		MYINFO("Memorized %I64d Ticks\n" , first_ticks);

		PIN_SetContextReg(ctx, REG_EAX, 1);	
	}
	else{
	
		unsigned __int64 now_cc = (ticks * frequency)/ms; // get the current cc based on the ticks 
		unsigned __int64 cc_rdtsc = __rdtsc(); // test if the previous expression is ok against this value 

		MYINFO("now_cc is %I64d | cc_rdtsc is %I64d\n" , now_cc , cc_rdtsc);

		unsigned __int64 ticks_now = now_cc * 1/frequency * ms;

		MYINFO("first_ticks is %I64d\n" , first_ticks);
		MYINFO("ticks_now is %I64d\n" , ticks_now);


		unsigned __int64 delta_ticks = ticks_now - first_ticks;

		MYINFO("Original delta in ticks is %I64d\n" , delta_ticks);

		unsigned __int64 delta_cc = now_cc - first_cc;  // what is the delta of CCs passed from the starting of the program? 
		
		
		MYINFO("Original delta in CC is %I64d\n" , delta_cc);

		unsigned __int64 divisor = 2;

		unsigned __int64 fake_delta_cc = delta_cc / divisor;	

		MYINFO("fake_delta in CC is %I64d\n" , fake_delta_cc);

		unsigned __int64 new_now_cc = first_cc + fake_delta_cc;

		MYINFO("new_now_cc is %I64d\n" , new_now_cc);

		unsigned __int64 new_ticks_now = new_now_cc * 1/frequency * ms;

		MYINFO("new_ticks_now is %I64d\n" ,new_ticks_now);

		unsigned __int64 new_delta_ticks = new_ticks_now - first_ticks;

		MYINFO("Delta ticks elapsed fake is  %I64d\n" , new_delta_ticks);

		flag_time = 0;

		PIN_SetContextReg(ctx, REG_EAX, 1);	
	}
	
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
				case 3:
					   {
						REGSET regsIn;
						REGSET_AddAll(regsIn);
						REGSET regsOut;
						REGSET_AddAll(regsOut);
						RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)GetTickCountHook, IARG_G_RESULT0, IARG_PARTIAL_CONTEXT, &regsIn, &regsOut, IARG_END);
				       }
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