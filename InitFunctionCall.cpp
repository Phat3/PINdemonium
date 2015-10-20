#include "InitFunctionCall.h"

//define based on the architecture 32/64bit
#define XED_32_BIT_BUILD 

	


InitFunctionCall::InitFunctionCall(void)
{
	xed_machine_mode_enum_t mmode;
    xed_address_width_enum_t stack_addr_width;
    xed_bool_t long_mode = 0;
	 // initialize the XED tables -- one time.
    xed_tables_init();

	xed_tables_init();
	#ifdef XED_32_BIT_BUILD
		mmode=XED_MACHINE_MODE_LEGACY_32;
		stack_addr_width = XED_ADDRESS_WIDTH_32b;
	#else
	    mmode=XED_MACHINE_MODE_LONG_64;
        stack_addr_width = XED_ADDRESS_WIDTH_64b;
    #endif


}


InitFunctionCall::~InitFunctionCall(void)
{
}

UINT32 InitFunctionCall::run(WriteInterval wi){
	
	MYLOG("Testing if an Init function is called inside the WriteInterval");
	int w_int_size = wi.getAddrEnd() - wi.getAddrBegin();
	unsigned int bytes = 0;
	MYLOG("WriteINt size: %d",w_int_size );

	unsigned char *inst_buffer = (unsigned char *)malloc(w_int_size);	
	
	PIN_SafeCopy(inst_buffer,(void *)(wi.getAddrBegin()),w_int_size);
	
	MYLOG("first bytes at inst_buffer: %x  first bytes at writeItem: %x",*inst_buffer,*((char *)wi.getAddrBegin()));
	FILE *fd = fopen("./WItemdump.bin","w");
	fwrite(inst_buffer,w_int_size,1,fd);
	fclose(fd);
	MYLOG("Dump Created");
	


	return 0;
}
