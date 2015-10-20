#include "pin.H"
#include "WriteInterval.h"
#include "OepFinder.h"
extern "C" {
	#include "xed-interface.h"
}


UINT32 test_heuristic(INS ins , WriteInterval wi){

	MYLOG("AWESOME");
	return OEPFINDER_FOUND_OEP;

}


UINT32 initFuncCalls(INS ins , WriteInterval wi){

	xed_machine_mode_enum_t mmode;
    xed_address_width_enum_t stack_addr_width;
    xed_bool_t long_mode = 0;
	 // initialize the XED tables -- one time.
    xed_tables_init();

    // The state of the machine -- required for decoding
    if (long_mode) {
        mmode=XED_MACHINE_MODE_LONG_64;
        stack_addr_width = XED_ADDRESS_WIDTH_64b;
    }
    else {
        mmode=XED_MACHINE_MODE_LEGACY_32;
        stack_addr_width = XED_ADDRESS_WIDTH_32b;
    }

	MYLOG("Test function calls");
	int w_int_size = wi.getAddrEnd() - wi.getAddrBegin();
	MYLOG("WriteINt size: %d",w_int_size );

	unsigned char *inst_buffer = (unsigned char *)malloc(w_int_size);
	MYLOG("inst buffer before Pin copy %x",*inst_buffer);
	MYLOG("Witem first byte before Pin copy  %x",*((char *)wi.getAddrBegin()+1));
	
	
	PIN_SafeCopy(inst_buffer,(void *)(wi.getAddrBegin()),w_int_size);
	
	MYLOG("first bytes at inst_buffer: %x  first bytes at writeItem: %x",*inst_buffer,*((char *)wi.getAddrBegin()+1));
	
	return OEPFINDER_FOUND_OEP;
}