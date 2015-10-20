#pragma once
#include "pin.H"
#include "WxorXHandler.h"
extern "C"{
	#include "xed-interface.h"
}

class InitFunctionCall
{
public:
	InitFunctionCall(void);
	~InitFunctionCall(void);
	UINT32 run(WriteInterval wi);
private:
	xed_machine_mode_enum_t mmode;
    xed_address_width_enum_t stack_addr_width;
};

