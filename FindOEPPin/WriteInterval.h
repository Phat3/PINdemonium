#pragma once

#include "pin.H"

class WriteInterval
{

public:
	//create a new WriteInterval 
	WriteInterval(ADDRINT addr_begin, ADDRINT addr_end);
	~WriteInterval(void);
	//check if we have to expand our interval
	BOOL checkUpdate(ADDRINT start_addr, ADDRINT end_addr);
	//check if a given address is inside our interval
	BOOL checkInside(ADDRINT ip);	
	//update our inteval with the new bounds
	VOID update(ADDRINT start_addr, ADDRINT end_addr);
	//getter
	ADDRINT getAddrBegin();
	ADDRINT getAddrEnd();
	UINT32 getEntropyFlag();
	UINT32 getLongJmpFlag();
	UINT32 getJmpOuterSectionFlag();
	UINT32 getPushadPopadflag();
	UINT32 getBrokenFlag();
	UINT32 getThreshold();
	//setter
	void setEntropyFlag(UINT32 flag);
	void setLongJmpFlag(UINT32 flag);
	void setJmpOuterSectionFlag(UINT32 flag);
	void setPushadPopadFlag(UINT32 flag);
	void setBrokenFlag(UINT32 flag);

private:
	ADDRINT addr_begin;
	ADDRINT addr_end;
	UINT32 entropy_flag;
	UINT32 long_jmp_flag;
	UINT32 jmp_outer_section_flag;
	UINT32 pushad_popad_flag;
	UINT32 broken_flag;

};

