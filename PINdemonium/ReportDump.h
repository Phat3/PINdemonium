#pragma once
#include "pin.H"
#include "ReportObject.h"

class ReportDump : public ReportObject
{
public:
	ReportDump();
	ReportDump(ADDRINT eip,ADDRINT start_addr, ADDRINT end_addr, int dump_number, bool intra_writeset);
	Json::Value ReportDump::toJson();

private:
	int number;
	bool intra_writeset;
	ADDRINT eip;
	ADDRINT start_address;
	ADDRINT end_address;
	int reconstructed_imports;
	int total_imports;
	vector<ReportObject *> heuristics;



};

