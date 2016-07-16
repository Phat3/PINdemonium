#pragma once
#include "pin.H"
#include "ReportObject.h"
#include "Debug.h"
#include "Log.h"

class ReportDump : public ReportObject
{
public:
	ReportDump();
	ReportDump(ADDRINT eip,ADDRINT start_addr, ADDRINT end_addr, int dump_number, bool intra_writeset,int pid);
	Json::Value ReportDump::toJson();
	void addHeuristic(ReportObject*);
	void setImportedFunctions(vector<ReportObject *>);
	void setNumberOfImports( int imports_number);

private:
	int number;
	bool intra_writeset;
	ADDRINT eip;
	ADDRINT start_address;
	ADDRINT end_address;
	int pid;
	int reconstructed_imports;
	int total_imports;
	vector<ReportObject *> imported_functions;
	/*
		In order to create a new heuristic Report you need:
		1. Create a class (like ReportLongJump) which contains the information needed as attributes
		2. Make this class inherit from the abstract class ReportObject the method toJson and implement it
		3. Invoke the method ReportDump::addHeuristic(ReportObject* heur) when the new heuristic object has been created 
			Example:
			ReportDump& report_dump = Report::getInstance()->getCurrentDump();
			ReportObject* long_jmp_heur = new ReportLongJump(result,prev_ip, diff);
			report_dump.addHeuristic(long_jmp_heur);	
	*/
	vector<ReportObject *> heuristics;
	



};

