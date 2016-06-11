#pragma once
#include "pin.H"


class ReportObject
{
public:
	ReportObject(void);
	virtual string toJson()
		{return "";}
};

