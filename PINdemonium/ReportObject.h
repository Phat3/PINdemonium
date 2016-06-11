#pragma once
#include "pin.H"
#include "json.h"


class ReportObject
{
public:
	ReportObject(void);
	virtual Json::Value toJson()
		{return NULL;}
};

