#pragma once
#include "pin.H"
#include "json.h"


class ReportObject
{
protected:
	Json::Value root;
public:
	ReportObject(void);
	virtual Json::Value toJson(void) = 0;
};

