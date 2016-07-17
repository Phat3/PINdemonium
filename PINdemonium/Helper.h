#pragma once
#include "pin.H"
#include <sstream>

namespace W{
		#include "windows.h"
}

class Helper
{
public:
	Helper(void);
	static BOOL existFile (string name);
	static 	vector<string> split(const string &s, char delim);
	static string replaceString(string str, const string& from, const string& to);
	static bool writeBufferToFile(unsigned char *buffer,UINT32 dwBytesToWrite,string path);
};

