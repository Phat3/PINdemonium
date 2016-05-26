#pragma once
#include "stdafx.h"

// List of the exported function

// Entry point of the plugin
// This function will be called PINdemonium
void runPlugin(static HANDLE hProcess, PUNRESOLVED_IMPORT unresolvedImport, unsigned int eip);