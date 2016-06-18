#include "YaraHeuristic.h"

#define YARA_LAUNCHER "YaraLauncher.bat"


#define YARA_PATH "C:\\pin\\PINdemoniumDependencies\\Yara\\yara32.exe"
#define YARA_RULES "C:\\pin\\PINdemoniumDependencies\\Yara\\yara_rules.yar"

BOOL YaraHeuristic::existFile (std::string name) {
	if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}



/**
	Get the size of the file passed as fp
**/
UINT32 YaraHeuristic::getFileSize(FILE * fp){
	fseek(fp, 0L, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
return size;
}

// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
// Stop when there is no more data. 
string YaraHeuristic::ReadFromPipe(W::PROCESS_INFORMATION piProcInfo) {
    W::DWORD dwRead; 
    CHAR chBuf[PIPE_BUFSIZE];
    bool bSuccess = FALSE;
    std::string out = "", err = "";
    for (;;) { 
        bSuccess=W::ReadFile( g_hChildStd_OUT_Rd, chBuf, PIPE_BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break; 

        std::string s(chBuf, dwRead);
        out += s;
    } 
    dwRead = 0;
   return  out ;

}

/*
Split a string in an array based on a delimiter character
*/
vector<string> YaraHeuristic::split(const string &s, char delim) {
    vector<string> elems;
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}
/*
Parse yara output and return a vector containing the matched rules as string
*/
vector<string> YaraHeuristic::parseYaraOutput(string output){
	vector<string> matched_rules;
	istringstream output_stream(output); 
	for(string line; getline(output_stream,line);){ // iterate through lines
		MYINFO("current line %s",line.c_str());
		try{
			string matched_string = split(line,' ').at(0);
			MYINFO("Adding rule %s",matched_string.c_str());
			matched_rules.push_back(matched_string); 
		}
		catch (const std::out_of_range& e){
		}	
	}
	return matched_rules;
}


UINT32 YaraHeuristic::run(){
	


	string yara_res_file = Config::getInstance()->getYaraResultPath();
	string  dumpFile = Config::getInstance()->getCurrentDumpFilePath();
	bool result= false;
	string raw_output = "";
	vector<string> matched_rules;
	if(!existFile(dumpFile)){
		MYERRORE("Dump file hasn't been created");
		return -1;
	}

	
	W::SECURITY_ATTRIBUTES sa; 
    // Set the bInheritHandle flag so pipe handles are inherited. 
    sa.nLength = sizeof(W::SECURITY_ATTRIBUTES); 
    sa.bInheritHandle = TRUE; 
    sa.lpSecurityDescriptor = NULL; 

    // Create a pipe for the child process's STDOUT. 
    if ( ! W::CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &sa, 0) ) {
		MYERRORE("Error creating Pipe for Yara");
        return -1; 
    }
    // Ensure the read handle to the pipe for STDOUT is not inherited
    if ( ! W::SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) ){
		MYERRORE("Error creating Pipe for Yara");
        return -1; 
    }
	W::PROCESS_INFORMATION  piResults;
	if(launchYara(YARA_PATH,YARA_RULES, dumpFile, yara_res_file,&piResults )){
		result =true;
		raw_output = ReadFromPipe(piResults);
		matched_rules = parseYaraOutput(raw_output);
		MYINFO("Yara raw output result %s",raw_output.c_str());
	}
	else{
		MYERRORE("error launching Yara");
	}

	ReportDump& report_dump = Report::getInstance()->getCurrentDump();
	ReportObject* yara_heur = new ReportYaraRules(result, matched_rules);
	report_dump.addHeuristic(yara_heur);

	
	return 0;
}




BOOL YaraHeuristic::launchYara(string yara_path, string yara_rules_path, string yara_input_path,string yara_output,W::PROCESS_INFORMATION * piResults){
	//string YaraLauncherBat = Config::getInstance()->getBasePath() + YARA_LAUNCHER;

	//Running external idaPython script
	W::STARTUPINFO si ={0};
	si.hStdOutput = g_hChildStd_OUT_Wr;
    si.dwFlags |= STARTF_USESTDHANDLES;
	W::PROCESS_INFORMATION pi ={0};

	si.cb=sizeof(si);
	

	//NB There can be problem if using spaces inside the path

	string yara_arguments =  yara_path  + " " +                        //path to yara executable
                             yara_rules_path + " " +     //path to yara rules
							 yara_input_path;       //path to yara input file




	// Create a file batch which run the IdaPython script and execute it
	/*FILE *YaraLauncherFile = fopen(YaraLauncherBat.c_str(),"w");
	fwrite(YaraLauncher.c_str(),strlen(YaraLauncher.c_str()),1,YaraLauncherFile);
	fclose(YaraLauncherFile);*/

	MYINFO("Launching  Yara executable %s command line %s ",yara_path.c_str(),yara_arguments.c_str());
	
	if(!W::CreateProcess(yara_path.c_str(),(char *)yara_arguments.c_str(),NULL,NULL,TRUE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi)){
		MYERRORE("Can't launch Yara Error %d",W::GetLastError());
		return false;
	}

	//Timeout 30 sec for the YARA processing
	W::WaitForSingleObject(pi.hProcess,30000);
	W::CloseHandle(pi.hProcess);
	W::CloseHandle(pi.hThread);
    W::CloseHandle(g_hChildStd_OUT_Wr);
	
	*piResults = pi;

	MYINFO("Yara Finished");
	return true;

}

