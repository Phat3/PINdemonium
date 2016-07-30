#include "YaraHeuristic.h"


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
    W::BOOL bSuccess = FALSE;
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
Parse yara output and return a vector containing the matched rules as string
*/
vector<string> YaraHeuristic::parseYaraOutput(string output){
	vector<string> matched_rules;
	istringstream output_stream(output); 
	for(string line; getline(output_stream,line);){ // iterate through lines
		try{
			string matched_string = Helper::split(line,' ').at(0);
			MYINFO("Adding matched Yara rule %s",matched_string.c_str());
			matched_rules.push_back(matched_string); 
		}
		catch (const std::out_of_range&){
		}	
	}
	return matched_rules;
}

vector<string> YaraHeuristic::analyseYara(string dump_to_analyse){

	string yara_rules_path = Config::getInstance()->getYaraRulesPath();
	string yara_exe_path = Config::getInstance()->getYaraExePath();	
	string yara_res_file = Config::getInstance()->getYaraResultPath();
	
	string raw_output = "";
	vector<string> matched_rules;
	W::SECURITY_ATTRIBUTES sa; 
    // Set the bInheritHandle flag so pipe handles are inherited. 
    sa.nLength = sizeof(W::SECURITY_ATTRIBUTES); 
    sa.bInheritHandle = TRUE; 
    sa.lpSecurityDescriptor = NULL; 

    // Create a pipe for the child process's STDOUT. 
    if ( ! W::CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &sa, 0) ) {
		MYERRORE("Error creating Pipe for Yara");
        return vector<string>(); 
    }
    // Ensure the read handle to the pipe for STDOUT is not inherited
    if ( ! W::SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) ){
		MYERRORE("Error creating Pipe for Yara");
        return vector<string>(); 
    }
	W::PROCESS_INFORMATION  piResults;
	if(launchYara(yara_exe_path,yara_rules_path, dump_to_analyse, yara_res_file,&piResults )){

		raw_output = ReadFromPipe(piResults);
		matched_rules = parseYaraOutput(raw_output);
		//MYINFO("Yara raw output result %s",raw_output.c_str());
	}
	else{
		MYERRORE("error launching Yara");
	}
	return matched_rules;

}


UINT32 YaraHeuristic::run(vector<string> paths_to_analyse){
	
	vector<string> global_matched_rules;
	bool result = false;
	for(vector<string>::iterator dump_to_analyse = paths_to_analyse.begin(); dump_to_analyse != paths_to_analyse.end(); dump_to_analyse++){
		vector<string> cur_matched_rules = analyseYara(*dump_to_analyse);
		global_matched_rules.insert(global_matched_rules.end(),cur_matched_rules.begin(),cur_matched_rules.end());
	}
	
	if(!global_matched_rules.empty()){
		result = true;
	}

	//Saving the information to the report
	try{
		ReportDump& report_dump = Report::getInstance()->getCurrentDump();
		ReportObject* yara_heur = new ReportYaraRules(result, global_matched_rules);
		report_dump.addHeuristic(yara_heur);
	}
	catch (const std::out_of_range& ){
		MYERRORE("Problem creating ReportYaraRules report");
	}	

	
	return 0;
}




BOOL YaraHeuristic::launchYara(std::string yara_path, std::string yara_rules_path, std::string yara_input_path,std::string yara_output,W::PROCESS_INFORMATION * piResults){
	//string YaraLauncherBat = Config::getInstance()->getBasePath() + YARA_LAUNCHER;

	//Running external idaPython script
	W::STARTUPINFO si ={0};
	si.hStdOutput = g_hChildStd_OUT_Wr;
    si.dwFlags |= STARTF_USESTDHANDLES;
	W::PROCESS_INFORMATION pi ={0};

	si.cb=sizeof(si);
	

	//NB There can be problem if using spaces inside the path

	std::string yara_arguments =  yara_path  + " " +                        //path to yara executable
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

