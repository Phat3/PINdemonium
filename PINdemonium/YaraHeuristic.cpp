#include "YaraHeuristic.h"

#define YARA_LAUNCHER "YaraLauncher.bat"


#define YARA_PATH "C:\\pin\\PinUnpackerDependencies\\Yara\\yara32.exe"
#define YARA_RULES "C:\\pin\\PinUnpackerDependencies\\Yara\\yara_rules.yar"

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



UINT32 YaraHeuristic::run(){
	


	string yara_res_file = Config::getInstance()->getYaraResultPath();
	string  dumpFile = Config::getInstance()->getCurrentDumpFilePath();
	bool result= false;
	string output = "";
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
		output = ReadFromPipe(piResults);
		MYINFO("Yara result %s",output.c_str());
	}
	else{
		MYERRORE("error launching Yara");
	}

	ReportDump& report_dump = Report::getInstance()->getCurrentDump();
	ReportObject* yara_heur = new ReportYaraRules(result, output);
	report_dump.addHeuristic(yara_heur);

	
	return 0;
}




BOOL YaraHeuristic::launchYara(string yara_path, string yara_rules_path, string yara_input_path,string yara_output,W::PROCESS_INFORMATION * piResults){
	string YaraLauncherBat = Config::getInstance()->getBasePath() + YARA_LAUNCHER;

	//Running external idaPython script
	W::STARTUPINFO si ={0};
	si.hStdOutput = g_hChildStd_OUT_Wr;
    si.dwFlags |= STARTF_USESTDHANDLES;
	W::PROCESS_INFORMATION pi ={0};

	si.cb=sizeof(si);
	

	//Creating the string used to launch the idaPython script
	std::stringstream YaraLauncherStream;
	YaraLauncherStream << "\"" << yara_path  << "\"  -s ";                       //path to yara executable
	YaraLauncherStream << "\"" << yara_rules_path << "\"  ";      //path to yara rules
	YaraLauncherStream << "\"" << yara_input_path << "\" ";       //path to yara input file
	//YaraLauncherStream << "> \"" << yara_output << "\" 2&>1";         //path to output produced by yara
	string YaraLauncher = YaraLauncherStream.str();	 //string containing the yara launcher



	// Create a file batch which run the IdaPython script and execute it
	FILE *YaraLauncherFile = fopen(YaraLauncherBat.c_str(),"w");
	fwrite(YaraLauncher.c_str(),strlen(YaraLauncher.c_str()),1,YaraLauncherFile);
	fclose(YaraLauncherFile);

	MYINFO("Launching  Yara  %s ",YaraLauncherBat);
	
	
	if(!W::CreateProcess(YaraLauncherBat.c_str(),NULL,NULL,NULL,TRUE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi)){
		MYERRORE("Can't launch Yara ");
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

