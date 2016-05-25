#pragma once

#define VERBOSE 1 
#define DEBUG_BUILD 1
#define INFO_BUILD  1
#define WARN_BUILD  1
#define ERROR_BUILD 1
#define LOG_BUILD 1

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define MYDEBUG(fmt, ...) \
	do { if (DEBUG_BUILD) fprintf(stderr, "[DEBUG](%s):%d:%s(): " fmt, __FILENAME__, \
								__LINE__, __FUNCTION__, __VA_ARGS__); } while (0)
#ifdef VERBOSE
#define MYWARN(fmt, ...) \
	do { if (WARN_BUILD) fprintf(Config::getInstance()->getLogFile(),"[WARNING](%s) "fmt"\n",__FILENAME__, __VA_ARGS__);fflush(Config::getInstance()->getLogFile()); } while (0)
#else
#define MYWARN(fmt,...)
#endif

#ifdef VERBOSE
#define MYERRORE(fmt, ...) \
	do { if (ERROR_BUILD) fprintf(Config::getInstance()->getLogFile(),"[ERROR](%s) "fmt"\n",__FILENAME__, __VA_ARGS__);fflush(Config::getInstance()->getLogFile()); } while (0)
#else
#define MYERRORE(fmt,...)
#endif

#ifdef VERBOSE
#define MYINFO(fmt, ...) \
	do { if (LOG_BUILD){ fprintf(Config::getInstance()->getLogFile(),"[INFO](%s) "fmt"\n",__FILENAME__, __VA_ARGS__);fflush(Config::getInstance()->getLogFile()); } } while (0)
#else
#define MYINFO(fmt, ...)
#endif

#ifdef VERBOSE
#define MYPRINT(fmt, ...) \
	do { if (LOG_BUILD){ fprintf(Config::getInstance()->getLogFile(),fmt"\n", __VA_ARGS__); fflush(Config::getInstance()->getLogFile()); } } while (0)
#else
#defone MYPRINT(fmt,...)
#endif

#define MYTEST(fmt, ...) \
	do { if (LOG_BUILD){ fprintf(Config::getInstance()->getTestFile(),fmt"\n", __VA_ARGS__); fflush(Config::getInstance()->getTestFile());exit(0); } } while (0)

#define CLOSELOG()\
	do { if (LOG_BUILD){ Config::getInstance()->closeLogFile();}}while (0)



