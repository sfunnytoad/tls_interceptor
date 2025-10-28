#include "pch.h"
#include "log.h"
#include <fstream>

std::fstream& getLogFile()
{
	struct InitLogFile
	{
		std::fstream fs;
		InitLogFile()
		{
			fs.open("mediacontrol.log", std::ios::out);
		}
	};

	static InitLogFile initLog;
	return initLog.fs;
}

void Log::write(const std::string& message)
{
	auto& file = getLogFile();
	file << message << "\n";
	file.flush();
}

void Log::write(const char* message)
{
	auto& file = getLogFile();
	file << message << "\n";
	file.flush();
}
