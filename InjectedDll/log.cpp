#include "pch.h"
#include "log.h"
#include <fstream>
#include <mutex>

struct Logger
{
	std::mutex mutex;
	std::fstream file;

	Logger()
	{
		file.open("mediacontrol.log", std::ios::out);
	}
};

Logger& getLogger()
{
	static Logger logger;
	return logger;
}

void Log::write(const std::string& message)
{
	auto& logger = getLogger();
	std::lock_guard<std::mutex> lock(logger.mutex);
	logger.file << message << "\n";
	logger.file.flush();
}

void Log::write(const char* message)
{
	auto& logger = getLogger();
	std::lock_guard<std::mutex> lock(logger.mutex);
	logger.file << message << "\n";
	logger.file.flush();
}
