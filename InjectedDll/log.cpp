#include "pch.h"
#include "log.h"
#include <chrono>
#include <format>
#include <fstream>
#include <mutex>

std::string logPrefix()
{
	auto now = std::chrono::system_clock::now();
	std::time_t t = std::chrono::system_clock::to_time_t(now);
	std::tm tm_buf;
	localtime_s(&tm_buf, &t);

	return std::format(
		"[{:04}-{:02}-{:02} {:02}:{:02}:{:02}] ",
		tm_buf.tm_year + 1900,  // years since 1900
		tm_buf.tm_mon + 1,      // months since January [0,11]
		tm_buf.tm_mday,         // day of month [1,31]
		tm_buf.tm_hour,         // hours [0,23]
		tm_buf.tm_min,          // minutes [0,59]
		tm_buf.tm_sec           // seconds [0,60] (leap second possible)
	);
}

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
	logger.file << logPrefix() << message << "\n";
	logger.file.flush();
}

void Log::write(const char* message)
{
	auto& logger = getLogger();
	std::lock_guard<std::mutex> lock(logger.mutex);
	logger.file << logPrefix() << message << "\n";
	logger.file.flush();
}
