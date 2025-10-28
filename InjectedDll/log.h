#pragma once

#include <string>

class Log
{
public:
	static void write(const std::string& message);
	static void write(const char* message);
};