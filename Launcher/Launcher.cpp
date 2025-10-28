// Launcher.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "safehandle.h"
#include "safeprocessmem.h"

#include <cstddef>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

constexpr char injectedDllPath[] = "mediacontrol.dll";
namespace fs = std::filesystem;

int main(int argc, const char* argv[])
{
	try
	{
		if (argc != 2)
		{
			std::cout << "Invalid program arguments.\n";
			return -1;
		}

		std::string targetPath = argv[1];
		auto dirPath = fs::path(targetPath).parent_path();

		// Launch target process.
		STARTUPINFOA startupInfo;
		PROCESS_INFORMATION processInfo;

		std::memset(&startupInfo, 0, sizeof(startupInfo));
		startupInfo.cb = sizeof(startupInfo);

		if (!CreateProcessA(
			targetPath.c_str(),
			nullptr,
			nullptr,
			nullptr,
			FALSE,
			CREATE_SUSPENDED,
			nullptr,
			dirPath.string().c_str(),
			&startupInfo,
			&processInfo))
		{
			std::cout << "Failed to launch process.\n";
			return -1;
		}

		SafeHandle<> process(processInfo.hProcess);
		SafeHandle<> thread(processInfo.hThread);

		// Allocate memory on target process.
		SafeProcessMemory targetMem(
			process.get(),
			VirtualAllocEx(process.get(), nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!targetMem)
		{
			std::cout << "Failed to allocate memory on target process.\n";
			return -1;
		}

		// Write DLL path.
		auto injectedDllFullPath = fs::canonical(fs::path(injectedDllPath)).string();
		size_t bytesToWrite = sizeof(char) * (injectedDllFullPath.size() + 1);
		SIZE_T bytesWritten;
		if (!WriteProcessMemory(
			process.get(),
			targetMem.address(),
			injectedDllFullPath.c_str(),
			bytesToWrite,
			&bytesWritten) ||
			bytesWritten != bytesToWrite)
		{
			std::cout << "Failed to write to target process memory.\n";
			return -1;
		}

		// Create injector thread.
		void* funcAddr = &LoadLibraryA;
		DWORD threadId;
		SafeHandle injectorThread(CreateRemoteThread(
			process.get(),
			nullptr,
			0,
			(LPTHREAD_START_ROUTINE)funcAddr,
			targetMem.address(),
			CREATE_SUSPENDED,
			&threadId));
		if (!injectorThread)
		{
			std::cout << "Failed to create remote thread.\n";
			return -1;
		}

		std::cout << "Injector thread ID: " << threadId << "\n";
		ResumeThread(injectorThread.get());

		std::cout << "Waiting for injector thread to finish execution.\n";
		WaitForSingleObject(injectorThread.get(), INFINITE);

		DWORD exitCode;
		if (!GetExitCodeThread(injectorThread.get(), &exitCode))
		{
			std::cout << "Failed to get exit code of injector thread.\n";
			return -1;
		}

		std::cout << "Injector thread exited with code " << std::hex << exitCode << std::dec << "\n";

		std::cout << "Resuming main thread.\n";
		ResumeThread(thread.get());

		return 0;
	}
	catch (std::exception& ex)
	{
		std::cout << "Error: " << ex.what() << "\n";
	}
}
