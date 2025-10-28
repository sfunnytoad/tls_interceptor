#include "pch.h"
#include "functionhook.h"
#include "memprotect.h"
#include "log.h"
#include <cstdint>
#include <cstring>
#include <format>
#include <stdexcept>
#include <map>

#if defined (_M_X64)
class JumpTableManager
{
private:
	struct Region
	{
		size_t size;
		size_t allocPos;
	};

public:
	void* allocateNearTo(void* address, size_t size, size_t maxDistance = 0x10000000u);

	static JumpTableManager instance;

private:
	std::map<void*, Region> allocatedRegions_;
};

JumpTableManager JumpTableManager::instance;

void* JumpTableManager::allocateNearTo(void* address, size_t size, size_t maxDistance)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	if (size > sysInfo.dwPageSize)
		throw std::runtime_error("cannot allocate region larger than page size.");

	auto iter = allocatedRegions_.upper_bound(address);
	while (iter != allocatedRegions_.end())
	{
		if (reinterpret_cast<std::uintptr_t>(iter->first) - reinterpret_cast<std::uintptr_t>(address) > maxDistance)
			break;

		if (iter->second.allocPos + size <= iter->second.size)
		{
			auto result = reinterpret_cast<char*>(iter->first) + iter->second.allocPos;
			iter->second.allocPos += size;
			return result;
		}

		allocatedRegions_.erase(iter);
		iter = allocatedRegions_.upper_bound(address);
	}

	// Search for free region
	Log::write(std::format("Searching free page near {:p}", address));

	auto searchLocation = reinterpret_cast<std::uintptr_t>(address);
	searchLocation &= ~std::uintptr_t(sysInfo.dwPageSize - 1);
	searchLocation += sysInfo.dwPageSize;

	for (;;)
	{
		if (searchLocation - reinterpret_cast<std::uintptr_t>(address) >= maxDistance)
		{
			Log::write("Failed to find a free page");
			throw std::runtime_error("failed to find a free page near requested address.");
		}

		MEMORY_BASIC_INFORMATION memInfo;
		std::memset(&memInfo, 0, sizeof(memInfo));
		
		if (VirtualQuery(
			reinterpret_cast<void*>(searchLocation),
			&memInfo,
			sysInfo.dwPageSize) != sizeof(memInfo))
		{
			searchLocation += sysInfo.dwPageSize;
			continue;
		}

		if (memInfo.State & MEM_FREE)
		{
			if (VirtualAlloc(reinterpret_cast<void*>(searchLocation), sysInfo.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
				break;

			Log::write(std::format("Failed to allocate page at {:p}, error {}", (void*)searchLocation, GetLastError()));
			searchLocation += sysInfo.dwPageSize;
		}

		if (memInfo.State & MEM_RESERVE)
			searchLocation = reinterpret_cast<std::uintptr_t>(memInfo.BaseAddress) + memInfo.RegionSize;
		else
			searchLocation += sysInfo.dwPageSize;
	}

	Log::write(std::format("Found free page at {:p}", (void*)searchLocation));

	Region newRegion;
	newRegion.size = sysInfo.dwPageSize;
	newRegion.allocPos = 0;
	iter = allocatedRegions_.insert(std::make_pair(
		reinterpret_cast<void*>(searchLocation),
		newRegion)).first;

	auto result = reinterpret_cast<char*>(iter->first) + iter->second.allocPos;
	iter->second.allocPos += size;
	return result;
}
#endif

void* setup_function_hook_untyped(void* target, void* hook)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

#if defined (_M_IX86)
	auto targetU8 = reinterpret_cast<std::uint8_t*>(target);
	if (targetU8[0] == 0xE9)
	{
		// Target function starts with jmp instruction.
		void* originalTarget = reinterpret_cast<void*>((
			((std::uint32_t)targetU8[1] << 0) |
			((std::uint32_t)targetU8[2] << 8) |
			((std::uint32_t)targetU8[3] << 16) |
			((std::uint32_t)targetU8[4] << 24)
			) + (reinterpret_cast<std::uintptr_t>(target) + 5));

		// Replace the jmp instruction.
		ScopedChangeMemoryProtection rwMem(target, 5, PAGE_READWRITE);
		std::uintptr_t offset = reinterpret_cast<std::uintptr_t>(hook) - (reinterpret_cast<std::uintptr_t>(target) + 5);

		targetU8[1] = std::uint8_t(offset >> 0);
		targetU8[2] = std::uint8_t(offset >> 8);
		targetU8[3] = std::uint8_t(offset >> 16);
		targetU8[4] = std::uint8_t(offset >> 24);

		Log::write(std::format("Successfully hooked function {:p} with {:p}", target, hook));

		return originalTarget;
	}
	else
		throw std::runtime_error("Unrecognizable instruction.");
#elif defined (_M_X64)
	auto targetU8 = reinterpret_cast<std::uint8_t*>(target);
	if (targetU8[0] == 0xE9)
	{
		// Target function starts with a 32-bit relative jump instruction.
		void* originalTarget = reinterpret_cast<void*>((
			((std::uint32_t)targetU8[1] << 0) |
			((std::uint32_t)targetU8[2] << 8) |
			((std::uint32_t)targetU8[3] << 16) |
			((std::uint32_t)targetU8[4] << 24)
			) + (reinterpret_cast<std::uintptr_t>(target) + 5));

		auto indirectAddr = reinterpret_cast<std::uint8_t*>(JumpTableManager::instance.allocateNearTo(target, 16));
		indirectAddr[ 0] = 0xFF;
		indirectAddr[ 1] = 0x25;
		indirectAddr[ 2] = 0;
		indirectAddr[ 3] = 0;
		indirectAddr[ 4] = 0;
		indirectAddr[ 5] = 0;
		indirectAddr[ 6] = std::uint8_t((std::uintptr_t)hook >> 0);
		indirectAddr[ 7] = std::uint8_t((std::uintptr_t)hook >> 8);
		indirectAddr[ 8] = std::uint8_t((std::uintptr_t)hook >> 16);
		indirectAddr[ 9] = std::uint8_t((std::uintptr_t)hook >> 24);
		indirectAddr[10] = std::uint8_t((std::uintptr_t)hook >> 32);
		indirectAddr[11] = std::uint8_t((std::uintptr_t)hook >> 40);
		indirectAddr[12] = std::uint8_t((std::uintptr_t)hook >> 48);
		indirectAddr[13] = std::uint8_t((std::uintptr_t)hook >> 56);

		// Replace the jmp instruction.
		ScopedChangeMemoryProtection rwMem(target, 5, PAGE_READWRITE);
		std::uintptr_t offset = reinterpret_cast<std::uintptr_t>(indirectAddr) - (reinterpret_cast<std::uintptr_t>(target) + 5);

		targetU8[1] = std::uint8_t(offset >> 0);
		targetU8[2] = std::uint8_t(offset >> 8);
		targetU8[3] = std::uint8_t(offset >> 16);
		targetU8[4] = std::uint8_t(offset >> 24);

		Log::write(std::format("Successfully hooked function {:p} with {:p}", target, hook));

		return originalTarget;
	}
	else
		throw std::runtime_error("Unrecognizable instruction.");
#else
	throw std::runtime_error("Current architecture is not supported.");
#endif
}
