#include "pch.h"
#include "functionhook.h"
#include "memprotect.h"
#include "log.h"
#include <cstdint>
#include <cstring>
#include <format>
#include <map>
#include <stdexcept>
#include <vector>

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
	void* allocateNearTo(void* address, size_t size, std::ptrdiff_t maxDistance = 0x70000000u);

	static JumpTableManager instance;

private:
	std::map<void*, Region> allocatedRegions_;
};

JumpTableManager JumpTableManager::instance;

void* JumpTableManager::allocateNearTo(void* address, size_t size, std::ptrdiff_t maxDistance)
{
	size += (0 - size) & 7;

	const auto minAddress = (char*)address - maxDistance;

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	if (size > sysInfo.dwPageSize)
		throw std::runtime_error("cannot allocate region larger than page size.");

	auto iter = allocatedRegions_.upper_bound(minAddress);
	while (iter != allocatedRegions_.end())
	{
		if (std::ptrdiff_t(reinterpret_cast<std::uintptr_t>(iter->first) - reinterpret_cast<std::uintptr_t>(address)) > maxDistance)
			break;

		if (iter->second.allocPos + size <= iter->second.size)
		{
			auto result = reinterpret_cast<char*>(iter->first) + iter->second.allocPos;
			iter->second.allocPos += size;
			return result;
		}

		allocatedRegions_.erase(iter);
		iter = allocatedRegions_.upper_bound(minAddress);
	}

	// Search for free region
	Log::write(std::format("Searching free page near {:p}", address));

	auto searchLocation = reinterpret_cast<std::uintptr_t>(minAddress);
	searchLocation &= ~std::uintptr_t(sysInfo.dwPageSize - 1);
	searchLocation += sysInfo.dwPageSize;

	for (;;)
	{
		if (std::ptrdiff_t(searchLocation - reinterpret_cast<std::uintptr_t>(address)) >= maxDistance)
		{
			throw std::runtime_error("failed to find a free page near requested address.");
		}

		MEMORY_BASIC_INFORMATION memInfo;
		std::memset(&memInfo, 0, sizeof(memInfo));
		
		const auto virtualQueryRes = VirtualQuery(
			reinterpret_cast<void*>(searchLocation),
			&memInfo,
			sysInfo.dwPageSize);

		if (virtualQueryRes != sizeof(memInfo) || (memInfo.State & MEM_FREE))
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

const std::vector<std::vector<std::uint8_t>> knownSequentialInstructionsX64
{
	{ 0xff, 0x40, 0xff, 0x53 },
	{ 0xff, 0x41, 0xff, 0x54 },
	{ 0xff, 0x41, 0xff, 0x55 },
	{ 0xff, 0x4c, 0xff, 0x8b, 0xff, 0xdc },
	{ 0xff, 0x48, 0xff, 0x83, 0xff, 0xec, 0x00, 0x00 },
	{ 0xff, 0x55 },
};

inline bool maskedMatch(const std::uint8_t* data, const std::uint8_t* pattern, size_t len)
{
	for (size_t i = 0; i < len; ++i)
	{
		const auto mask  = pattern[i * 2];
		const auto value = pattern[i * 2 + 1];
		if ((data[i] & mask) != value)
			return false;
	}

	return true;
}

size_t tryFindSequantialPortion(
	const std::uint8_t* from, size_t desiredLength,
	const std::vector<std::vector<std::uint8_t>>& knownInstructions)
{
	size_t foundLen = 0;
	while (foundLen < desiredLength)
	{
		bool matched = false;
		for (const auto& inst : knownInstructions)
		{
			const auto instLen = inst.size() / 2;
			if (maskedMatch(from, inst.data(), instLen))
			{
				matched = true;
				foundLen += instLen;
				from += instLen;
				break;
			}
		}

		if (!matched)
			break;
	}

	return foundLen;
}

void setupIndirectJumpX64(void* from, void* to)
{
	auto indirectAddr = reinterpret_cast<std::uint8_t*>(JumpTableManager::instance.allocateNearTo(from, 14));
	indirectAddr[ 0] = 0xFF;
	indirectAddr[ 1] = 0x25;
	indirectAddr[ 2] = 0;
	indirectAddr[ 3] = 0;
	indirectAddr[ 4] = 0;
	indirectAddr[ 5] = 0;
	indirectAddr[ 6] = std::uint8_t((std::uintptr_t)to >>  0);
	indirectAddr[ 7] = std::uint8_t((std::uintptr_t)to >>  8);
	indirectAddr[ 8] = std::uint8_t((std::uintptr_t)to >> 16);
	indirectAddr[ 9] = std::uint8_t((std::uintptr_t)to >> 24);
	indirectAddr[10] = std::uint8_t((std::uintptr_t)to >> 32);
	indirectAddr[11] = std::uint8_t((std::uintptr_t)to >> 40);
	indirectAddr[12] = std::uint8_t((std::uintptr_t)to >> 48);
	indirectAddr[13] = std::uint8_t((std::uintptr_t)to >> 56);

	// Replace the jmp instruction.
	ScopedChangeMemoryProtection rwMem(from, 5, PAGE_READWRITE);
	std::uintptr_t offset = reinterpret_cast<std::uintptr_t>(indirectAddr) - (reinterpret_cast<std::uintptr_t>(from) + 5);

	((std::uint8_t*)from)[0] = 0xE9;
	((std::uint8_t*)from)[1] = std::uint8_t(offset >> 0);
	((std::uint8_t*)from)[2] = std::uint8_t(offset >> 8);
	((std::uint8_t*)from)[3] = std::uint8_t(offset >> 16);
	((std::uint8_t*)from)[4] = std::uint8_t(offset >> 24);
}

inline std::uint32_t readU32(const std::uint8_t* p)
{
	return
		((std::uint32_t)p[0] <<  0) |
		((std::uint32_t)p[1] <<  8) |
		((std::uint32_t)p[2] << 16) |
		((std::uint32_t)p[3] << 24);
}

inline std::uint64_t readU64(const std::uint8_t* p)
{
	return
		((std::uint64_t)p[0] << 0) |
		((std::uint64_t)p[1] << 8) |
		((std::uint64_t)p[2] << 16) |
		((std::uint64_t)p[3] << 24) |
		((std::uint64_t)p[4] << 32) |
		((std::uint64_t)p[5] << 40) |
		((std::uint64_t)p[6] << 48) |
		((std::uint64_t)p[7] << 56);
}

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
		void* originalTarget = (void*)(reinterpret_cast<std::uintptr_t>(target) + 5 + readU32(targetU8 + 1));

		setupIndirectJumpX64(target, hook);
		Log::write(std::format("Successfully hooked function {:p} with {:p}", target, hook));

		return originalTarget;
	}
	else if (targetU8[0] == 0x48 && targetU8[1] == 0xFF && targetU8[2] == 0x25)
	{
		// Target function starts with "JMP cs:[mem]" instruction.
		void* originalTarget = (void*)readU64(targetU8 + 7 + readU32(targetU8 + 3));

		setupIndirectJumpX64(target, hook);
		Log::write(std::format("Successfully hooked function {:p} with {:p}", target, hook));
		
		return originalTarget;
	}
	else
	{
		auto sequentialLen = tryFindSequantialPortion(targetU8, 5, knownSequentialInstructionsX64);
		if (sequentialLen < 5)
			throw std::runtime_error("unrecognizable instruction or not enough sequential instructions.");

		auto resumeTarget = targetU8 + sequentialLen;
		auto resumeStub = reinterpret_cast<std::uint8_t*>(JumpTableManager::instance.allocateNearTo(target, sequentialLen + 14));
		std::memcpy(resumeStub, targetU8, sequentialLen);

		resumeStub[sequentialLen +  0] = 0xFF;
		resumeStub[sequentialLen +  1] = 0x25;
		resumeStub[sequentialLen +  2] = 0;
		resumeStub[sequentialLen +  3] = 0;
		resumeStub[sequentialLen +  4] = 0;
		resumeStub[sequentialLen +  5] = 0;
		resumeStub[sequentialLen +  6] = std::uint8_t((std::uintptr_t)resumeTarget >> 0);
		resumeStub[sequentialLen +  7] = std::uint8_t((std::uintptr_t)resumeTarget >> 8);
		resumeStub[sequentialLen +  8] = std::uint8_t((std::uintptr_t)resumeTarget >> 16);
		resumeStub[sequentialLen +  9] = std::uint8_t((std::uintptr_t)resumeTarget >> 24);
		resumeStub[sequentialLen + 10] = std::uint8_t((std::uintptr_t)resumeTarget >> 32);
		resumeStub[sequentialLen + 11] = std::uint8_t((std::uintptr_t)resumeTarget >> 40);
		resumeStub[sequentialLen + 12] = std::uint8_t((std::uintptr_t)resumeTarget >> 48);
		resumeStub[sequentialLen + 13] = std::uint8_t((std::uintptr_t)resumeTarget >> 56);

		setupIndirectJumpX64(target, hook);
		Log::write(std::format("Successfully hooked function {:p} with {:p}", target, hook));

		return resumeStub;
	}
#else
	throw std::runtime_error("Current architecture is not supported.");
#endif
}
