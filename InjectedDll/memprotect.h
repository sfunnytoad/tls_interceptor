#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

class ScopedChangeMemoryProtection
{
public:
	ScopedChangeMemoryProtection();
	~ScopedChangeMemoryProtection();
	ScopedChangeMemoryProtection(void* address, size_t len, DWORD protection);

	ScopedChangeMemoryProtection(const ScopedChangeMemoryProtection&) = delete;
	ScopedChangeMemoryProtection(ScopedChangeMemoryProtection&& o) noexcept;
	void swap(ScopedChangeMemoryProtection& o) noexcept;

	ScopedChangeMemoryProtection& operator =(ScopedChangeMemoryProtection o)
	{
		swap(o);
		return *this;
	}

private:
	static size_t getPageSize();

private:
	std::uintptr_t start_, end_;
	std::vector<DWORD> originalProtection_;
};
