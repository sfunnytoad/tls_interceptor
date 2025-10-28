#include "pch.h"
#include "memprotect.h"
#include <stdexcept>
#include <utility>

ScopedChangeMemoryProtection::ScopedChangeMemoryProtection()
{
	start_ = 0;
	end_ = 0;
}

ScopedChangeMemoryProtection::~ScopedChangeMemoryProtection()
{
	if (start_ != end_)
	{
		const auto pageSize = getPageSize();

		for (size_t i = 0; i < originalProtection_.size(); ++i)
		{
			DWORD oldProtect;
			VirtualProtect(
				reinterpret_cast<void*>(start_ + pageSize * i),
				pageSize,
				originalProtection_[i],
				&oldProtect);
		}
	}
}

ScopedChangeMemoryProtection::ScopedChangeMemoryProtection(void* address, size_t len, DWORD protection)
{
	const auto pageSize = getPageSize();
	start_ = reinterpret_cast<std::uintptr_t>(address) & ~std::uintptr_t(pageSize - 1);
	end_ = ((reinterpret_cast<std::uintptr_t>(address) + len - 1) & ~std::uintptr_t(pageSize - 1)) + pageSize;

	originalProtection_ = std::vector<DWORD>((end_ - start_) / pageSize);

	size_t appliedPos = 0;
	try
	{
		while (appliedPos < originalProtection_.size())
		{
			if (!VirtualProtect(
				reinterpret_cast<void*>(start_ + pageSize * appliedPos),
				pageSize,
				protection,
				&originalProtection_[appliedPos]))
				throw std::runtime_error("Failed to change page protection flags.");

			++appliedPos;
		}
	}
	catch(...)
	{
		// Undo changes
		while (appliedPos)
		{
			--appliedPos;

			DWORD temp;
			VirtualProtect(
				reinterpret_cast<void*>(start_ + pageSize * appliedPos),
				pageSize,
				originalProtection_[appliedPos],
				&temp);
		}

		throw;
	}
}

ScopedChangeMemoryProtection::ScopedChangeMemoryProtection(ScopedChangeMemoryProtection&& o) noexcept
{
	start_ = o.start_;
	end_ = o.end_;
	originalProtection_ = std::move(o.originalProtection_);

	o.start_ = 0;
	o.end_ = 0;
	o.originalProtection_ = {};
}

void ScopedChangeMemoryProtection::swap(ScopedChangeMemoryProtection& o) noexcept
{
	std::swap(start_, o.start_);
	std::swap(end_, o.end_);
	std::swap(originalProtection_, o.originalProtection_);
}

size_t ScopedChangeMemoryProtection::getPageSize()
{
	struct SystemInfo
	{
		SYSTEM_INFO value;
		SystemInfo() { GetSystemInfo(&value); }
	};

	static SystemInfo sysInfo;

	return sysInfo.value.dwPageSize;
}
