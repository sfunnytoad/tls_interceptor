#pragma once

#include <utility>

class SafeProcessMemory
{
public:
	SafeProcessMemory()
	{
		process_ = nullptr;
		ptr_ = nullptr;
	}

	~SafeProcessMemory()
	{
		if (ptr_)
			VirtualFreeEx(process_, ptr_, 0, MEM_FREE);
	}

	SafeProcessMemory(HANDLE process, void* ptr)
	{
		process_ = process;
		ptr_ = ptr;
	}

	SafeProcessMemory(const SafeProcessMemory&) = delete;

	SafeProcessMemory(SafeProcessMemory&& o) noexcept
	{
		process_ = o.process_;
		ptr_ = o.ptr_;

		o.process_ = nullptr;
		o.ptr_ = nullptr;
	}

	void swap(SafeProcessMemory& o) noexcept
	{
		std::swap(process_, o.process_);
		std::swap(ptr_, o.ptr_);
	}

	SafeProcessMemory& operator =(SafeProcessMemory o)
	{
		swap(o);
		return *this;
	}

	HANDLE process() const { return process_; }
	void* address() const { return ptr_; }
	explicit operator bool() const { return ptr_ != nullptr; }

private:
	HANDLE process_;
	void* ptr_;
};
