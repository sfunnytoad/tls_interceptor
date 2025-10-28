#pragma once

#include <utility>

struct NullAsInvalidHandle
{
	static HANDLE value() { return nullptr; }
};

struct MinusOneAsInvalidHandle
{
	static HANDLE value() { return INVALID_HANDLE_VALUE; }
};

template<typename InvalidHandleValue = NullAsInvalidHandle>
class SafeHandle
{
public:
	SafeHandle()
	{
		value_ = InvalidHandleValue::value();
	}

	~SafeHandle()
	{
		if (value_ != InvalidHandleValue::value())
			CloseHandle(value_);
	}

	explicit SafeHandle(HANDLE h)
	{
		value_ = h;
	}

	SafeHandle(const SafeHandle&) = delete;

	SafeHandle(SafeHandle&& o) noexcept
	{
		value_ = o.value_;
		o.value_ = InvalidHandleValue::value();
	}

	void swap(SafeHandle& o) noexcept
	{
		std::swap(value_, o.value_);
	}

	SafeHandle& operator =(SafeHandle o)
	{
		swap(o);
		return *this;
	}

	HANDLE get() const { return value_; }

	HANDLE detach()
	{
		HANDLE res = value_;
		value_ = InvalidHandleValue::value();
		return res;
	}

	explicit operator bool() const
	{
		return value_ != InvalidHandleValue::value();
	}

private:
	HANDLE value_;
};
