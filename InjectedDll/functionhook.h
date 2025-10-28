#pragma once

void* setup_function_hook_untyped(void* target, void* hook);

template<typename T> inline T* setupFunctionHook(void* target, T* hook)
{
	return (T*)setup_function_hook_untyped(target, (void*)hook);
}
