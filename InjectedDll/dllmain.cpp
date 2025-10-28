// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "functionhook.h"
#include "log.h"
#include <cstdint>
#include <exception>
#include <format>
#include <stdexcept>

struct SSL_CTX;
struct SSL_METHOD;

SSL_CTX* (*original_SSL_CTX_new)(const SSL_METHOD* method);
SSL_CTX* hooked_SSL_CTX_new(const SSL_METHOD* method)
{
    Log::write("SSL_CTX_new()");

    return (*original_SSL_CTX_new)(method);
}

void initializeDll()
{
    try
    {
        // Get handle to libssl
        auto sslModule = LoadLibraryA("libssl-1_1-x64.dll");
        if (!sslModule)
            throw std::runtime_error("failed to get handle to libssl module.");

        original_SSL_CTX_new = setup_function_hook((void*)((std::uintptr_t)sslModule + 0x1BF9), hooked_SSL_CTX_new);
    }
    catch (std::exception& ex)
    {
        Log::write(std::format("Error: {}", ex.what()));
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        initializeDll();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

