// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "functionhook.h"
#include "log.h"

#include <WinSock2.h>
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

int (WSAAPI *original_connect)(SOCKET s, const struct sockaddr* name, int namelen);
int WSAAPI hooked_connect(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (name->sa_family == AF_INET)
    {
        auto sin = (sockaddr_in*)name;
        Log::write(std::format("connect() - {}.{}.{}.{}:{}",
             sin->sin_addr.s_addr        & 0xFFu,
            (sin->sin_addr.s_addr >>  8) & 0xFFu,
            (sin->sin_addr.s_addr >> 16) & 0xFFu,
            (sin->sin_addr.s_addr >> 24) & 0xFFu,
            ((sin->sin_port >> 8) & 0xFFu) | ((sin->sin_port & 0xFFu) << 8)
        ));
    }
    else
        Log::write("connect() (unrecognized address)");

    return (*original_connect)(s, name, namelen);
}

BOOL WINAPI hooked_IsDebuggerPresent()
{
    return FALSE;
}

void initializeDll()
{
    try
    {
        // Hook into kernel32
        setupFunctionHook(&IsDebuggerPresent, hooked_IsDebuggerPresent);

        // Hook into ws2_32
        auto ws2Module = LoadLibraryA("ws2_32.dll");
        if (!ws2Module)
            throw std::runtime_error("failed to get handle to ws2_32 module.");

        original_connect = setupFunctionHook((void*)GetProcAddress(ws2Module, "connect"), hooked_connect);

        // Hook into libssl
        auto sslModule = LoadLibraryA("libssl-1_1-x64.dll");
        if (!sslModule)
            throw std::runtime_error("failed to get handle to libssl module.");

        original_SSL_CTX_new = setupFunctionHook((void*)((std::uintptr_t)sslModule + 0x1BF9), hooked_SSL_CTX_new);
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

