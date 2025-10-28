// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "functionhook.h"
#include "log.h"

#include <WinSock2.h>
#include <cstdint>
#include <exception>
#include <format>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>

struct SSL_CTX;
struct SSL;
struct SSL_METHOD;

class SocketHandleRegistry
{
public:
    void add(SOCKET s, const std::string& endpoint)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sockets_.insert(std::make_pair(s, endpoint));
    }

    void remove(SOCKET s)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sockets_.erase(s);
    }

    bool lookup(SOCKET s, std::string& endpoint)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = sockets_.find(s);
        if (iter == sockets_.end())
            return false;

        endpoint = iter->second;
        return true;
    }

private:
    std::mutex mutex_;
    std::unordered_map<SOCKET, std::string> sockets_;
};

SocketHandleRegistry g_socketHandles;

int (WSAAPI *original_connect)(SOCKET s, const struct sockaddr* name, int namelen);
int WSAAPI hooked_connect(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (name->sa_family == AF_INET)
    {
        auto sin = (sockaddr_in*)name;

        std::string endpoint = std::format("{}.{}.{}.{}:{}",
            sin->sin_addr.s_addr & 0xFFu,
            (sin->sin_addr.s_addr >> 8) & 0xFFu,
            (sin->sin_addr.s_addr >> 16) & 0xFFu,
            (sin->sin_addr.s_addr >> 24) & 0xFFu,
            ((sin->sin_port >> 8) & 0xFFu) | ((sin->sin_port & 0xFFu) << 8));

        Log::write(std::format("connect() - {}", endpoint));

        g_socketHandles.add(s, endpoint);
    }
    else
        Log::write("connect() (unrecognized address)");

    return (*original_connect)(s, name, namelen);
}

int (WSAAPI* original_closesocket)(SOCKET s);
int WSAAPI hooked_closesocket(SOCKET s)
{
    Log::write(std::format("closesocket() - {}", s));
    g_socketHandles.remove(s);

    return (*original_closesocket)(s);
}

SSL_CTX* (*original_SSL_CTX_new)(const SSL_METHOD* method);
SSL_CTX* hooked_SSL_CTX_new(const SSL_METHOD* method)
{
    Log::write("SSL_CTX_new()");

    return (*original_SSL_CTX_new)(method);
}

int (*original_SSL_set_fd)(SSL* ssl, int fd);
int hooked_SSL_set_fd(SSL* ssl, int fd)
{
    Log::write(std::format("SSL_set_fd(): {:p}, {}", (void*)ssl, fd));
    std::string endpoint;
    if (g_socketHandles.lookup(fd, endpoint))
        Log::write(std::format("  endpoint address: {}", endpoint));
    else
        Log::write("  socket not found in registry");

    return (*original_SSL_set_fd)(ssl, fd);
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

        original_SSL_CTX_new = setupFunctionHook((void*)GetProcAddress(sslModule, "SSL_CTX_new"), hooked_SSL_CTX_new);
        original_SSL_set_fd = setupFunctionHook((void*)GetProcAddress(sslModule, "SSL_set_fd"), hooked_SSL_set_fd);
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

