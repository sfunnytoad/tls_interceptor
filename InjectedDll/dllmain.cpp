// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "concurrent_map.h"
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
struct BIO;

ConcurrentMap<SOCKET, std::string> g_socketEndpoints;
ConcurrentMap<BIO*, std::string> g_bioEndpoints;

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

        g_socketEndpoints.add(s, endpoint);
    }
    else
        Log::write("connect() (unrecognized address)");

    return (*original_connect)(s, name, namelen);
}

int (WSAAPI* original_closesocket)(SOCKET s);
int WSAAPI hooked_closesocket(SOCKET s)
{
    Log::write(std::format("closesocket() - {}", s));
    g_socketEndpoints.remove(s);

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
    if (g_socketEndpoints.lookup(fd, endpoint))
        Log::write(std::format("  endpoint address: {}", endpoint));
    else
        Log::write("  socket not found in registry");

    return (*original_SSL_set_fd)(ssl, fd);
}

void (*original_SSL_set_bio)(SSL* ssl, BIO* rbio, BIO* wbio);
void hooked_SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio)
{
    Log::write("SSL_set_bio()");

    return (*original_SSL_set_bio)(ssl, rbio, wbio);
}

int (*original_SSL_write_ex)(SSL* s, const void* buf, size_t num, size_t* written);
int hooked_SSL_write_ex(SSL* s, const void* buf, size_t num, size_t* written)
{
    return (*original_SSL_write_ex)(s, buf, num, written);
}

int (*original_SSL_write)(SSL* ssl, const void* buf, int num);
int hooked_SSL_write(SSL* ssl, const void* buf, int num)
{
    return (*original_SSL_write)(ssl, buf, num);
}

BIO* (*original_BIO_new_connect)(const char* name);
BIO* hooked_BIO_new_connect(const char* name)
{
    Log::write(std::format("BIO_new_connect() : {}", name));

    return (*original_BIO_new_connect)(name);
}

BIO* (*original_BIO_new_socket)(int sock, int close_flag);
BIO* hooked_BIO_new_socket(int sock, int close_flag)
{
    Log::write(std::format("BIO_new_socket(): {}", sock));
    std::string endpoint;
    if (g_socketEndpoints.lookup(sock, endpoint))
        Log::write(std::format("  endpoint address: {}", endpoint));
    else
        Log::write("  socket not found in registry");

    BIO* res = (*original_BIO_new_socket)(sock, close_flag);
    if (res)
        g_bioEndpoints.add(res, endpoint);

    return res;
}

int (*original_BIO_free)(BIO* bio);
int hooked_BIO_free(BIO* bio)
{
    g_bioEndpoints.remove(bio);
    return (*original_BIO_free)(bio);
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

        // Hook into libcrypto
        auto cryptoModule = LoadLibraryA("libcrypto-1_1-x64.dll");
        if (!cryptoModule)
            throw std::runtime_error("failed to get handle to libcrypto module.");

        original_BIO_new_connect    = setupFunctionHook((void*)GetProcAddress(cryptoModule, "BIO_new_connect"), hooked_BIO_new_connect);
        original_BIO_new_socket     = setupFunctionHook((void*)GetProcAddress(cryptoModule, "BIO_new_socket"), hooked_BIO_new_socket);
        original_BIO_free           = setupFunctionHook((void*)GetProcAddress(cryptoModule, "BIO_free"), hooked_BIO_free);

        // Hook into libssl
        auto sslModule = LoadLibraryA("libssl-1_1-x64.dll");
        if (!sslModule)
            throw std::runtime_error("failed to get handle to libssl module.");

        original_SSL_CTX_new    = setupFunctionHook((void*)GetProcAddress(sslModule, "SSL_CTX_new"), hooked_SSL_CTX_new);
        original_SSL_set_fd     = setupFunctionHook((void*)GetProcAddress(sslModule, "SSL_set_fd"), hooked_SSL_set_fd);
        original_SSL_set_bio    = setupFunctionHook((void*)GetProcAddress(sslModule, "SSL_set_bio"), hooked_SSL_set_bio);
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

