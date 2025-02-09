#pragma once

#include "Helper.h"
#include <inaddr.h>
#include <vector>
#include <winhttp.h> // HINTERNET

// Link with Ws2_32.lib, winhttp.lib and Iphlpapi.lib (for GetAdaptersInfo)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")

class Sender final
{
public:
    static bool GetLocalIpAddress(const char* interfaceName, PIP_ADDR_STRING localIP) noexcept;
    static mac SendARPRequest(const in_addr target) noexcept;
    static bool SendPing(const in_addr target) noexcept;
    static std::vector<in_addr> mapLocalNetwork(const IP_ADDR_STRING& localIpData);
    static in_addr DoHQuery(const std::wstring& domain);

private:
    static in_addr extractIpFromDoHResponse(const std::string& response);
};


// Simple RAII wrapper for WinHTTP handles
class WinHttpHandle
{
public:
    explicit WinHttpHandle(HINTERNET handle);
    ~WinHttpHandle() noexcept;

    // Allow the wrapper to be used where HINTERNET is expected
    constexpr operator HINTERNET() const noexcept;
private:
    HINTERNET m_handle;
};
