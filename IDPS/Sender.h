#pragma once

#include "Helper.h"
#include <inaddr.h>
#include <vector>

// Link with Ws2_32.lib, winhttp.lib and Iphlpapi.lib (for GetAdaptersInfo)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")

class Sender final
{
public:
    static bool GetLocalIpAddress(const char* interfaceName, PIP_ADDR_STRING localIP);
    static mac SendARPRequest(const in_addr target);
    static bool SendPing(const in_addr target);
    static std::vector<in_addr> mapLocalNetwork(const IP_ADDR_STRING& localIpData);
    static std::string SendHTTP(const std::string_view& url);
};
