#pragma once

#include "Helper.h"
#include <inaddr.h>
#include <vector>

// Link with Ws2_32.lib and Iphlpapi.lib (for GetAdaptersInfo)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace Sender
{
    bool GetLocalIpAddress(const char* interfaceName, PIP_ADDR_STRING localIP) noexcept;
    mac SendARPRequest(const in_addr target) noexcept;
    bool SendPing(const in_addr target) noexcept;
    std::vector<in_addr> mapLocalNetwork(const IP_ADDR_STRING& localIpData);
};
